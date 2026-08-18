package main

// bencpass-server — the sync endpoint.
//
// Deliberately small and deliberately stupid. It stores ciphertext, orders it
// with a sequence number, and refuses a write from a client that has not seen
// the latest one. It holds no key, so it cannot merge, cannot search, and cannot
// tell a good record from a damaged one — which is why snapshots exist.

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

const maxBody = 32 << 20 // 32 MiB; a vault of any sane size is far below this

type server struct {
	store *Store
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8788", "listen address")
	dir := flag.String("dir", "./data", "data directory")
	cert := flag.String("cert", "", "TLS certificate (see `tailscale cert`)")
	key := flag.String("key", "", "TLS private key")
	keep := flag.Int("snapshots", 50, "snapshots to retain")
	flag.Parse()

	store, err := OpenStore(*dir, *keep)
	if err != nil {
		log.Fatalf("cannot open store: %v", err)
	}

	// A server with no devices cannot be enrolled against, and there is nobody
	// to authorise the first enrolment. So the first one is bootstrapped from
	// the console — which requires access to the machine, and is therefore the
	// authorisation.
	if store.DeviceCount() == 0 {
		code, err := store.NewCode(30 * time.Minute)
		if err != nil {
			log.Fatalf("cannot mint bootstrap code: %v", err)
		}
		log.Printf("no devices enrolled yet")
		log.Printf("bootstrap enrolment code (valid 30 minutes): %s", code)
	}

	s := &server{store: store}
	srv := &http.Server{
		Addr:    *addr,
		Handler: s.routes(),

		// Headers arrive promptly or not at all. The rest is deliberately
		// generous: a body is capped at 32 MiB and the client's last attempt is
		// not time-boxed on purpose, because a large vault over a slow link is a
		// slow sync rather than a failure. Two minutes is far more than a real
		// vault needs — they run to kilobytes — while still putting a bound on
		// how long a connection that has gone quiet can hold anything open.
		// Without these, a body sent one byte at a time holds a connection for
		// as long as it likes once the headers are through.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	// Bind first and report the address the listener actually got, not the one
	// that was asked for. With `-addr 127.0.0.1:0` the kernel picks the port,
	// and logging the request would print ":0" — useless to anyone trying to
	// connect, and to the test harness that reads this line.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v", *addr, err)
	}

	if *cert != "" && *key != "" {
		log.Printf("listening on https://%s", ln.Addr())
		log.Fatal(srv.ServeTLS(ln, *cert, *key))
	}
	// Plain HTTP is a supported configuration, not an oversight — the payload is
	// already end-to-end encrypted and every request is signed. Say so at
	// startup anyway, so nobody concludes it by accident.
	log.Printf("listening on http://%s (no TLS; payload is E2E encrypted and requests are signed)", ln.Addr())
	log.Fatal(srv.Serve(ln))
}

// routes is separate from main so the tests drive the same table the binary
// does. A test that wires up its own routing proves nothing about the routing.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.status)
	mux.HandleFunc("GET /favicon.svg", s.favicon)
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/enrol", s.enrol)
	mux.HandleFunc("POST /v1/codes", s.auth(s.mintCode))
	mux.HandleFunc("GET /v1/meta", s.auth(s.getMeta))
	mux.HandleFunc("PUT /v1/meta", s.auth(s.putMeta))
	mux.HandleFunc("GET /v1/records", s.auth(s.getRecords))
	mux.HandleFunc("PUT /v1/records", s.auth(s.putRecords))
	return mux
}

// ---- plumbing --------------------------------------------------------------

func (s *server) auth(next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		// The body must be read before the signature can be checked, since the
		// signature covers its hash.
		if _, err := s.store.authenticate(r, body); err != nil {
			fail(w, http.StatusUnauthorized, "unauthorised")
			return
		}
		next(w, r, body)
	}
}

func send(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	send(w, code, map[string]string{"error": msg})
}

// ---- handlers --------------------------------------------------------------

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	send(w, http.StatusOK, map[string]any{"ok": true, "seq": s.store.Seq()})
}

func (s *server) enrol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	dev, err := s.store.Redeem(req.Code, req.Name)
	if err != nil {
		fail(w, http.StatusForbidden, "unknown or expired code")
		return
	}
	log.Printf("enrolled device %q (%s)", dev.Name, dev.ID)
	send(w, http.StatusOK, map[string]string{"deviceId": dev.ID, "key": dev.Key})
}

func (s *server) mintCode(w http.ResponseWriter, r *http.Request, _ []byte) {
	// Keyed on the request that asked, so a replay of that request returns the
	// same code rather than another one. See NewCodeFor.
	code, err := s.store.NewCodeFor(r.Header.Get(hdrDevice), r.Header.Get(hdrNonce), 30*time.Minute)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot mint code")
		return
	}
	send(w, http.StatusOK, map[string]any{"code": code, "ttlSeconds": 1800})
}

func (s *server) getMeta(w http.ResponseWriter, r *http.Request, _ []byte) {
	meta, seq := s.store.Meta()
	if meta == nil {
		send(w, http.StatusOK, map[string]any{"meta": nil, "seq": seq})
		return
	}
	send(w, http.StatusOK, map[string]any{"meta": meta, "seq": seq})
}

func (s *server) putMeta(w http.ResponseWriter, r *http.Request, body []byte) {
	var req struct {
		Meta json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Meta) == 0 {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	// The same If-Match as records, for the same reason and then some: this is
	// the wrapped vault key, and a write that lands out of order puts an old
	// wrapping back.
	ifMatch := int64(-1)
	if v := r.Header.Get("If-Match"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		// Negative is refused rather than passed on. Below, a negative ifMatch
		// means "not checking", which is only ever legitimate for the first
		// write to an empty store — reached by the absent-header path just
		// below, never by anything a client sends. Forwarded, it would let any
		// caller turn compare-and-swap off by asking.
		if err != nil || n < 0 {
			fail(w, http.StatusBadRequest, "bad If-Match")
			return
		}
		ifMatch = n
	} else if s.store.Seq() != 0 {
		fail(w, http.StatusPreconditionRequired, "If-Match required")
		return
	}

	seq, err := s.store.PutMeta(req.Meta, ifMatch)
	if errors.Is(err, ErrConflict) {
		fail(w, http.StatusConflict, "sequence moved on")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot write")
		return
	}
	send(w, http.StatusOK, map[string]any{"seq": seq})
}

func (s *server) getRecords(w http.ResponseWriter, r *http.Request, _ []byte) {
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil {
		since = 0
	}
	seq, records := s.store.Since(since)
	send(w, http.StatusOK, map[string]any{"seq": seq, "records": records})
}

func (s *server) putRecords(w http.ResponseWriter, r *http.Request, body []byte) {
	var req struct {
		Records []Envelope `json:"records"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}

	// If-Match carries the sequence the client last saw. Its absence is only
	// legitimate for the first write to an empty store; anything else is a
	// client that has skipped the compare-and-swap.
	ifMatch := int64(-1)
	if v := r.Header.Get("If-Match"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		// Negative is refused rather than passed on. Below, a negative ifMatch
		// means "not checking", which is only ever legitimate for the first
		// write to an empty store — reached by the absent-header path just
		// below, never by anything a client sends. Forwarded, it would let any
		// caller turn compare-and-swap off by asking.
		if err != nil || n < 0 {
			fail(w, http.StatusBadRequest, "bad If-Match")
			return
		}
		ifMatch = n
	} else if s.store.Seq() != 0 {
		fail(w, http.StatusPreconditionRequired, "If-Match required")
		return
	}

	seq, err := s.store.Put(req.Records, ifMatch)
	switch {
	case errors.Is(err, ErrConflict):
		// The client re-pulls from `seq`, merges, and retries. The server never
		// resolves this itself, because it cannot read either side.
		send(w, http.StatusConflict, map[string]any{"seq": seq, "error": "conflict"})
	case errors.Is(err, ErrBackward):
		fail(w, http.StatusUnprocessableEntity, err.Error())
	case err != nil:
		fail(w, http.StatusInternalServerError, "cannot write")
	default:
		send(w, http.StatusOK, map[string]any{"seq": seq})
	}
}
