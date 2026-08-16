package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	id   string
	key  []byte
	skew time.Duration // deliberately wrong clock, for the replay-window test
}

func newServer(t *testing.T) (*httptest.Server, *Store, string) {
	t.Helper()
	store, err := OpenStore(t.TempDir(), 5)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.NewCode(30 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{store: store}
	srv := httptest.NewServer(s.routes())
	t.Cleanup(srv.Close)
	return srv, store, code
}

// enrol runs the real bootstrap path rather than reaching into the store.
func enrol(t *testing.T, srv *httptest.Server, code, name string) *client {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"code": code, "name": name})
	resp, err := http.Post(srv.URL+"/v1/enrol", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrol: %d", resp.StatusCode)
	}
	var out struct{ DeviceId, Key string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(out.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("device key is %d bytes, want 32", len(key))
	}
	return &client{t: t, srv: srv, id: out.DeviceId, key: key}
}

func (c *client) do(method, path string, body any, headers map[string]string) (int, map[string]any) {
	c.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, c.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		c.t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Add(c.skew).UnixMilli(), 10)
	req.Header.Set(hdrDevice, c.id)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrSig, sign(c.key, method, path, ts, raw))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func env(id string, rev int) Envelope {
	return Envelope{ID: id, Rev: rev, N: "bm9uY2U=", Ct: fmt.Sprintf("Y3Q%d", rev)}
}

// ---- enrolment -------------------------------------------------------------

func TestEnrolmentCodeIsSingleUse(t *testing.T) {
	srv, _, code := newServer(t)
	enrol(t, srv, code, "laptop")

	// A code that survived its first use would let anyone who saw it over a
	// shoulder enrol a device of their own later.
	body, _ := json.Marshal(map[string]string{"code": code, "name": "attacker"})
	resp, err := http.Post(srv.URL+"/v1/enrol", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reused code accepted: %d", resp.StatusCode)
	}
}

func TestUnknownCodeIsRefused(t *testing.T) {
	srv, _, _ := newServer(t)
	body, _ := json.Marshal(map[string]string{"code": "not-a-code", "name": "x"})
	resp, err := http.Post(srv.URL+"/v1/enrol", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestExpiredCodeIsRefused(t *testing.T) {
	srv, store, _ := newServer(t)
	code, err := store.NewCode(-time.Second) // already expired
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"code": code, "name": "x"})
	resp, err := http.Post(srv.URL+"/v1/enrol", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired code accepted: %d", resp.StatusCode)
	}
}

func TestEnrolledDeviceCanMintCodeForTheNextMachine(t *testing.T) {
	srv, _, code := newServer(t)
	a := enrol(t, srv, code, "laptop")

	status, out := a.do("POST", "/v1/codes", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("mint: %d", status)
	}
	b := enrol(t, srv, out["code"].(string), "desktop")
	if b.id == a.id {
		t.Fatal("second device reused the first device's identity")
	}
}

// ---- authentication --------------------------------------------------------

func TestUnsignedRequestIsRefused(t *testing.T) {
	srv, _, _ := newServer(t)
	resp, err := http.Get(srv.URL + "/v1/records?since=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestTamperedBodyIsRefused(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// Sign one body, send another — what a LAN attacker rewriting a request in
	// flight would do. The signature covers the body's hash, so it fails.
	raw, _ := json.Marshal(map[string]any{"records": []Envelope{env("a", 1)}})
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	good := sign(c.key, "PUT", "/v1/records", ts, raw)

	evil, _ := json.Marshal(map[string]any{"records": []Envelope{env("a", 99)}})
	req, _ := http.NewRequest("PUT", srv.URL+"/v1/records", bytes.NewReader(evil))
	req.Header.Set(hdrDevice, c.id)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrSig, good)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body accepted: %d", resp.StatusCode)
	}
}

func TestStaleClockIsRefused(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")
	// Outside the replay window: a captured request should not stay usable.
	c.skew = -2 * maxSkew

	if status, _ := c.do("GET", "/v1/records?since=0", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("stale request accepted: %d", status)
	}
}

func TestOneDeviceKeyDoesNotWorkForAnother(t *testing.T) {
	srv, _, code := newServer(t)
	a := enrol(t, srv, code, "laptop")
	_, out := a.do("POST", "/v1/codes", nil, nil)
	b := enrol(t, srv, out["code"].(string), "desktop")

	// Revoking a lost machine has to mean something, so a key must be bound to
	// the device id it was issued with.
	forged := &client{t: t, srv: srv, id: b.id, key: a.key}
	if status, _ := forged.do("GET", "/v1/records?since=0", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("mismatched key accepted: %d", status)
	}
}

// ---- records ---------------------------------------------------------------

func TestPutThenGetSince(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	status, out := c.do("PUT", "/v1/records", map[string]any{
		"records": []Envelope{env("a", 1), env("b", 1)},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("first put: %d %v", status, out)
	}
	seq := int64(out["seq"].(float64))
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}

	// Everything, from the beginning.
	_, out = c.do("GET", "/v1/records?since=0", nil, nil)
	if n := len(out["records"].([]any)); n != 2 {
		t.Fatalf("since=0 returned %d records, want 2", n)
	}

	// Nothing new since that write — the incremental case the client relies on.
	_, out = c.do("GET", "/v1/records?since="+strconv.FormatInt(seq, 10), nil, nil)
	if n := len(out["records"].([]any)); n != 0 {
		t.Fatalf("since=%d returned %d records, want 0", seq, n)
	}
}

func TestSecondWriterGetsAConflict(t *testing.T) {
	srv, _, code := newServer(t)
	a := enrol(t, srv, code, "laptop")
	_, out := a.do("POST", "/v1/codes", nil, nil)
	b := enrol(t, srv, out["code"].(string), "desktop")

	a.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 1)}},
		map[string]string{"If-Match": "0"})

	// b still believes the store is at 0, which is exactly the offline-edit case.
	status, out := b.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 2)}},
		map[string]string{"If-Match": "0"})
	if status != http.StatusConflict {
		t.Fatalf("stale write accepted: %d", status)
	}
	if seq := int64(out["seq"].(float64)); seq != 1 {
		t.Fatalf("conflict reported seq %d, want 1 so the client knows where to resume", seq)
	}

	// Re-pull, then retry against the sequence it now knows.
	status, _ = b.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 2)}},
		map[string]string{"If-Match": "1"})
	if status != http.StatusOK {
		t.Fatalf("retry after conflict: %d", status)
	}
}

func TestIfMatchRequiredOnceTheStoreIsNotEmpty(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// The first write to an empty store may omit it; nothing after that may.
	if status, _ := c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 1)}}, nil); status != http.StatusOK {
		t.Fatalf("first write: %d", status)
	}
	status, _ := c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("b", 1)}}, nil)
	if status != http.StatusPreconditionRequired {
		t.Fatalf("write without If-Match accepted: %d", status)
	}
}

func TestRevisionsCannotGoBackwards(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 5)}},
		map[string]string{"If-Match": "0"})

	// A rollback: replaying an old revision would resurrect a password already
	// rotated away from. The client's AAD binding catches this too; the server
	// refusing it as well means a buggy client cannot damage the shared store.
	status, _ := c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 4)}},
		map[string]string{"If-Match": "1"})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("backward revision accepted: %d", status)
	}

	// The same revision is fine — retrying a push that timed out mid-flight
	// must not be an error.
	status, _ = c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 5)}},
		map[string]string{"If-Match": "1"})
	if status != http.StatusOK {
		t.Fatalf("idempotent re-push refused: %d", status)
	}
}

func TestTombstonesAreStoredAndServed(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{env("a", 1)}},
		map[string]string{"If-Match": "0"})
	tomb := env("a", 2)
	tomb.Deleted = true
	c.do("PUT", "/v1/records", map[string]any{"records": []Envelope{tomb}},
		map[string]string{"If-Match": "1"})

	// A deletion has to travel as a fact. A record that simply vanished would be
	// indistinguishable from one that never arrived.
	_, out := c.do("GET", "/v1/records?since=0", nil, nil)
	recs := out["records"].([]any)
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if !recs[0].(map[string]any)["deleted"].(bool) {
		t.Fatal("tombstone lost its flag")
	}
}

// ---- meta ------------------------------------------------------------------

func TestMetaRoundTrips(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	if status, _ := c.do("GET", "/v1/meta", nil, nil); status != http.StatusOK {
		t.Fatalf("empty meta: %d", status)
	}
	meta := map[string]any{"format": 1, "kdf": map[string]any{"salt": "AAAA"}}
	if status, _ := c.do("PUT", "/v1/meta", map[string]any{"meta": meta}, nil); status != http.StatusOK {
		t.Fatal("put meta failed")
	}
	_, out := c.do("GET", "/v1/meta", nil, nil)
	got := out["meta"].(map[string]any)
	if got["format"].(float64) != 1 {
		t.Fatalf("meta did not round-trip: %v", got)
	}
}

// ---- durability ------------------------------------------------------------

func TestStoreSurvivesReopening(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put([]Envelope{env("a", 1)}, -1); err != nil {
		t.Fatal(err)
	}

	again, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	seq, recs := again.Since(0)
	if seq != 1 || len(recs) != 1 || recs[0].ID != "a" {
		t.Fatalf("reopened store lost data: seq=%d recs=%v", seq, recs)
	}
}

func TestSnapshotsAreWrittenAndPruned(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		if _, err := store.Put([]Envelope{env("a", i)}, int64(i-1)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	// Retention is the only defence the server can offer against a client that
	// pushes damaged ciphertext, since it cannot tell good from bad.
	if len(entries) != 3 {
		t.Fatalf("kept %d snapshots, want 3", len(entries))
	}
}
