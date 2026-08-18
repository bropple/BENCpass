package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	t     *testing.T
	srv   *httptest.Server
	id    string
	key   []byte
	skew  time.Duration // deliberately wrong clock, for the replay-window test
	nonce string        // pinned, so a test can deliberately send the same one twice
}

// newServerOn reopens an existing data directory: a restart, with the devices
// and the sequence intact and everything held only in memory gone.
func newServerOn(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	store, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&server{store: store}).routes())
	t.Cleanup(srv.Close)
	return srv
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
// codeFrom asks an enrolled device for a code to enrol the next one with.
// Not `mint`: store.go has a type by that name, and they share a package.
func codeFrom(t *testing.T, c *client) string {
	t.Helper()
	status, out := c.do("POST", "/v1/codes", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("minting refused: %d", status)
	}
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatal("no code in the reply")
	}
	return code
}

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
	// A fresh nonce per call, because the server accepts each one once. Tests
	// that want to replay a request capture the headers and send them again.
	nonce := c.nonce
	if nonce == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			c.t.Fatal(err)
		}
		nonce = hex.EncodeToString(b[:])
	}
	req.Header.Set(hdrDevice, c.id)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrNonce, nonce)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Signed after the caller's headers are on, because If-Match is one of them
	// and it is part of what gets signed.
	req.Header.Set(hdrSig, sign(c.key, method, req.Host, path, ts, nonce, req.Header.Get("If-Match"), raw))

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

func TestNegativeIfMatchCannotSwitchOffTheCheck(t *testing.T) {
	for _, path := range []string{"/v1/meta", "/v1/records"} {
		// A server each: the first write below is the one that is allowed to go
		// without If-Match, and it is only allowed while the store is empty.
		srv, _, code := newServer(t)
		c := enrol(t, srv, code, "laptop")

		body := map[string]any{"meta": map[string]any{"wrap": "v1"}}
		if path == "/v1/records" {
			body = map[string]any{"records": []Envelope{env("a", 1)}}
		}
		if status, _ := c.do("PUT", path, body, nil); status != http.StatusOK {
			t.Fatalf("%s: first write refused: %d", path, status)
		}

		// Below the handler, a negative ifMatch means "not checking" -- which is
		// only ever legitimate for the first write to an empty store, and is
		// reached by leaving the header off rather than by sending a number. A
		// client asking for it by name is asking to skip compare-and-swap.
		for _, v := range []string{"-1", "-5"} {
			status, _ := c.do("PUT", path, body, map[string]string{"If-Match": v})
			if status != http.StatusBadRequest {
				t.Fatalf("%s: If-Match %s switched off the check: %d", path, v, status)
			}
		}
	}
}

func TestIfMatchCannotBeChangedInFlight(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	if status, _ := c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v1"}}, nil); status != http.StatusOK {
		t.Fatalf("first write refused: %d", status)
	}

	// Everything correct -- right device, fresh nonce, untouched body -- except
	// that the header deciding whether the write is checked has been altered on
	// the way. If it is not part of what was signed, this succeeds and
	// compare-and-swap has been steered by somebody who never held the key.
	//
	// Both values are positive and well-formed, which is the point. An earlier
	// version signed 999 and sent -1, and still passed with the signing removed
	// entirely: the handler's negative check was refusing it, so the test proved
	// nothing about signing at all. The real attack is positive to positive --
	// take a stale write held back on the wire and move its If-Match from the
	// sequence it was built for to the one the server is on now, and it lands
	// past a compare-and-swap that was working perfectly.
	raw, _ := json.Marshal(map[string]any{"meta": map[string]any{"wrap": "evil"}})
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const nonce = "in-flight"
	req, _ := http.NewRequest("PUT", srv.URL+"/v1/meta", bytes.NewReader(raw))
	req.Header.Set(hdrDevice, c.id)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, sign(c.key, "PUT", req.Host, "/v1/meta", ts, nonce, "1", raw))
	req.Header.Set("If-Match", "9999") // signed for one sequence, sent for another

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// 401 specifically. A 409 would mean it got past authentication and
	// compare-and-swap happened to catch it -- which is exactly what happens
	// when If-Match is left out of the signature, and is what made the earlier
	// version of this test pass for the wrong reason.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("If-Match was altered in flight and the signature did not notice: %d", resp.StatusCode)
	}
}

func TestMetaWriteNeedsTheSequenceItSaw(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// First write to a fresh store: no sequence to match yet.
	status, out := c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v1"}}, nil)
	if status != http.StatusOK {
		t.Fatalf("first meta write refused: %d", status)
	}
	first := int64(out["seq"].(float64))

	// A master password change: same store, new wrapping, matching the sequence.
	status, out = c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v2"}},
		map[string]string{"If-Match": strconv.FormatInt(first, 10)})
	if status != http.StatusOK {
		t.Fatalf("rotation refused: %d", status)
	}

	// Now the write that used to slip through: an old header arriving late.
	// Without compare-and-swap it lands, the sequence goes *up*, and the client
	// -- which only watches for the sequence going down -- serves the old
	// wrapped key to the next machine that bootstraps from it.
	status, _ = c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v1"}},
		map[string]string{"If-Match": strconv.FormatInt(first, 10)})
	if status != http.StatusConflict {
		t.Fatalf("a stale meta write was accepted: %d", status)
	}

	status, out = c.do("GET", "/v1/meta", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("meta read failed: %d", status)
	}
	if got := out["meta"].(map[string]any)["wrap"]; got != "v2" {
		t.Fatalf("the header was rolled back to %v", got)
	}
}

func TestMetaWriteRequiresIfMatchOnceTheStoreIsNotEmpty(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	if status, _ := c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v1"}}, nil); status != http.StatusOK {
		t.Fatalf("first meta write refused: %d", status)
	}
	// A client that skips the check entirely, rather than getting it wrong.
	status, _ := c.do("PUT", "/v1/meta", map[string]any{"meta": map[string]any{"wrap": "v9"}}, nil)
	if status != http.StatusPreconditionRequired {
		t.Fatalf("a meta write with no If-Match was accepted: %d", status)
	}
}

func TestARestartDoesNotHandBackTheReplayWindow(t *testing.T) {
	srv, store, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// One genuine mint, captured off the wire by anyone on the plain-HTTP LAN
	// the design deliberately tolerates.
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const nonce = "captured-before-the-restart"
	send := func(target string) (int, string) {
		r, err := http.NewRequest("POST", target+"/v1/codes", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(hdrDevice, c.id)
		r.Header.Set(hdrTime, ts)
		r.Header.Set(hdrNonce, nonce)
		r.Header.Set(hdrSig, sign(c.key, "POST", r.Host, "/v1/codes", ts, nonce, "", nil))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		minted, _ := out["code"].(string)
		return resp.StatusCode, minted
	}

	status, first := send(srv.URL)
	if status != http.StatusOK || first == "" {
		t.Fatalf("the genuine mint was refused: %d", status)
	}

	// While the process lives the nonce is spent, and the replay is refused.
	if status, _ := send(srv.URL); status != http.StatusUnauthorized {
		t.Fatalf("a replay was honoured before any restart: %d", status)
	}

	// The code is then used, because that is what a code is for. This step is
	// the one an earlier version of this test left out, and leaving it out was
	// the difference between passing and catching a device-key giveaway: the
	// first implementation keyed idempotency on the code still existing, and
	// redeeming it is precisely what makes it stop existing.
	enrol(t, srv, first, "the-second-machine")

	// Now the restart. Devices and sequence survive; the nonce map does not.
	restarted := newServerOn(t, store.dir)
	status, again := send(restarted.URL)

	// The replay must not produce a code that can still be redeemed. Returning
	// the spent one is fine — whoever could replay the request also saw the
	// response to the original — but a fresh one is a second device key, which
	// is a full peer on the vault.
	if status == http.StatusOK && again != first {
		t.Fatalf("the replay minted a second code after the first was redeemed: %q then %q", first, again)
	}
	if status != http.StatusOK && status != http.StatusUnauthorized {
		t.Fatalf("unexpected answer to the replay: %d", status)
	}

	// And whatever came back cannot buy a device.
	if again != "" {
		body, _ := json.Marshal(map[string]any{"code": again, "name": "rogue"})
		resp, err := http.Post(restarted.URL+"/v1/enrol", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("the replayed code enrolled a rogue device")
		}
	}
}

func TestReplayedRequestIsRefused(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// The exact bytes of one signed mint, sent twice. The first send is the real
	// device asking for an enrolment code; the second is anyone who was on the
	// network while it did, since the LAN address is plain HTTP by design.
	//
	// This is the shape that made the timestamp window insufficient on its own:
	// minting is not a write under compare-and-swap, so nothing else was going
	// to stop the second one. Every replay used to return a *fresh* code, and
	// each code buys a device key.
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const nonce = "a-nonce-used-once"

	send := func() (int, map[string]any) {
		r, err := http.NewRequest("POST", srv.URL+"/v1/codes", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(hdrDevice, c.id)
		r.Header.Set(hdrTime, ts)
		r.Header.Set(hdrNonce, nonce)
		r.Header.Set(hdrSig, sign(c.key, "POST", r.Host, "/v1/codes", ts, nonce, "", nil))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	status, first := send()
	if status != http.StatusOK {
		t.Fatalf("the genuine request was refused: %d", status)
	}
	if first["code"] == nil || first["code"] == "" {
		t.Fatal("no code in the genuine reply")
	}

	status, second := send()
	if status != http.StatusUnauthorized {
		t.Fatalf("a captured mint was honoured a second time: %d, code %v", status, second["code"])
	}
}

func TestNonceIsRequired(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// An older client, or anything hoping the check can be skipped by leaving
	// the header off. Signed correctly for everything else.
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	r, _ := http.NewRequest("POST", srv.URL+"/v1/codes", nil)
	r.Header.Set(hdrDevice, c.id)
	r.Header.Set(hdrTime, ts)
	r.Header.Set(hdrSig, sign(c.key, "POST", r.Host, "/v1/codes", ts, "", "", nil))

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request with no nonce was accepted: %d", resp.StatusCode)
	}
}

func TestSignatureIsBoundToTheHost(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// What a hostile first address harvests: a complete, correctly signed
	// request that it read before dropping the connection. Sending it on to the
	// real server has to fail, or the two-address failover hands an eavesdropper
	// a working request every time the LAN address is unreachable.
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const nonce = "harvested"
	r, _ := http.NewRequest("POST", srv.URL+"/v1/codes", nil)
	r.Header.Set(hdrDevice, c.id)
	r.Header.Set(hdrTime, ts)
	r.Header.Set(hdrNonce, nonce)
	r.Header.Set(hdrSig, sign(c.key, "POST", "somewhere-else.invalid:8788", "/v1/codes", ts, nonce, "", nil))

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request signed for another address was accepted: %d", resp.StatusCode)
	}
}

func TestTamperedBodyIsRefused(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")

	// Sign one body, send another — what a LAN attacker rewriting a request in
	// flight would do. The signature covers the body's hash, so it fails.
	raw, _ := json.Marshal(map[string]any{"records": []Envelope{env("a", 1)}})
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	evil, _ := json.Marshal(map[string]any{"records": []Envelope{env("a", 99)}})
	req, _ := http.NewRequest("PUT", srv.URL+"/v1/records", bytes.NewReader(evil))
	good := sign(c.key, "PUT", req.Host, "/v1/records", ts, "tamper-nonce", "", raw)
	req.Header.Set(hdrDevice, c.id)
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrNonce, "tamper-nonce")
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

func TestExpiredCodesDoNotAccumulate(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 5)
	if err != nil {
		t.Fatal(err)
	}

	// Codes that were minted and never used. Redeem is the only thing that ever
	// removed one, and only the exact code submitted, so these used to stay in
	// the file for the life of the server -- and every mint rewrites the file
	// whole, so the cost of keeping them grew with the count.
	for i := 0; i < 20; i++ {
		if _, err := store.NewCode(-time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.NewCode(30 * time.Minute); err != nil {
		t.Fatal(err)
	}

	if n := len(store.d.Codes); n != 1 {
		t.Fatalf("expired codes are still held: %d in the store, want only the live one", n)
	}
}

func TestDevicesCanBeListedAndRevoked(t *testing.T) {
	srv, _, code := newServer(t)
	first := enrol(t, srv, code, "laptop")
	second := enrol(t, srv, codeFrom(t, first), "the-lost-one")

	status, out := first.do("GET", "/v1/devices", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("listing refused: %d", status)
	}
	devices, _ := out["devices"].([]any)
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}

	// Keys never leave the store. An authenticated caller has their own and no
	// business with anyone else's.
	for _, d := range devices {
		if _, leaked := d.(map[string]any)["key"]; leaked {
			t.Fatal("the device list handed out a signing key")
		}
	}

	// Revoke the lost machine from the one still in hand.
	if status, _ := first.do("DELETE", "/v1/devices/"+second.id, nil, nil); status != http.StatusOK {
		t.Fatalf("revoking refused: %d", status)
	}

	// Its key stops authenticating anything at all.
	if status, _ := second.do("GET", "/v1/records?since=0", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("a revoked device could still read: %d", status)
	}
	if status, _ := second.do("POST", "/v1/codes", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("a revoked device could still mint codes: %d", status)
	}

	// And the machine that did the revoking is unaffected.
	if status, _ := first.do("GET", "/v1/records?since=0", nil, nil); status != http.StatusOK {
		t.Fatalf("the surviving device lost access: %d", status)
	}
}

func TestTheLastDeviceCannotRevokeItself(t *testing.T) {
	srv, _, code := newServer(t)
	only := enrol(t, srv, code, "the-only-one")

	// A store with no devices is unreachable: nothing can enrol, because
	// minting a code needs a device to sign the request, and nothing can read,
	// because every route is signed. The only way back would be deleting the
	// file, which takes the vault header with it.
	status, _ := only.do("DELETE", "/v1/devices/"+only.id, nil, nil)
	if status != http.StatusConflict {
		t.Fatalf("the last device removed itself: %d", status)
	}
	if status, _ := only.do("GET", "/v1/records?since=0", nil, nil); status != http.StatusOK {
		t.Fatalf("the last device lost access anyway: %d", status)
	}
}

func TestRevokingSomethingAlreadyGoneIsFine(t *testing.T) {
	srv, _, code := newServer(t)
	c := enrol(t, srv, code, "laptop")
	enrol(t, srv, codeFrom(t, c), "spare")

	// Asked for a state that already holds. Reporting a failure would invite a
	// retry loop over something that is already true.
	status, out := c.do("DELETE", "/v1/devices/never-existed", nil, nil)
	if status != http.StatusOK || out["alreadyGone"] != true {
		t.Fatalf("revoking an unknown device: %d %v", status, out)
	}
}
