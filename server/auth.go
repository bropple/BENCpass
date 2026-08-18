package main

// Request signing.
//
// The vault is end-to-end encrypted, so this is not what keeps the contents
// secret — it is what stops anyone on the network from writing to the store,
// harvesting the wrapped key, or serving a client an old copy of its own vault.
// It works over plain HTTP, which is what makes the LAN fallback acceptable.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const (
	hdrDevice = "X-Bencpass-Device"
	hdrTime   = "X-Bencpass-Time"
	hdrSig    = "X-Bencpass-Sig"
	hdrNonce  = "X-Bencpass-Nonce"

	// Tolerance on the client's clock. Wide enough for a machine that has not
	// reached an NTP server yet, narrow enough that the set of nonces the server
	// has to remember stays small — see replay.go, which is what actually stops
	// a captured request being sent twice.
	maxSkew = 5 * time.Minute

	// Long enough that two clients cannot pick the same one, short enough to
	// bound what an attacker can make the server remember. 16 bytes, hex.
	maxNonce = 64
)

var errUnauthorised = errors.New("unauthorised")

// canonical is the exact string both sides sign. Any disagreement about it —
// a trailing slash, a dropped query string — surfaces as a signature mismatch
// with nothing to point at the cause, so it is defined in one place and the
// JavaScript client mirrors it literally.
//
//	METHOD \n host \n /path?query \n unix-millis \n nonce \n If-Match \n sha256(body) in hex
//
// The host is in there because a client with two addresses for one server will
// try the second when the first does not answer — and "does not answer" is not
// the same as "did not receive". Something sitting on the LAN address can read
// a whole signed request and then drop the connection, leaving the client to
// succeed quietly against the real address while the eavesdropper keeps a
// perfectly good request. Binding the host makes what it kept useless anywhere
// but the address it was already sent to.
//
// A consequence worth knowing when deploying: a reverse proxy that rewrites the
// Host header will break every signature, because the client signs the address
// it dialled and the server checks the one it was handed.
// If-Match is signed because it decides whether the write is checked at all.
// Left out, an attacker on the path could take an otherwise perfectly valid
// request — right device, right nonce, right body — and change only that header
// without disturbing the signature, turning a compare-and-swap into an
// unconditional overwrite. The header is carried in the signature rather than
// merely validated so that it cannot be edited in flight at all.
func canonical(method, host, uri, ts, nonce, ifMatch string, body []byte) string {
	sum := sha256.Sum256(body)
	return method + "\n" + host + "\n" + uri + "\n" + ts + "\n" + nonce + "\n" +
		ifMatch + "\n" + hex.EncodeToString(sum[:])
}

func sign(key []byte, method, host, uri, ts, nonce, ifMatch string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical(method, host, uri, ts, nonce, ifMatch, body)))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// authenticate returns the calling device, or an error that deliberately does
// not distinguish an unknown device from a bad signature from a stale clock.
func (s *Store) authenticate(r *http.Request, body []byte) (Device, error) {
	id := r.Header.Get(hdrDevice)
	ts := r.Header.Get(hdrTime)
	got := r.Header.Get(hdrSig)
	nonce := r.Header.Get(hdrNonce)
	if id == "" || ts == "" || got == "" || nonce == "" || len(nonce) > maxNonce {
		return Device{}, errUnauthorised
	}

	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return Device{}, errUnauthorised
	}
	if d := time.Since(time.UnixMilli(ms)); d > maxSkew || d < -maxSkew {
		return Device{}, errUnauthorised
	}

	dev, ok := s.Device(id)
	if !ok {
		return Device{}, errUnauthorised
	}
	key, err := base64.StdEncoding.DecodeString(dev.Key)
	if err != nil {
		return Device{}, errUnauthorised
	}

	want := sign(key, r.Method, r.Host, r.URL.RequestURI(), ts, nonce, r.Header.Get("If-Match"), body)
	// Constant time, because the comparison is against a value the caller chose.
	if !hmac.Equal([]byte(want), []byte(got)) {
		return Device{}, errUnauthorised
	}

	// Last, and only once the signature has been proved. A nonce recorded before
	// that would let anyone on the network fill the set with values they never
	// had to sign for.
	if !s.seen.use(id, nonce, time.Now()) {
		return Device{}, errUnauthorised
	}
	return dev, nil
}
