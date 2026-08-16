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

	// Tolerance on the client's clock. Wide enough for a machine that has not
	// reached an NTP server yet, narrow enough that a captured request is not
	// replayable for long. Writes are additionally protected by compare-and-swap
	// on the sequence, so a replayed PUT loses the race with the real one.
	maxSkew = 5 * time.Minute
)

var errUnauthorised = errors.New("unauthorised")

// canonical is the exact string both sides sign. Any disagreement about it —
// a trailing slash, a dropped query string — surfaces as a signature mismatch
// with nothing to point at the cause, so it is defined in one place and the
// JavaScript client mirrors it literally.
//
//	METHOD \n /path?query \n unix-millis \n sha256(body) in lowercase hex
func canonical(method, uri, ts string, body []byte) string {
	sum := sha256.Sum256(body)
	return method + "\n" + uri + "\n" + ts + "\n" + hex.EncodeToString(sum[:])
}

func sign(key []byte, method, uri, ts string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical(method, uri, ts, body)))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// authenticate returns the calling device, or an error that deliberately does
// not distinguish an unknown device from a bad signature from a stale clock.
func (s *Store) authenticate(r *http.Request, body []byte) (Device, error) {
	id := r.Header.Get(hdrDevice)
	ts := r.Header.Get(hdrTime)
	got := r.Header.Get(hdrSig)
	if id == "" || ts == "" || got == "" {
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

	want := sign(key, r.Method, r.URL.RequestURI(), ts, body)
	// Constant time, because the comparison is against a value the caller chose.
	if !hmac.Equal([]byte(want), []byte(got)) {
		return Device{}, errUnauthorised
	}
	return dev, nil
}
