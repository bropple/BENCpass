package main

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// The PNG icon exists for exactly one customer: TrueNAS's app-icon field,
// which fetches the URL itself and shows a generic placeholder when handed an
// SVG. So what is pinned here is what that fetcher needs — a real PNG body
// under a PNG content type, unauthenticated — not just "some 200".
func TestFaviconPNGIsServedForTheTrueNASIconField(t *testing.T) {
	srv, _, _ := newServer(t)

	res, err := http.Get(srv.URL + "/favicon.png")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content type %q", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("body does not start with the PNG signature")
	}
	// A truncated embed would still carry the signature; a real 512px render
	// of the mark cannot be tiny.
	if len(body) < 1024 {
		t.Fatalf("suspiciously small for a 512px icon: %d bytes", len(body))
	}
}
