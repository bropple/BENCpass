package main

import (
	"testing"
	"time"
)

// The bug this pins is not "a nonce is forgotten too late" but "too early".
//
// A request is accepted while |now - ts| <= maxSkew, so it stays good until
// maxSkew *past the timestamp it carries*. A nonce, though, is recorded when it
// arrives. Remembering it for only maxSkew therefore leaves a gap for any
// client whose clock runs ahead — which is the case maxSkew exists to tolerate,
// so the defence fell over exactly where it was designed to hold.
func TestANonceOutlivesTheRequestThatCarriedIt(t *testing.T) {
	s := newSeen()
	arrived := time.Now()

	if !s.use("device", "n1", arrived) {
		t.Fatal("the first use of a nonce was refused")
	}

	// The far edge of what the timestamp check will still accept: a client five
	// minutes ahead, replayed five minutes after the genuine request landed.
	latest := arrived.Add(2 * maxSkew)
	if s.use("device", "n1", latest) {
		t.Fatalf("a nonce was forgotten %v after arrival while its request was still valid", 2*maxSkew)
	}

	// And it does not remember for ever, which would be an unbounded map.
	if !s.use("device", "n1", arrived.Add(2*maxSkew+time.Second)) {
		t.Fatal("a nonce was still remembered after every request carrying it had expired")
	}
}

func TestNoncesAreRememberedPerDevice(t *testing.T) {
	s := newSeen()
	now := time.Now()
	if !s.use("a", "shared", now) || !s.use("b", "shared", now) {
		t.Fatal("two devices picking the same nonce blocked each other")
	}
	if s.use("a", "shared", now) {
		t.Fatal("a device reused its own nonce")
	}
}

func TestTheSweepDoesNotForgetWhatItShouldKeep(t *testing.T) {
	// The sweep runs at most once a minute, so entries can outlive their
	// lifetime by up to that — harmless, since keeping one too long only ever
	// refuses a replay. What must never happen is the reverse.
	s := newSeen()
	start := time.Now()
	for i := 0; i < 200; i++ {
		if !s.use("device", string(rune('a'+i%26))+string(rune('a'+i/26)), start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("a fresh nonce was refused at step %d", i)
		}
	}
	// Sweeps have run by now. The earliest nonce is still inside its lifetime.
	if s.use("device", "aa", start.Add(199*time.Second)) {
		t.Fatal("the sweep dropped a nonce that was still within its lifetime")
	}
}
