package main

import (
	"strconv"
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
	// lifetime by up to that -- harmless, since keeping one too long only ever
	// refuses a replay. What must never happen is the reverse.
	//
	// The span deliberately runs past nonceLifetime so the sweep actually
	// deletes something; an earlier version stayed inside it and so never
	// exercised the branch it claimed to be testing.
	s := newSeen()
	start := time.Now()

	if !s.use("device", "first", start) {
		t.Fatal("a fresh nonce was refused")
	}

	// Traffic either side of the boundary, enough of it to trigger sweeps.
	for i := 1; i <= 40; i++ {
		at := start.Add(time.Duration(i) * time.Minute / 2)
		if !s.use("device", "n"+strconv.Itoa(i), at) {
			t.Fatalf("a fresh nonce was refused at %v", at)
		}
	}

	// Still inside its lifetime despite every sweep that has run since.
	if s.use("device", "n38", start.Add(20*time.Minute)) {
		t.Fatal("the sweep dropped a nonce that was still within its lifetime")
	}

	// And the map does not grow for ever: the first one is long past its
	// lifetime by now and has been let go.
	if len(s.when) > 40 {
		t.Fatalf("the sweep is not collecting: %d entries held", len(s.when))
	}
}
