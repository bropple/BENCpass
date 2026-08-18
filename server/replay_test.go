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
	// Written against nonceLifetime rather than a multiple of maxSkew, because
	// the relationship between the two has already changed once: the lifetime
	// has to cover the whole span in which a request stays acceptable, and that
	// span is maxSkew+maxFuture, not twice either of them.
	s := newSeen()
	arrived := time.Now()

	if !s.use("device", "n1", arrived) {
		t.Fatal("the first use of a nonce was refused")
	}

	// The far edge of what the timestamp check will still accept.
	if s.use("device", "n1", arrived.Add(nonceLifetime)) {
		t.Fatalf("a nonce was forgotten %v after arrival while its request was still valid", nonceLifetime)
	}

	// And it does not remember for ever, which would be an unbounded map.
	if !s.use("device", "n1", arrived.Add(nonceLifetime+time.Second)) {
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
	//
	// Both probes are expressed as fractions of nonceLifetime. An earlier
	// version used absolute times that happened to sit inside it, so it passed
	// with the lifetime reverted *and* with the sweep four times too
	// aggressive, while claiming to pin both.
	s := newSeen()
	start := time.Now()
	step := 30 * time.Second
	steps := int(2*nonceLifetime/step) + 4

	for i := 1; i <= steps; i++ {
		if !s.use("device", "n"+strconv.Itoa(i), start.Add(time.Duration(i)*step)) {
			t.Fatalf("a fresh nonce was refused at %v", time.Duration(i)*step)
		}
	}
	check := start.Add(time.Duration(steps) * step)

	// Still inside its lifetime, so a request carrying it could still be
	// accepted, so it must still be remembered.
	inside := steps - int(nonceLifetime/step) + 1
	if s.use("device", "n"+strconv.Itoa(inside), check) {
		t.Fatal("a nonce inside its lifetime was swept away")
	}

	// Long dead, and actually gone from the map rather than merely refused by
	// the age check — the sweep either collects or the map grows for ever, and
	// only looking inside can tell those apart.
	if _, held := s.when["device\x00n1"]; held {
		t.Fatal("a nonce long past its lifetime is still in the map")
	}

	if len(s.when) > steps/2 {
		t.Fatalf("the sweep is not collecting: %d of %d entries held", len(s.when), steps)
	}
}

// Minting is idempotent, so a replay cannot turn one captured request into two
// device keys — which is the property the nonce map provides while the process
// lives and cannot provide across a restart, since it starts empty.
//
// The end-to-end version of this is TestARestartDoesNotHandBackTheReplayWindow.
// This is the store-level check that the same request twice yields one code.
func TestMintingIsIdempotentForOneRequest(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.NewCodeFor("device", "nonce-a", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.NewCodeFor("device", "nonce-a", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("the same request minted two codes: %q then %q", first, again)
	}

	// Across a restart too, which is the case that matters: the nonce map is
	// gone by then and this file is all that is left to remember by.
	reopened, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.NewCodeFor("device", "nonce-a", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if after != first {
		t.Fatalf("a restart let one request mint a second code: %q then %q", first, after)
	}

	// A different request is a different code, or nobody could ever enrol twice.
	other, err := reopened.NewCodeFor("device", "nonce-b", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("two different requests were given the same code")
	}

	// And the bootstrap code, which belongs to no request, is never shared.
	boot1, _ := reopened.NewCode(30 * time.Minute)
	boot2, _ := reopened.NewCode(30 * time.Minute)
	if boot1 == boot2 {
		t.Fatal("two bootstrap codes came back identical")
	}
}
