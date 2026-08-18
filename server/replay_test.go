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
	// The probe has to be an entry whose age at the moment of checking sits
	// between maxSkew and nonceLifetime, because that is the only band where a
	// too-short lifetime and a correct one disagree. An earlier version probed
	// an entry thirty seconds old, which no plausible regression would have
	// dropped: it passed with the lifetime reverted to maxSkew and with the
	// sweep made four times too aggressive, while claiming to pin both.
	s := newSeen()
	start := time.Now()

	// Half-minute traffic for twenty minutes, so sweeps fire throughout and
	// entries cross the boundary while the map is in use.
	for i := 1; i <= 40; i++ {
		at := start.Add(time.Duration(i) * 30 * time.Second)
		if !s.use("device", "n"+strconv.Itoa(i), at) {
			t.Fatalf("a fresh nonce was refused at %v", at.Sub(start))
		}
	}
	check := start.Add(20 * time.Minute)

	// n21 landed at 10m30s, so it is 9m30s old here: past maxSkew, inside
	// nonceLifetime. A request carrying it can still be accepted, so the nonce
	// must still be remembered.
	if s.use("device", "n21", check) {
		t.Fatal("a nonce inside its lifetime was swept away")
	}

	// n1 landed at 30s, so it is 19m30s old: no request carrying it can be
	// accepted any more, and holding it for ever would be an unbounded map.
	if !s.use("device", "n1", check) {
		t.Fatal("a nonce was still held long after any request carrying it had expired")
	}

	// And the sweep has actually deleted, rather than merely letting entries
	// expire logically. The distinction is the whole reason the sweep exists:
	// the membership check above refuses a stale nonce whether or not anything
	// was ever removed, so without looking in the map, a server that never
	// collects is indistinguishable from one that does -- until it runs for a
	// month.
	//
	// Checked by asking for a specific long-dead key rather than by counting.
	// A count is only as good as the number it is compared against, and an
	// earlier version of this test compared against the exact number of inserts
	// it made, so the assertion could not fire under any implementation at all.
	if _, held := s.when["device\x00n2"]; held {
		t.Fatal("a nonce nineteen minutes past its lifetime is still in the map")
	}

	// Roughly the entries from the last ten minutes, plus the one the probe
	// above put back. Generous, because the sweep cadence means a few may
	// linger; tight enough that a sweep which never runs fails here.
	if len(s.when) > 25 {
		t.Fatalf("the sweep is not collecting: %d entries held", len(s.when))
	}
}
