package main

// Replay protection.
//
// A signature proves who sent a request. It does not prove the request has not
// been sent before, and the difference matters here because the LAN address is
// plain HTTP by design — anyone on the network can copy a request verbatim.
//
// The signing scheme used to lean on two things instead. Neither was enough:
//
//   - the five-minute clock window, which bounds how long a captured request
//     stays useful but does not stop it being used inside that window;
//   - compare-and-swap on the sequence, which does defeat a replayed record
//     write, because the second one loses the race. But not every authenticated
//     request is a write under CAS. `POST /v1/codes` mints a *fresh* enrolment
//     code on every call, so replaying one captured mint hands out as many
//     valid codes as the attacker cares to ask for, and each one buys a device
//     key. That is the whole enrolment model undone by a copied packet.
//
// So every authenticated request now carries a nonce, and a nonce is accepted
// once. The set only has to remember as far back as the clock window, because
// anything older is already refused by the timestamp check.

import (
	"sync"
	"time"
)

// How long a nonce is remembered.
//
// Twice the clock window, and the factor of two is the whole point. A request
// is accepted while |now - ts| <= maxSkew, which is a *ten* minute span: five
// minutes either side of the timestamp it carries. But a nonce is recorded when
// it arrives, not when it claims to have been sent — so remembering it for only
// maxSkew leaves a gap whenever the client's clock runs ahead.
//
// Concretely, with a client δ ahead: the request arrives at T, is remembered
// until T+maxSkew, and stays timestamp-valid until T+δ+maxSkew. Between those
// two the nonce has been forgotten and the request is still good, which is the
// replay this file exists to stop — reopened by exactly the unsynchronised
// clock maxSkew was widened to tolerate in the first place.
//
// Retaining for 2*maxSkew covers the entire validity window from either
// direction, and costs one more sweep interval of entries.
const nonceLifetime = 2 * maxSkew

// seen remembers which nonces have been used, per device, until they age out.
//
// Deliberately in memory and not written to disk. It holds at most a few
// minutes of traffic, and persisting it would mean a disk write on every
// authenticated read — the cost of which lands on every sync, to defend a
// window that a restart closes anyway by making every pre-restart timestamp
// stale within five minutes.
type seen struct {
	mu    sync.Mutex
	when  map[string]time.Time
	swept time.Time
}

func newSeen() *seen {
	return &seen{when: map[string]time.Time{}}
}

// use records a nonce and reports whether it was fresh.
//
// Called only after the signature has been checked. Recording before that would
// let anyone on the network fill this map with nonces they never had to sign
// for, which is a memory-exhaustion hole rather than a defence.
func (s *seen) use(device, nonce string, now time.Time) bool {
	key := device + "\x00" + nonce

	s.mu.Lock()
	defer s.mu.Unlock()

	// Sweep at most once a minute rather than on every request: the map is
	// small, and walking it per request would make the cost of a sync grow with
	// the traffic around it.
	if now.Sub(s.swept) > time.Minute {
		for k, t := range s.when {
			if now.Sub(t) > nonceLifetime {
				delete(s.when, k)
			}
		}
		s.swept = now
	}

	if t, ok := s.when[key]; ok && now.Sub(t) <= nonceLifetime {
		return false
	}
	s.when[key] = now
	return true
}
