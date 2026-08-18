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
// A request is accepted while its timestamp sits in [now-maxSkew, now+maxFuture]
// — equivalently, while now sits in [ts-maxFuture, ts+maxSkew]. That is a window
// of maxSkew+maxFuture wide, and a nonce has to outlive it or the request it
// spent becomes usable again at the end.
const nonceLifetime = maxSkew + maxFuture

// seen remembers which nonces have been used, per device, until they age out.
//
// In memory and not written to disk, because persisting it would mean a disk
// write on every authenticated request and that cost lands on every sync.
//
// An earlier version of this comment claimed a restart "closes the window
// anyway". It does the opposite, and it was demonstrated doing the opposite:
// a restart empties this map while the timestamps of everything captured in
// the preceding five minutes are still inside the clock window, so every one
// of them becomes replayable exactly once more. On `POST /v1/codes` — the
// endpoint this file exists for — that is a fresh enrolment code, and each
// code is a device key.
//
// The restart is handled where the damage was, rather than here: minting is
// idempotent on the request that asked for it, so a replay after a restart
// returns the code the caller already had instead of a new one. See
// NewCodeFor in store.go. A time floor was tried here first and refused honest
// clients for thirty seconds after every restart, including somebody starting
// the server and enrolling their second machine straight away.
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
