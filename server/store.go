package main

// Persistence. Everything here is opaque: the server stores ciphertext, counts
// revisions and hands out a sequence number. It holds no key and can decrypt
// nothing, so it also cannot merge anything — that is entirely the client's job.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrConflict = errors.New("sequence has moved on")
	ErrBackward = errors.New("record revision would go backwards")
	ErrBadCode  = errors.New("unknown or expired enrolment code")
)

// Envelope is a sealed record. The server understands only the four fields it
// needs to order and address one; n and ct are never interpreted.
type Envelope struct {
	ID      string `json:"id"`
	Rev     int    `json:"rev"`
	Deleted bool   `json:"deleted"`
	N       string `json:"n"`
	Ct      string `json:"ct"`
	Seq     int64  `json:"seq"`
}

type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Key     string `json:"key"` // base64, HMAC-SHA256 request signing
	Created int64  `json:"created"`
}

type data struct {
	Seq     int64               `json:"seq"`
	Meta    json.RawMessage     `json:"meta,omitempty"`
	Records map[string]Envelope `json:"records"`
	Devices map[string]Device   `json:"devices"`
	Codes   map[string]int64    `json:"codes"` // code -> expiry, unix ms
}

type Store struct {
	mu   sync.Mutex
	dir  string
	keep int
	d    data

	// Nonces already spent, so a captured request cannot be sent twice. Not
	// part of `data` and never written to disk — see replay.go.
	seen *seen
}

func OpenStore(dir string, keep int) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, keep: keep, seen: newSeen(), d: data{
		Records: map[string]Envelope{},
		Devices: map[string]Device{},
		Codes:   map[string]int64{},
	}}

	raw, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, fmt.Errorf("store is unreadable: %w", err)
	}
	// A store written by an older build may be missing a map entirely, and a nil
	// map panics on assignment rather than on read — so the failure would land
	// on the first write, long after the cause.
	if s.d.Records == nil {
		s.d.Records = map[string]Envelope{}
	}
	if s.d.Devices == nil {
		s.d.Devices = map[string]Device{}
	}
	if s.d.Codes == nil {
		s.d.Codes = map[string]int64{}
	}
	return s, nil
}

func (s *Store) path() string { return filepath.Join(s.dir, "store.json") }

// save writes through a temporary file and renames it, so an interrupted write
// leaves the previous store intact rather than a truncated one. The directory is
// fsynced as well: on ext4 a rename can otherwise outlive the data it points at.
func (s *Store) save() error {
	raw, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path()); err != nil {
		return err
	}
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return s.snapshot(raw)
}

// snapshot keeps the last `keep` writes. This is the backstop for a client that
// pushes damaged records: the server cannot tell good ciphertext from bad, so
// the only defence it can offer is a copy of what was there before.
func (s *Store) snapshot(raw []byte) error {
	if s.keep <= 0 {
		return nil
	}
	name := filepath.Join(s.dir, "snapshots", fmt.Sprintf("%012d.json", s.d.Seq))
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "snapshots"))
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // zero-padded, so lexical order is numeric order
	for i := 0; i < len(names)-s.keep; i++ {
		_ = os.Remove(filepath.Join(s.dir, "snapshots", names[i]))
	}
	return nil
}

// ---- records ---------------------------------------------------------------

func (s *Store) Seq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Seq
}

// Since returns every record written after seq, oldest first.
func (s *Store) Since(seq int64) (int64, []Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []Envelope{}
	for _, e := range s.d.Records {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].ID < out[j].ID
	})
	return s.d.Seq, out
}

// Put applies a batch under compare-and-swap on the global sequence.
//
// ifMatch < 0 means the caller is not checking, which is only for the very first
// write of a fresh vault. Everything else must pass the sequence it last saw, or
// two machines that both edited offline would silently overwrite one another.
func (s *Store) Put(records []Envelope, ifMatch int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ifMatch >= 0 && ifMatch != s.d.Seq {
		return s.d.Seq, ErrConflict
	}
	// Refuse a batch that would move any record backwards. A correct client
	// cannot produce one; an incorrect client doing so would erase a revision
	// that another machine had already agreed on. Equal revisions are allowed so
	// that retrying a push that timed out mid-flight is safe.
	for _, r := range records {
		if old, ok := s.d.Records[r.ID]; ok && r.Rev < old.Rev {
			return s.d.Seq, fmt.Errorf("%w: %s at rev %d, store has %d",
				ErrBackward, r.ID, r.Rev, old.Rev)
		}
	}

	s.d.Seq++
	// One sequence number per accepted batch, not per record: `since` then means
	// "everything from that write onward", and a batch cannot be half-visible.
	for _, r := range records {
		r.Seq = s.d.Seq
		s.d.Records[r.ID] = r
	}
	if err := s.save(); err != nil {
		return s.d.Seq, err
	}
	return s.d.Seq, nil
}

// ---- meta ------------------------------------------------------------------

// Meta is the vault header: KDF parameters and the wrapped vault key. It has to
// live here so a newly enrolled machine can bootstrap from the master password
// alone.
//
// It is also the reason an attacker who takes the server can mount an offline
// attack on the master password. That is inherent to any synced vault and is
// stated plainly rather than glossed: Argon2id at 128 MiB is the whole of what
// stands between a stolen store.json and the contents.
func (s *Store) Meta() (json.RawMessage, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Meta, s.d.Seq
}

// PutMeta replaces the vault header, under the same compare-and-swap as records.
//
// The check is not ceremony. This header carries the wrapped vault key, so a
// write that lands out of order reinstates an old wrapping — and after a master
// password change that means the new password stops opening the vault and the
// old one starts again. The client cannot notice on its own: it watches for the
// sequence going *backwards*, and a stale header written late arrives with a
// sequence going forwards like any other write.
//
// ifMatch < 0 means the caller is not checking, which is only legitimate for the
// first write to a fresh store.
func (s *Store) PutMeta(meta json.RawMessage, ifMatch int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ifMatch >= 0 && ifMatch != s.d.Seq {
		return s.d.Seq, ErrConflict
	}

	s.d.Meta = meta
	s.d.Seq++
	if err := s.save(); err != nil {
		return s.d.Seq, err
	}
	return s.d.Seq, nil
}

// ---- devices and enrolment -------------------------------------------------

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("no entropy: " + err.Error()) // unrecoverable, and never silently
	}
	return b
}

func token(n int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(n))
}

func (s *Store) DeviceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.d.Devices)
}

func (s *Store) Device(id string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.d.Devices[id]
	return d, ok
}

// NewCode mints a one-time enrolment code. Short-lived on purpose: it is typed
// by a human into another machine, so it only has to survive that walk.
func (s *Store) NewCode(ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear out anything that expired without being redeemed. Only the exact
	// code submitted was ever deleted, on redemption, so a code that was minted
	// and never used stayed in the file for good — and every mint rewrites the
	// whole file, so the cost of keeping them compounds. Nobody would notice
	// until the store had been in use for years, which is the kind of thing
	// that is much easier to fix now than then.
	now := time.Now().UnixMilli()
	for c, expiry := range s.d.Codes {
		if now > expiry {
			delete(s.d.Codes, c)
		}
	}

	code := token(9)
	s.d.Codes[code] = time.Now().Add(ttl).UnixMilli()
	return code, s.save()
}

// Redeem consumes a code and issues a device. The code is deleted whether or not
// the save succeeds, so a failed enrolment cannot be retried with the same code.
func (s *Store) Redeem(code, name string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.d.Codes[code]
	delete(s.d.Codes, code)
	if !ok || time.Now().UnixMilli() > expiry {
		return Device{}, ErrBadCode
	}

	dev := Device{
		ID:      token(9),
		Name:    name,
		Key:     base64.StdEncoding.EncodeToString(randomBytes(32)),
		Created: time.Now().UnixMilli(),
	}
	s.d.Devices[dev.ID] = dev
	return dev, s.save()
}
