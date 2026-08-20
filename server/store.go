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
	ErrConflict  = errors.New("sequence has moved on")
	ErrBackward  = errors.New("record revision would go backwards")
	ErrResurrect = errors.New("record would come back from deletion")
	ErrBadCode   = errors.New("unknown or expired enrolment code")

	// A device that is not enrolled: already revoked, or never was.
	ErrNoDevice = errors.New("no such device")

	// Guards against locking every machine out at once; see Forget.
	ErrLastDevice = errors.New("cannot remove the last device")
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
	// Which request minted which code, so that minting is idempotent — see
	// NewCodeFor. Keyed by device and the request's nonce.
	//
	// Carries its own expiry rather than living or dying with the code it names.
	// The first version was a bare map to the code and asked whether that code
	// was still live: redeeming it — the one thing a code is for — broke the
	// link, and a replay after a restart then minted a fresh one. The fact worth
	// remembering is "this request was already served", which has nothing to do
	// with what later happened to the code.
	Mints map[string]mint `json:"mints,omitempty"` // device\x00nonce -> what it got
}

// mint is what one request was already given, and until when that is worth
// remembering.
type mint struct {
	Code   string `json:"code"`
	Expiry int64  `json:"expiry"` // unix ms
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
		Mints:   map[string]mint{},
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
	if s.d.Mints == nil {
		s.d.Mints = map[string]mint{}
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
	//
	// Refuse, likewise, a live record over a stored tombstone. Deletion is
	// terminal per id: nothing in the client ever revives one in place — add,
	// import and conflict forks all mint fresh UUIDs, and update refuses a
	// deleted id — so the only way a live write lands on a deleted record is a
	// machine that was never shown the tombstone, which means a server that
	// withheld it: a restored backup, a dropped delta, a bug. In a password
	// manager that write puts back a credential somebody deliberately rotated
	// away from. The client refuses to fast-forward over its own acknowledged
	// tombstone; this is the same rule on the storing side, so the resurrection
	// is never even held.
	//
	// Be clear about what this buys. `deleted` is cleartext the server can read
	// but cannot verify — the sealed body is the authority, and only the client
	// holds the key. So this stops an honest-but-broken server from *storing* a
	// resurrection, and it does nothing against a hostile server, which would
	// simply not run this check. The client-side refusal is the real defence;
	// this is the belt to those braces.
	//
	// A store with no record at the id is not a tombstone: a fresh push after
	// the data directory is lost, or a re-enrolment against a rebuilt server,
	// passes untouched. Tombstone over tombstone passes too — that is how a
	// superseded deletion, or a retried one, syncs.
	for _, r := range records {
		old, ok := s.d.Records[r.ID]
		if !ok {
			continue
		}
		if r.Rev < old.Rev {
			return s.d.Seq, fmt.Errorf("%w: %s at rev %d, store has %d",
				ErrBackward, r.ID, r.Rev, old.Rev)
		}
		if old.Deleted && !r.Deleted {
			return s.d.Seq, fmt.Errorf("%w: %s is deleted at rev %d, refusing live rev %d",
				ErrResurrect, r.ID, old.Rev, r.Rev)
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

// DeviceInfo is a device as the outside world is allowed to see it.
//
// A separate type rather than a Device with the key left blank, and the
// difference is not style. Blanking a field is a thing somebody has to remember
// to keep doing: one `append(out, d)` written in a hurry and every signing key
// in the store goes out over the wire. A type with nowhere to put a key cannot
// carry one.
type DeviceInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
}

// Devices lists what is enrolled. Never the keys: an authenticated caller has
// their own and no business with anyone else's.
func (s *Store) Devices() []DeviceInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]DeviceInfo, 0, len(s.d.Devices))
	for _, d := range s.d.Devices {
		out = append(out, DeviceInfo{ID: d.ID, Name: d.Name, Created: d.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created < out[j].Created })
	return out
}

// Forget removes a device. That is what revoking a lost machine means: its key
// stops authenticating anything, and it cannot enrol again without a new code.
//
// The last one cannot be removed. A store with no devices is unreachable —
// nothing could enrol, because minting a code needs a device to sign the
// request, and nothing could read, because every route is signed. So the one
// machine still holding a key keeps it. The deliberate exception is offline:
// when every machine really is gone, the rescue tool's -forget empties the
// device list with the server stopped, and the next start prints a bootstrap
// code again.
func (s *Store) Forget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.d.Devices[id]; !ok {
		return ErrNoDevice
	}
	if len(s.d.Devices) == 1 {
		return ErrLastDevice
	}
	delete(s.d.Devices, id)
	return s.save()
}

// NewCode mints a one-time enrolment code. Short-lived on purpose: it is typed
// by a human into another machine, so it only has to survive that walk.
// NewCodeFor mints an enrolment code for one request, and only one.
//
// Idempotent on (device, nonce), and that is the whole defence rather than a
// convenience. Minting is the one authenticated call with no compare-and-swap
// behind it, so a captured request replayed on the wire used to return a fresh
// code every time — and every code buys a device key, which is a full peer on
// the vault. The in-memory nonce set stops that while the process lives and is
// empty after a restart, which is exactly when it was needed.
//
// Remembering which request produced which code, in the file beside the code,
// removes the reason to care. A replay returns the same code the caller already
// had — and if the attacker was positioned to capture the request, they saw the
// response carrying that code anyway. It is single-use, so whoever redeems
// first wins, and the replay has gained nothing that the original capture did
// not already give away.
//
// A time-based floor was tried first and thrown away: it refused honest clients
// for thirty seconds after every restart, including the case of starting the
// server and immediately enrolling a second machine, which is what people do on
// the first day.
func (s *Store) NewCodeFor(device, nonce string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := device + "\x00" + nonce
	// Deliberately not conditional on the code still existing. It will not: the
	// point of minting one is to redeem it, and Redeem deletes it. Asking about
	// liveness here is what let a replay after a restart mint a second code
	// once the first had been used — the whole hole, reopened by the ordinary
	// case rather than an unusual one.
	if m, ok := s.d.Mints[key]; ok && time.Now().UnixMilli() <= m.Expiry {
		return m.Code, nil
	}
	return s.mintLocked(key, ttl)
}

// NewCode mints without an owning request: the bootstrap code printed at
// startup, which no client asked for and nobody can replay.
func (s *Store) NewCode(ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mintLocked("", ttl)
}

func (s *Store) mintLocked(key string, ttl time.Duration) (string, error) {

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

	// Swept on their own expiry. A request stops being replayable once its
	// timestamp falls outside the clock window, so remembering it for as long
	// as the code it produced is already generous.
	for k, m := range s.d.Mints {
		if now > m.Expiry {
			delete(s.d.Mints, k)
		}
	}

	code := token(9)
	expiry := time.Now().Add(ttl).UnixMilli()
	s.d.Codes[code] = expiry
	if key != "" {
		s.d.Mints[key] = mint{Code: code, Expiry: expiry}
	}
	return code, s.save()
}

// Redeem consumes a code and issues a device. The code is deleted whether or not
// the save succeeds, so a failed enrolment cannot be retried with the same code.
// CleanName is what a device may be called.
//
// Names are chosen by people and read by people — in the device list, and in
// this server's log. So: bounded, single-line, and never empty. Control
// characters go because a name reaches the log, and while the log already
// quotes with %q, a name is not the place to rely on that being remembered.
//
// An empty result is not an error. A device with no name is listed by its id,
// which is worse to read and better than refusing an enrolment over a label.
func CleanName(name string) string {
	const max = 60
	out := make([]rune, 0, max)
	for _, r := range strings.TrimSpace(name) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
		if len(out) == max {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

// Rename changes what a device is called and nothing else. Its key, its id and
// what it may do are untouched — this is a label, so that "linux" can become
// "the one in the loft" before somebody has to decide which to revoke.
func (s *Store) Rename(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dev, ok := s.d.Devices[id]
	if !ok {
		return ErrNoDevice
	}
	dev.Name = CleanName(name)
	s.d.Devices[id] = dev
	return s.save()
}

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
		Name:    CleanName(name),
		Key:     base64.StdEncoding.EncodeToString(randomBytes(32)),
		Created: time.Now().UnixMilli(),
	}
	s.d.Devices[dev.ID] = dev
	return dev, s.save()
}
