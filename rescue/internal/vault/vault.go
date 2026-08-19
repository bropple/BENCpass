// Package vault opens a BENCpass vault from a file, outside the browser.
//
// This is a second implementation of a format whose first implementation is
// src/core/crypto.js and src/core/vault.js, and it exists for the day the
// first one cannot be reached: a profile that will not load, an extension that
// will not install, a machine that is gone. It is therefore held to the format
// rather than to the other implementation's habits — the tests read fixtures
// the real JavaScript sealed, and the plaintext it says is inside them.
//
// Read-only, always. Nothing here opens a file for writing, and the rescue
// tool's exports are written elsewhere, to a path the user names. A tool people
// reach for while frightened must not be able to damage the last copy.
//
// What it cannot do: biometric unlock. That secret lives in an authenticator
// and is released to a WebAuthn caller behind a fingerprint; there is no way to
// reproduce it here, and pretending otherwise would be the wrong kind of
// convenient. The master password and the recovery code are the two ways in.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Format is the vault format this understands. A file claiming any other
// number is refused by name rather than guessed at: the fields it does not
// share are exactly the ones that would fail silently.
//
// There is exactly one, on purpose. Format 2 bound the tombstone flag into the
// record AAD; format 1 left it a cleartext claim anyone holding the file could
// flip. A tool that also opened format 1 would be a downgrade path — relabel
// an envelope and the weaker binding applies — and nothing is lost by refusing
// it: v0.11.0 wrote format 1 but was never run, so no format-1 vault exists
// outside the repository's own history.
const Format = 2

// Bounds on what a file may ask this program to do.
//
// The KDF parameters travel inside the file, which is the right design — it is
// what lets the cost be raised later without stranding an existing vault — but
// it means a hostile or corrupt file gets to choose them. Argon2 with the
// memory field set to a few terabytes is a crash, or an out-of-memory kill,
// before any password is ever wrong. A server's store.json is the realistic
// source of such a file: it is the copy that sits on a machine reachable from
// the network.
//
// These ceilings are far above anything the extension writes (128 MiB, t=3,
// p=1) and far below anything that takes the process down.
const (
	maxMemoryKiB   = 2 << 20 // 2 GiB
	maxIterations  = 32
	maxParallelism = 16
	keyLen         = 32 // AES-256
)

// A var rather than a const so that a test can lower it and prove the bound
// without writing 256 MiB to do it.
var maxFileBytes int64 = 256 << 20 // a vault of 10,000 records is a few MiB

// ErrWrongSecret is returned when the vault will not open.
//
// One error for a wrong password and for a damaged file, deliberately, because
// AES-GCM's tag cannot tell them apart and neither can anyone else. Reporting
// which it was would tell somebody holding a stolen file whether a guess was
// close, and there is nothing the honest user does differently in the two
// cases.
var ErrWrongSecret = errors.New("wrong secret, or the vault is damaged")

// ErrNoRecovery is returned when a vault has no recovery wrapping to try.
var ErrNoRecovery = errors.New("this vault has no recovery code enrolled")

type wrap struct {
	Wrapper string `json:"wrapper"`
	N       string `json:"n"`
	Ct      string `json:"ct"`
	Salt    string `json:"salt,omitempty"` // the recovery wrapping carries its own
}

type kdfParams struct {
	Name        string `json:"name"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"`
}

type meta struct {
	Format  int              `json:"format"`
	Created int64            `json:"created"`
	KDF     kdfParams        `json:"kdf"`
	Wraps   map[string]*wrap `json:"wraps"`
}

type envelope struct {
	ID      string `json:"id"`
	Rev     int    `json:"rev"`
	Deleted bool   `json:"deleted"`
	N       string `json:"n"`
	Ct      string `json:"ct"`
}

// Kind describes which of the two shapes a file turned out to be, so the tool
// can say where it thinks it is reading from.
type Kind string

const (
	KindBackup Kind = "encrypted backup"
	KindServer Kind = "server store"
)

// File is a vault at rest: the header, and the sealed records. Still locked.
type File struct {
	Path string
	Kind Kind

	meta      meta
	envelopes []envelope
}

// backup is what the extension's "save an encrypted backup" writes, and what
// it keeps in browser.storage.local.
type backupShape struct {
	Meta      *meta      `json:"meta"`
	Envelopes []envelope `json:"envelopes"`
}

// server is what the sync server keeps in its data directory. The same vault,
// keyed by id, beside devices and codes that are none of this tool's business.
type serverShape struct {
	Seq     int64               `json:"seq"`
	Meta    *meta               `json:"meta"`
	Records map[string]envelope `json:"records"`
}

// Read loads a vault from a file, working out which shape it is.
//
// The two shapes are told apart by structure rather than by filename, because
// the person using this tool is often working with a file they recovered from
// a backup and renamed, and a rescue tool that refuses a vault over its
// extension is a rescue tool that failed.
func Read(path string) (*File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		// A server's data directory is the thing a person actually has, so
		// take it and find the file inside.
		return Read(strings.TrimRight(path, "/\\") + string(os.PathSeparator) + "store.json")
	}
	// Bounded while reading rather than by asking stat first.
	//
	// The first version checked info.Size() and then called os.ReadFile, which
	// is not a bound at all: stat reports 0 for a FIFO and for /dev/zero, and
	// os.ReadFile reads to EOF regardless — verified, 4 MiB through a fifo that
	// stat called empty, and /dev/zero never reaches EOF at all. A regular file
	// could also be grown between the stat and the read. The limit belongs on
	// the read.
	//
	// Non-regular files are deliberately still accepted: reading a decrypted
	// backup straight from a pipe — `rescue -list <(gpg -d backup.json.gpg)` —
	// is a good way to use this, and refusing it to fix the bound would cost
	// more than it bought.
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	raw, err := io.ReadAll(io.LimitReader(fh, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than the %d bytes this tool will read", path, maxFileBytes)
	}

	f := &File{Path: path}

	var b backupShape
	if err := json.Unmarshal(raw, &b); err == nil && b.Meta != nil && b.Envelopes != nil {
		f.Kind, f.meta, f.envelopes = KindBackup, *b.Meta, b.Envelopes
	} else {
		var s serverShape
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s is not JSON this tool recognises: %w", path, err)
		}
		if s.Meta == nil {
			// A store that no machine has ever synced to holds records and no
			// header. Worth saying plainly: the vault key is in the header, so
			// there is nothing here that any password could open.
			if s.Records != nil {
				return nil, fmt.Errorf("%s is a server store with no vault header — "+
					"no machine has published one to it yet, and the records in it cannot be opened without one", path)
			}
			return nil, fmt.Errorf("%s has no vault header", path)
		}
		f.Kind, f.meta = KindServer, *s.Meta
		for _, e := range s.Records {
			f.envelopes = append(f.envelopes, e)
		}
		// Map iteration order is random, and a rescue tool that lists records
		// in a different order every run is one nobody can check against a
		// previous run.
		sort.Slice(f.envelopes, func(i, j int) bool { return f.envelopes[i].ID < f.envelopes[j].ID })
	}

	if f.meta.Format != Format {
		// The advice has to point the right way. A higher number means the
		// extension moved on and this binary is stale; a lower one means an
		// older BENCpass wrote the file, and its sealing — which did not
		// authenticate the tombstone flag — is refused rather than read.
		hint := "use a newer rescue tool"
		if f.meta.Format < Format {
			hint = "it was written by an older BENCpass, and its weaker sealing is refused rather than read"
		}
		return nil, fmt.Errorf("%s is vault format %d and this tool understands %d — %s",
			path, f.meta.Format, Format, hint)
	}
	if err := f.meta.KDF.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.meta.Wraps["password"] == nil {
		return nil, fmt.Errorf("%s has no password wrapping", path)
	}
	return f, nil
}

func (k kdfParams) check() error {
	if k.Name != "argon2id" {
		return fmt.Errorf("unsupported key derivation %q", k.Name)
	}
	switch {
	case k.MemoryKiB == 0 || k.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("kdf memory %d KiB is outside what this tool will attempt", k.MemoryKiB)
	case k.Iterations == 0 || k.Iterations > maxIterations:
		return fmt.Errorf("kdf iterations %d is outside what this tool will attempt", k.Iterations)
	case k.Parallelism == 0 || k.Parallelism > maxParallelism:
		return fmt.Errorf("kdf parallelism %d is outside what this tool will attempt", k.Parallelism)
	}
	if _, err := b64(k.Salt); err != nil {
		return errors.New("kdf salt is not valid base64")
	}
	return nil
}

// Created is when the vault was made, in unix milliseconds.
func (f *File) Created() int64 { return f.meta.Created }

// Count is how many sealed records the file holds, tombstones included. It is
// available before unlocking, because it is the one thing worth telling
// somebody who is not sure they have the right file.
func (f *File) Count() int { return len(f.envelopes) }

// HasRecovery reports whether a recovery code was ever enrolled on this vault.
func (f *File) HasRecovery() bool { return f.meta.Wraps["recovery"] != nil }

// HasBiometric reports whether a fingerprint was enrolled. Nothing here can
// use it; it is reported so the tool can say why not.
func (f *File) HasBiometric() bool { return f.meta.Wraps["biometric"] != nil }

// KDFDescription is the work factor, for anyone wondering why unlocking takes
// a moment.
func (f *File) KDFDescription() string {
	return fmt.Sprintf("argon2id, %d MiB, t=%d, p=%d",
		f.meta.KDF.MemoryKiB/1024, f.meta.KDF.Iterations, f.meta.KDF.Parallelism)
}

// UnlockWithPassword opens the vault with the master password.
func (f *File) UnlockWithPassword(password string) (*Vault, error) {
	w := f.meta.Wraps["password"]
	salt, err := b64(f.meta.KDF.Salt)
	if err != nil {
		return nil, err
	}
	return f.unlock(w, f.derive(password, salt))
}

// UnlockWithRecoveryCode opens the vault with the printed recovery code.
//
// The code is normalised first — case, spacing and dashes are presentation,
// and somebody reading thirty characters off paper should not be locked out by
// a line break. See NormaliseCode.
func (f *File) UnlockWithRecoveryCode(code string) (*Vault, error) {
	w := f.meta.Wraps["recovery"]
	if w == nil {
		return nil, ErrNoRecovery
	}
	// Its own salt, not the password's: sharing one would mean a single Argon2
	// derivation served both, and cracking either would be cracking both.
	salt, err := b64(w.Salt)
	if err != nil {
		return nil, errors.New("the recovery wrapping's salt is not valid base64")
	}
	return f.unlock(w, f.derive(NormaliseCode(code), salt))
}

func (f *File) derive(secret string, salt []byte) []byte {
	k := f.meta.KDF
	return argon2.IDKey([]byte(secret), salt, k.Iterations, k.MemoryKiB, k.Parallelism, keyLen)
}

func (f *File) unlock(w *wrap, wrapping []byte) (*Vault, error) {
	// Wiped on the way out. Go can move a slice and leave a copy behind, and
	// the garbage collector is under no obligation to help, so this is a
	// reduction in exposure rather than a guarantee — the same claim the
	// JavaScript side makes, and worth making for the same reason: the window
	// in which this value sits in a long-lived process is otherwise the whole
	// run of the program.
	defer wipe(wrapping)

	// The label is authenticated, so a blob lifted from one slot and offered in
	// another fails to open rather than opening as something it is not.
	vaultKey, err := open(wrapping, w, fmt.Sprintf("bencpass:v%d:wrap:%s", Format, w.Wrapper))
	if err != nil {
		return nil, ErrWrongSecret
	}

	v := &Vault{key: vaultKey, file: f}
	for _, e := range f.envelopes {
		body, err := open(vaultKey, &wrap{N: e.N, Ct: e.Ct}, aadRecord(e.ID, e.Rev, e.Deleted))
		if err != nil {
			// The tombstone flag is bound into the AAD, so a flipped flag is a
			// broken seal — and from one failure, indistinguishable from real
			// damage. A rescue tool must not lose a record to a one-bit lie,
			// so the only other claim this envelope could have made is tried.
			// Not a trust fallback: both attempts authenticate the full AAD,
			// and success here proves the outer flag was flipped by whoever
			// held the file. The body's own `deleted` — the sealer's word —
			// is what decides below, exactly as it always has.
			body, err = open(vaultKey, &wrap{N: e.N, Ct: e.Ct}, aadRecord(e.ID, e.Rev, !e.Deleted))
		}
		if err != nil {
			// One unreadable record does not condemn the rest. In a rescue
			// tool that is the whole difference between losing one password
			// and losing all of them, so it is counted and reported rather
			// than returned as an error.
			v.Damaged = append(v.Damaged, e.ID)
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(body, &fields); err != nil {
			v.Damaged = append(v.Damaged, e.ID)
			continue
		}
		// The `deleted` flag beside the ciphertext is whatever the last writer
		// said — the server, or anyone who has the file. The sealed body is
		// the one that cannot be invented, so that is the one that is
		// believed; the AAD binding above guarantees the two can only differ
		// if the outer flag was tampered with after sealing. Trusting the
		// outer flag would let a tombstone be flipped back into a live record,
		// or a live record be hidden from its owner by the machine holding it.
		if del, _ := fields["deleted"].(bool); del {
			v.Deleted++
			continue
		}
		v.Records = append(v.Records, Record{ID: e.ID, Rev: e.Rev, Fields: fields})
	}
	sort.SliceStable(v.Records, func(i, j int) bool {
		a, b := strings.ToLower(v.Records[i].Title()), strings.ToLower(v.Records[j].Title())
		if a != b {
			return a < b
		}
		return v.Records[i].ID < v.Records[j].ID
	})
	return v, nil
}

// Vault is an opened vault. Its records are plaintext in memory.
type Vault struct {
	Records []Record
	// Deleted is how many tombstones were skipped, and Damaged names records
	// that would not open. Both are reported rather than hidden: a rescue tool
	// that silently returns fewer records than the file contains is lying at
	// the worst possible moment.
	Deleted int
	Damaged []string

	key  []byte
	file *File
}

// Close wipes the vault key. Same caveat as wipe: a reduction, not a promise.
func (v *Vault) Close() {
	wipe(v.key)
	v.Records = nil
}

// Record is one decrypted record, kept as the map it decoded to.
//
// Verbatim on purpose. A struct with named fields would drop anything a later
// version of the extension added, and dropping a field the user needed is the
// one failure this tool is not allowed to have. Accessors cover the fields the
// interface knows how to show; export writes everything.
type Record struct {
	ID     string
	Rev    int
	Fields map[string]any
}

// Str reads a string field, or "" if it is absent or another type.
func (r Record) Str(key string) string {
	s, _ := r.Fields[key].(string)
	return s
}

func (r Record) Type() string     { return r.Str("type") }
func (r Record) Title() string    { return r.Str("title") }
func (r Record) Username() string { return r.Str("username") }
func (r Record) Password() string { return r.Str("password") }
func (r Record) Notes() string    { return r.Str("notes") }

// URLs are the sites a login applies to.
func (r Record) URLs() []string {
	raw, _ := r.Fields["urls"].([]any)
	out := make([]string, 0, len(raw))
	for _, u := range raw {
		if s, ok := u.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// IsAddress reports whether this is an address rather than a login.
func (r Record) IsAddress() bool { return r.Type() == "address" }

const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NormaliseCode reduces what was typed to what was meant.
//
// The same rule as src/core/recovery.js, and for the same reason: the code is
// read off paper, possibly years later, possibly in bad light. Case, spaces and
// dashes are presentation. Anything outside the alphabet is dropped rather than
// guessed at — the alphabet has no O, I, L, 0 or 1 precisely so that no code
// can contain one, so seeing one means some other character was misread, and
// inventing a substitution would only disguise where the mistake was.
func NormaliseCode(code string) string {
	var out strings.Builder
	for _, c := range strings.ToUpper(code) {
		if strings.ContainsRune(alphabet, c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// CodeLength is how many characters a whole recovery code has, ignoring dashes.
const CodeLength = 30

// aadRecord is the string a record was sealed under: format, id, revision, and
// the tombstone bit. It must match src/core/crypto.js character for character —
// the cross-language fixtures exist to catch it drifting.
func aadRecord(id string, rev int, deleted bool) string {
	d := 0
	if deleted {
		d = 1
	}
	return fmt.Sprintf("bencpass:v%d:rec:%s:%d:%d", Format, id, rev, d)
}

func b64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func open(key []byte, w *wrap, aad string) ([]byte, error) {
	nonce, err := b64(w.N)
	if err != nil {
		return nil, err
	}
	ct, err := b64(w.Ct)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("wrong nonce length")
	}
	return gcm.Open(nil, nonce, ct, []byte(aad))
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
