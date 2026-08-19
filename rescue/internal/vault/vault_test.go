package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The fixtures were sealed by the real JavaScript core, and expected.json is
// what that core says is inside them. Everything here compares against that
// rather than against constants typed on this side, because two
// implementations agreeing with each other is the only property worth testing
// and a Go-authored expectation cannot demonstrate it.
//
// Regenerate with: node internal/vault/testdata/gen.mjs

type expectation struct {
	Password  string           `json:"password"`
	Code      string           `json:"code"`
	Tombstone string           `json:"tombstone"`
	Records   []map[string]any `json:"records"`
}

func load(t *testing.T) expectation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "expected.json"))
	if err != nil {
		t.Fatalf("fixtures missing — run: node internal/vault/testdata/gen.mjs (%v)", err)
	}
	var e expectation
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Records) == 0 {
		t.Fatal("expected.json holds no records")
	}
	return e
}

// sameRecords asserts the opened vault holds exactly what the JavaScript says,
// field for field. Not a spot check on the password: a rescue tool that
// recovers a password and quietly drops the note beside it has still lost
// something the user came for.
func sameRecords(t *testing.T, got []Record, want []map[string]any) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	byID := map[string]Record{}
	for _, r := range got {
		byID[r.ID] = r
	}
	for _, w := range want {
		id, _ := w["id"].(string)
		r, ok := byID[id]
		if !ok {
			t.Fatalf("record %s (%v) is missing", id, w["title"])
		}
		// id and rev are not inside the sealed body. They live on the envelope,
		// where the AAD binds the ciphertext to them, and the JavaScript merges them
		// into the record it hands out. Here they stay as fields on Record, so they
		// are checked separately and set aside before the bodies are compared.
		if rev, ok := w["rev"].(float64); ok && int(rev) != r.Rev {
			t.Errorf("record %s rev = %d, want %d", id, r.Rev, int(rev))
		}
		body := map[string]any{}
		for k, val := range w {
			if k != "id" && k != "rev" {
				body[k] = val
			}
		}
		if !reflect.DeepEqual(r.Fields, body) {
			t.Errorf("record %s differs\n got: %#v\nwant: %#v", id, r.Fields, body)
		}
	}
}

func TestOpensAnExtensionBackupWithThePassword(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindBackup {
		t.Errorf("kind = %q, want %q", f.Kind, KindBackup)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if len(v.Damaged) != 0 {
		t.Errorf("damaged records: %v", v.Damaged)
	}
	sameRecords(t, v.Records, want.Records)
}

// The same vault, reached through the copy that lives on the server. This is
// the "my laptop is gone but the NAS is fine" path, and it has to produce
// identical plaintext from a different file shape.
func TestOpensAServerStoreWithThePassword(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindServer {
		t.Errorf("kind = %q, want %q", f.Kind, KindServer)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	sameRecords(t, v.Records, want.Records)
}

// A directory is what a person actually has — the dataset the server writes
// into — so it is accepted and the file inside is found.
func TestReadsAServerDataDirectory(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err != nil {
		t.Fatalf("a data directory should be readable: %v", err)
	}
}

// The printed sheet, read back by somebody in bad light: lower case, a stray
// space, a line break where the paper ran out. All of it presentation.
func TestOpensWithTheRecoveryCodeHoweverItIsTyped(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.HasRecovery() {
		t.Fatal("the fixture should have a recovery wrapping")
	}
	messy := "  " + strings.ToLower(strings.ReplaceAll(want.Code, "-", " ")) + "\n"
	for _, code := range []string{want.Code, messy} {
		v, err := f.UnlockWithRecoveryCode(code)
		if err != nil {
			t.Fatalf("recovery code %q: %v", code, err)
		}
		sameRecords(t, v.Records, want.Records)
		v.Close()
	}
}

func TestRefusesTheWrongSecret(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.UnlockWithPassword(want.Password + "!"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong password gave %v, want ErrWrongSecret", err)
	}
	// A code of the right shape but the wrong value. Only the tag decides.
	if _, err := f.UnlockWithRecoveryCode("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong recovery code gave %v, want ErrWrongSecret", err)
	}
}

// The tombstone rule, and the reason it is not a one-line check of a boolean.
//
// `deleted` sits beside the ciphertext in the clear, so it is whatever the last
// writer said — the server, or anyone holding the file. It is bound into the
// AAD, so a flipped flag is a broken seal; a rescue tool must not lose records
// to a one-bit lie, so unlock retries the only other claim the envelope could
// have made and believes the sealed body it recovers. Both directions are
// tested by flipping the outer flag and asserting nothing moves: a tombstone
// cannot be resurrected into a live record, and a live record cannot be hidden
// from its owner by the machine storing it — and none of it lands in Damaged.
func TestBelievesTheSealedBodyRatherThanTheFlag(t *testing.T) {
	want := load(t)

	raw, err := os.ReadFile(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	envs, _ := doc["envelopes"].([]any)
	flipped := 0
	for _, e := range envs {
		env, _ := e.(map[string]any)
		// Every flag inverted: the tombstone claims to be alive, the live
		// records claim to be deleted.
		del, _ := env["deleted"].(bool)
		env["deleted"] = !del
		flipped++
	}
	if flipped != len(want.Records)+1 {
		t.Fatalf("flipped %d flags, expected %d", flipped, len(want.Records)+1)
	}

	path := filepath.Join(t.TempDir(), "lying.json")
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	sameRecords(t, v.Records, want.Records)
	if v.Deleted != 1 {
		t.Errorf("skipped %d tombstones, want 1", v.Deleted)
	}
	if len(v.Damaged) != 0 {
		t.Errorf("flipped flags were reported as damage: %v", v.Damaged)
	}
	for _, r := range v.Records {
		if r.ID == want.Tombstone {
			t.Error("the deleted record came back when its cleartext flag was flipped")
		}
	}
}

// The property the flipped-flag recovery rests on: the flag is authenticated,
// so an envelope does not open under a flag its sealer never wrote. Without
// this, the retry above would be reading an unauthenticated claim rather than
// proving one — which is exactly the format-1 hole this format exists to close.
func TestAFlippedFlagBreaksTheSeal(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	for _, e := range f.envelopes {
		if _, err := open(v.key, &wrap{N: e.N, Ct: e.Ct}, aadRecord(e.ID, e.Rev, e.Deleted)); err != nil {
			t.Errorf("record %s does not open under its own flag: %v", e.ID, err)
		}
		if _, err := open(v.key, &wrap{N: e.N, Ct: e.Ct}, aadRecord(e.ID, e.Rev, !e.Deleted)); err == nil {
			t.Errorf("record %s opened under a flipped flag", e.ID)
		}
	}
}

// One corrupt record must not cost the others. In a rescue tool this is the
// difference between losing a password and losing all of them.
func TestOneDamagedRecordDoesNotCondemnTheRest(t *testing.T) {
	want := load(t)

	raw, err := os.ReadFile(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	envs, _ := doc["envelopes"].([]any)
	victim, _ := envs[0].(map[string]any)
	id, _ := victim["id"].(string)
	ct, _ := victim["ct"].(string)
	// Flip one base64 character. The tag will not verify.
	swap := map[byte]byte{'A': 'B', 'B': 'A'}
	b := []byte(ct)
	if r, ok := swap[b[0]]; ok {
		b[0] = r
	} else {
		b[0] = 'A'
	}
	victim["ct"] = string(b)

	path := filepath.Join(t.TempDir(), "damaged.json")
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatalf("a damaged record must not stop the vault opening: %v", err)
	}
	defer v.Close()

	if len(v.Damaged) != 1 || v.Damaged[0] != id {
		t.Errorf("damaged = %v, want [%s]", v.Damaged, id)
	}
	// Whatever the victim was, everything else is still readable and intact.
	for _, r := range v.Records {
		if r.ID == id {
			t.Error("the damaged record was listed as if it opened")
		}
	}
	if len(v.Records) == 0 {
		t.Error("no records survived")
	}
}

// The KDF parameters travel inside the file, which is what lets the cost be
// raised later. It also means a hostile file chooses them, and Argon2 asked for
// a few terabytes is an out-of-memory kill before any password is wrong.
func TestRefusesAbsurdKDFParameters(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"memory", "memoryKiB", 64 << 20}, // 64 GiB
		{"iterations", "iterations", 100000},
		{"parallelism", "parallelism", 255},
		{"algorithm", "name", "scrypt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			meta, _ := doc["meta"].(map[string]any)
			kdf, _ := meta["kdf"].(map[string]any)
			kdf[tc.field] = tc.value

			path := filepath.Join(t.TempDir(), "hostile.json")
			out, _ := json.Marshal(doc)
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); err == nil {
				t.Fatalf("%s = %v was accepted", tc.field, tc.value)
			}
		})
	}
}

func TestRefusesAnUnknownFormat(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	meta, _ := doc["meta"].(map[string]any)
	meta["format"] = Format + 1

	path := filepath.Join(t.TempDir(), "future.json")
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Read(path)
	if err == nil {
		t.Fatal("a future format was accepted")
	}
	// The message has to tell the user what to do, not just that it failed.
	if !strings.Contains(err.Error(), "newer rescue tool") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Format 1 left the tombstone flag outside the AAD. A tool that still opened
// it would be a downgrade path — relabel a file as format 1 and the flippable
// flag is back — and nothing is stranded by refusing: v0.11.0 wrote format 1
// but was never run. The refusal must say which direction the mismatch is,
// because "use a newer rescue tool" is exactly the wrong advice here.
func TestRefusesTheRetiredFormat(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	meta, _ := doc["meta"].(map[string]any)
	meta["format"] = 1

	path := filepath.Join(t.TempDir(), "retired.json")
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Read(path)
	if err == nil {
		t.Fatal("the retired format was accepted")
	}
	if !strings.Contains(err.Error(), "older BENCpass") {
		t.Errorf("unhelpful message: %v", err)
	}
	if strings.Contains(err.Error(), "newer rescue tool") {
		t.Errorf("the message points the wrong way: %v", err)
	}
}

// A store nobody has synced to holds records and no header, and the header is
// where the wrapped vault key lives. No password opens that, and saying so is
// kinder than a wrong-password error the user will retype five times.
func TestSaysWhyAHeaderlessStoreCannotBeOpened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-store.json")
	body := `{"seq":0,"records":{"a":{"id":"a","rev":1,"n":"","ct":""}},"devices":{}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path)
	if err == nil {
		t.Fatal("a store with no vault header was accepted")
	}
	if !strings.Contains(err.Error(), "no vault header") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Unicode and the characters a CSV writer has to think about, byte for byte
// through Argon2, GCM, base64 and two JSON implementations.
func TestAwkwardCharactersSurviveIntact(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.UnlockWithPassword(want.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	var found bool
	for _, r := range v.Records {
		if strings.Contains(r.Title(), "日本") {
			found = true
			if !strings.Contains(r.Password(), "\t") || !strings.Contains(r.Password(), `"quote"`) {
				t.Errorf("password mangled: %q", r.Password())
			}
			if !strings.Contains(r.Notes(), "\n") {
				t.Errorf("newline in notes lost: %q", r.Notes())
			}
			if len(r.URLs()) != 2 {
				t.Errorf("urls = %v, want 2", r.URLs())
			}
		}
	}
	if !found {
		t.Error("the unicode record is missing from the fixtures")
	}
}

func TestListsInAStableOrder(t *testing.T) {
	want := load(t)
	f, err := Read(filepath.Join("testdata", "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	var first []string
	for i := 0; i < 3; i++ {
		v, err := f.UnlockWithPassword(want.Password)
		if err != nil {
			t.Fatal(err)
		}
		var order []string
		for _, r := range v.Records {
			order = append(order, r.ID)
		}
		if i == 0 {
			first = order
		} else if !reflect.DeepEqual(order, first) {
			t.Fatalf("order changed between runs: %v then %v", first, order)
		}
		v.Close()
	}
}

// Biometric unlock cannot work here and the tool should be able to say so
// rather than leaving the user wondering which secret it wants.
func TestReportsWhatTheVaultHas(t *testing.T) {
	f, err := Read(filepath.Join("testdata", "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.HasRecovery() {
		t.Error("recovery wrapping not reported")
	}
	if f.HasBiometric() {
		t.Error("the fixture has no biometric wrapping")
	}
	if f.Count() != len(load(t).Records)+1 {
		t.Errorf("count = %d, want %d including the tombstone", f.Count(), len(load(t).Records)+1)
	}
	if !strings.Contains(f.KDFDescription(), "128 MiB") {
		t.Errorf("kdf description = %q", f.KDFDescription())
	}
}

// The read bound has to be a bound on the read.
//
// It used to be a check of os.Stat's size followed by os.ReadFile, which is no
// bound at all: stat reports 0 bytes for a fifo and for /dev/zero, and
// os.ReadFile reads to EOF whatever stat said. A store.json on a NAS is a file
// an attacker may be able to replace with either.
func TestRefusesToReadPastTheLimit(t *testing.T) {
	was := maxFileBytes
	maxFileBytes = 4096 // so the test does not have to write 256 MiB
	t.Cleanup(func() { maxFileBytes = was })

	path := filepath.Join(t.TempDir(), "huge.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), int(maxFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path)
	if err == nil {
		t.Fatal("a file over the limit was read")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// The case the stat-then-read version could not see at all: something that
// reports no size and then hands over as much as it likes.
func TestRefusesAFileThatLiesAboutItsSize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no fifos")
	}
	was := maxFileBytes
	maxFileBytes = 4096
	t.Cleanup(func() { maxFileBytes = was })

	path := filepath.Join(t.TempDir(), "store.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot make a fifo here: %v", err)
	}

	// A writer that would go on for ever if anything let it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer w.Close()
		chunk := bytes.Repeat([]byte("A"), 4096)
		for i := 0; i < 4096; i++ {
			if _, err := w.Write(chunk); err != nil {
				return // the reader stopped, which is the point
			}
		}
	}()

	if fi, err := os.Stat(path); err == nil && fi.Size() != 0 {
		t.Fatalf("this test assumes a fifo stats as 0 bytes, got %d", fi.Size())
	}

	_, err := Read(path)
	if err == nil {
		t.Fatal("a fifo claiming to be empty was read without limit")
	}
	// The message has to be the bound refusing it, not a parse error further
	// on. Asserting only that "an error happened" passed against the very
	// stat-then-ReadFile version this test exists to reject: it read sixteen
	// megabytes of As and then failed on the JSON, which is an error and is
	// not the guarantee.
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("the fifo was read past the limit and failed later instead: %v", err)
	}
	<-done
}
