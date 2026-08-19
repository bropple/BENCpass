package export

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ropple.net/bencpass/rescue/internal/vault"
)

// The property worth having: what this writes, the extension reads.
//
// Both halves are the real thing — the Go exporter here, and src/core/transfer.js
// through node — so a divergence in the envelope, the field names, the CSV
// quoting or the escaping shows up as a failure rather than as a file the user
// cannot import on the day they need to.
func openFixture(t *testing.T) *vault.Vault {
	t.Helper()
	f, err := vault.Read(filepath.Join("..", "vault", "testdata", "backup.json"))
	if err != nil {
		t.Fatalf("fixtures missing — run: node internal/vault/testdata/gen.mjs (%v)", err)
	}
	v, err := f.UnlockWithPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}

func reimport(t *testing.T, path string) []map[string]any {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not on PATH; the round trip needs the extension's own importer")
	}
	out, err := exec.Command("node", filepath.Join("testdata", "reimport.mjs"), path).CombinedOutput()
	if err != nil {
		t.Fatalf("the extension refused to import what we wrote: %v\n%s", err, out)
	}
	var records []map[string]any
	if err := json.Unmarshal(out, &records); err != nil {
		t.Fatalf("could not read the importer's answer: %v\n%s", err, out)
	}
	return records
}

func TestTheExtensionCanImportOurJSON(t *testing.T) {
	v := openFixture(t)
	body, err := JSON(v.Records, time.UnixMilli(1700000000000))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "export.json")
	if err := ToFile(path, body); err != nil {
		t.Fatal(err)
	}

	got := reimport(t, path)
	if len(got) != len(v.Records) {
		t.Fatalf("imported %d records, exported %d", len(got), len(v.Records))
	}

	// Every field the user came for, not just the count.
	byTitle := map[string]map[string]any{}
	for _, r := range got {
		title, _ := r["title"].(string)
		byTitle[title] = r
	}
	for _, r := range v.Records {
		back, ok := byTitle[r.Title()]
		if !ok {
			t.Fatalf("record %q did not survive the round trip", r.Title())
		}
		if r.IsAddress() {
			continue
		}
		if got, _ := back["password"].(string); got != r.Password() {
			t.Errorf("%q password: exported %q, imported %q", r.Title(), r.Password(), got)
		}
		if got, _ := back["username"].(string); got != r.Username() {
			t.Errorf("%q username: exported %q, imported %q", r.Title(), r.Username(), got)
		}
		if got, _ := back["notes"].(string); got != r.Notes() {
			t.Errorf("%q notes: exported %q, imported %q", r.Title(), r.Notes(), got)
		}
	}
}

func TestTheExtensionCanImportOurCSV(t *testing.T) {
	v := openFixture(t)
	path := filepath.Join(t.TempDir(), "export.csv")
	if err := ToFile(path, CSV(v.Records)); err != nil {
		t.Fatal(err)
	}

	got := reimport(t, path)

	// Addresses are deliberately not in a CSV, so the count is the logins.
	logins := 0
	for _, r := range v.Records {
		if !r.IsAddress() {
			logins++
		}
	}
	if len(got) != logins {
		t.Fatalf("imported %d rows, exported %d logins", len(got), logins)
	}

	// The awkward record is the one that proves the quoting: it holds a tab, a
	// pair of double quotes, a comma, a backslash and an embedded newline.
	var found bool
	for _, r := range v.Records {
		if !strings.Contains(r.Title(), "日本") {
			continue
		}
		found = true
		for _, back := range got {
			if title, _ := back["title"].(string); title != r.Title() {
				continue
			}
			if pw, _ := back["password"].(string); pw != r.Password() {
				t.Errorf("password did not survive CSV: exported %q, imported %q", r.Password(), pw)
			}
			if notes, _ := back["notes"].(string); notes != r.Notes() {
				t.Errorf("embedded newline did not survive CSV: exported %q, imported %q", r.Notes(), notes)
			}
		}
	}
	if !found {
		t.Error("the awkward record is missing from the fixtures")
	}
}

// A second run must not quietly write over the first. This program is reached
// for in a hurry, often twice.
func TestRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.json")
	if err := ToFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	err := ToFile(path, []byte("second"))
	if err == nil {
		t.Fatal("the second write was allowed to destroy the first")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Go's encoder escapes <, > and & by default, for embedding JSON in a page.
// A password is not a web page, and rewriting one on the way out would be a
// silent corruption discovered only when the login failed.
func TestDoesNotEscapeHTMLInPasswords(t *testing.T) {
	rec := vault.Record{ID: "x", Rev: 1, Fields: map[string]any{
		"type": "login", "title": "t", "password": `a<b>c&d`,
	}}
	body, err := JSON([]vault.Record{rec}, time.UnixMilli(0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `a<b>c&d`) {
		t.Errorf("password was escaped on the way out:\n%s", body)
	}
}

// The window's save dialog creates the file before handing back a path, and
// the mode argument to OpenFile applies only on create. Every GUI export
// therefore landed at the umask's mode — 0644 on an ordinary machine — while
// the dialog promised "created readable only by you".
func TestReplacingAnExistingFileStillEndsUpPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes")
	}
	path := filepath.Join(t.TempDir(), "export.json")

	// Exactly what the toolkit does first.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteReplacing(path, []byte("every password")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("export left at %v, want 0600 — anyone on this machine can read it", perm)
	}
}

// The dialog's default filename is predictable, which is enough to plant a
// link for on a shared machine.
func TestRefusesToWriteThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege here")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-can-read-this")
	link := filepath.Join(dir, "bencpass-export.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot symlink here: %v", err)
	}

	err := WriteReplacing(link, []byte("every password"))
	if err == nil {
		t.Fatal("wrote every password through a symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("unhelpful message: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the link's target was created anyway")
	}
}
