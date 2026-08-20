package devices

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A store the way the server writes one — compact JSON — plus fields no
// current server writes, because the whole claim under test is that this
// package carries what it does not understand verbatim rather than dropping
// it. The mints key contains an escaped NUL, exactly as the server's
// device\x00nonce keys marshal.
const fixture = `{"seq":7,` +
	`"meta":{"format":2,"created":1700000000000,"kdf":{"name":"argon2id"},"wraps":{"password":{"n":"AA=="}}},` +
	`"records":{"r1":{"id":"r1","rev":3,"deleted":false,"n":"bm9uY2U=","ct":"Y3Q=","seq":5}},` +
	`"devices":{` +
	`"dev-old":{"id":"dev-old","name":"mac","key":"a2V5LW9sZA==","created":1700000000000,"futureDeviceField":true},` +
	`"dev-new":{"id":"dev-new","name":"linux","key":"a2V5LW5ldw==","created":1700000000001}},` +
	`"codes":{"ABCDEF":1700009999999},` +
	`"mints":{"dev-old\u0000nonce1":{"code":"XYZ","expiry":1700009999999}},` +
	`"futureField":{"anything":["at","all"]}}`

func write(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestListIsOldestFirst(t *testing.T) {
	s, err := Load(write(t, "store.json", fixture))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{ID: "dev-old", Name: "mac", Created: 1700000000000},
		{ID: "dev-new", Name: "linux", Created: 1700000000001},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTheDataDirectoryIsAccepted(t *testing.T) {
	p := write(t, "store.json", fixture)
	s, err := Load(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != p {
		t.Fatalf("resolved to %s, want %s", s.Path, p)
	}
}

func TestAnEncryptedBackupIsRefusedByName(t *testing.T) {
	p := write(t, "backup.json", `{"meta":{"format":2},"envelopes":[]}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "encrypted backup") {
		t.Fatalf("want a refusal naming the backup shape, got %v", err)
	}
}

func TestSomethingElseEntirelyIsRefused(t *testing.T) {
	p := write(t, "store.json", `{"seq":1,"records":{}}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "devices") {
		t.Fatalf("want a refusal naming the missing devices field, got %v", err)
	}
}

func TestForgetNeedsTheExactID(t *testing.T) {
	s, err := Load(write(t, "store.json", fixture))
	if err != nil {
		t.Fatal(err)
	}
	// A prefix, a name, and a case slip: all things -show would match, none of
	// them good enough to delete by.
	for _, id := range []string{"dev", "mac", "DEV-OLD"} {
		if _, err := s.Forget(id); err == nil {
			t.Errorf("Forget(%q) succeeded; removal must take the exact id", id)
		}
	}
	if _, err := s.Forget("dev-old"); err != nil {
		t.Fatalf("the exact id was refused: %v", err)
	}
}

// The heart of it: removing one device must change nothing else. Every other
// field — the vault header, the sealed records, the sequence, the codes, the
// fields this package has never heard of, and the KEPT device's signing key —
// comes back byte-for-byte. A rewrite that dropped the kept device's key would
// lock out the one machine still working.
func TestForgetRewritesOnlyTheDeviceItNames(t *testing.T) {
	p := write(t, "store.json", fixture)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget("dev-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}

	var before, after map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &before); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"seq", "meta", "records", "codes", "mints", "futureField"} {
		if string(before[k]) != string(after[k]) {
			t.Errorf("%s changed:\n before %s\n after  %s", k, before[k], after[k])
		}
	}

	var devs map[string]json.RawMessage
	if err := json.Unmarshal(after["devices"], &devs); err != nil {
		t.Fatal(err)
	}
	if _, gone := devs["dev-old"]; gone {
		t.Error("dev-old is still enrolled")
	}
	var beforeDevs map[string]json.RawMessage
	if err := json.Unmarshal(before["devices"], &beforeDevs); err != nil {
		t.Fatal(err)
	}
	if string(devs["dev-new"]) != string(beforeDevs["dev-new"]) {
		t.Errorf("the kept device was rewritten:\n before %s\n after  %s",
			beforeDevs["dev-new"], devs["dev-new"])
	}
}

func TestTheBackupIsTheOriginalAndComesFirst(t *testing.T) {
	p := write(t, "store.json", fixture)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget("dev-old"); err != nil {
		t.Fatal(err)
	}
	backup, err := s.Save()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("no backup at %s: %v", backup, err)
	}
	if string(raw) != fixture {
		t.Error("the backup is not byte-identical to the original")
	}
}

func TestNothingIsWrittenWhenTheBackupCannot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere; the read-only directory proves nothing")
	}
	p := write(t, "store.json", fixture)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget("dev-old"); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	if _, err := s.Save(); err == nil {
		t.Fatal("Save succeeded with nowhere to put the backup")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != fixture {
		t.Error("the store was modified even though the backup failed")
	}
}

// Offline, removing the last device is not lockout but the goal: the server
// prints a bootstrap enrolment code at startup only while nothing is enrolled.
// The API's ErrLastDevice guards a running server, where an empty device list
// would be unreachable; here the person holds the file, and the door it opens
// is their own.
func TestTheLastDeviceCanBeForgotten(t *testing.T) {
	p := write(t, "store.json",
		`{"seq":1,"meta":{"format":2},"records":{},`+
			`"devices":{"only":{"id":"only","name":"mac","key":"aw==","created":1}},"codes":{}}`)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget("only"); err != nil {
		t.Fatalf("the last device must be removable offline: %v", err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Devices map[string]json.RawMessage `json:"devices"`
	}
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Devices) != 0 {
		t.Fatalf("want an empty device list, got %d", len(after.Devices))
	}
}

func TestTheModeIsPreserved(t *testing.T) {
	p := write(t, "store.json", fixture)
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget("dev-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode is %o, want 640", fi.Mode().Perm())
	}
}
