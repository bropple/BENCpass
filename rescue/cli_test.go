package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ropple.net/bencpass/rescue/internal/vault"
)

// Fields are built the way encoding/json builds them — map[string]any, []any,
// float64 — because that is exactly what a decrypted record body decodes to,
// and an accessor tested against friendlier types would prove nothing about
// the real path.
func loginWithHistory() vault.Record {
	return vault.Record{
		ID: "11111111-1111-4111-8111-111111111111",
		Fields: map[string]any{
			"type":     "login",
			"title":    "Example",
			"username": "ben",
			"password": "hunter3",
			"history": []any{
				map[string]any{"password": "hunter2", "changed": float64(1700000000000)},
				map[string]any{"password": "hunter1", "changed": float64(0)},
				// A row with no password is nothing this tool can hand back;
				// the extension's importer drops these too.
				map[string]any{"changed": float64(1600000000000)},
				// Not even an object. A damaged export should not panic the
				// rescue tool, of all things.
				"rubbish",
			},
			"urls": []any{"https://example.com"},
		},
	}
}

func TestShowPrintsPasswordHistory(t *testing.T) {
	var b strings.Builder
	printRecord(&b, loginWithHistory())
	out := b.String()

	// The current password first, then the previous ones with their dates —
	// 1700000000000 ms is 2023-11-14 UTC.
	for _, want := range []string{
		"password   hunter3",
		"previous   hunter2  (set 2023-11-1",
		"previous   hunter1  (undated)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "previous") != 2 {
		t.Errorf("want exactly 2 history lines (the empty and rubbish rows dropped), got:\n%s", out)
	}
	if i, j := strings.Index(out, "hunter2"), strings.Index(out, "hunter1"); i > j {
		t.Errorf("history printed out of order — newest first is the order the vault keeps:\n%s", out)
	}
}

func TestShowWithoutHistoryPrintsNoPreviousLine(t *testing.T) {
	r := loginWithHistory()
	delete(r.Fields, "history")

	var b strings.Builder
	printRecord(&b, r)
	if strings.Contains(b.String(), "previous") {
		t.Errorf("a login with no history should not claim to have one:\n%s", b.String())
	}
}

// ---- the devices subcommand -------------------------------------------------

const storeFixture = `{"seq":3,"meta":{"format":2},` +
	`"records":{"r1":{"id":"r1","rev":1,"deleted":false,"n":"bg==","ct":"Y3Q=","seq":1}},` +
	`"devices":{` +
	`"dev-a":{"id":"dev-a","name":"mac","key":"a2E=","created":1700000000000},` +
	`"dev-b":{"id":"dev-b","name":"linux","key":"a2I=","created":1700000000001}},` +
	`"codes":{}}`

func writeStore(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(p, []byte(storeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDevicesListsWithoutWriting(t *testing.T) {
	p := writeStore(t)
	var out strings.Builder
	if err := runDevices(p, "", strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 device(s)", "mac", "dev-a", "linux", "dev-b"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("listing is missing %q:\n%s", want, out.String())
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != storeFixture {
		t.Error("listing devices modified the store")
	}
}

func TestForgetWithoutTheMagicWordWritesNothing(t *testing.T) {
	p := writeStore(t)
	var out strings.Builder
	// "yes" is a plausible thing to type at a prompt that demands "forget";
	// it must not count.
	err := runDevices(p, "dev-a", strings.NewReader("yes\n"), &out)
	if err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a refusal saying nothing was written, got %v", err)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != storeFixture {
		t.Error("the store was modified despite the refusal")
	}
	if entries, _ := filepath.Glob(p + ".bak-*"); len(entries) != 0 {
		t.Error("a backup was written for a refused removal")
	}
}

func TestForgetRemovesTheDeviceAndSaysWhatIsNext(t *testing.T) {
	p := writeStore(t)
	var out strings.Builder
	if err := runDevices(p, "dev-a", strings.NewReader("forget\n"), &out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "dev-a") {
		t.Error("dev-a is still in the store")
	}
	if !strings.Contains(string(raw), "dev-b") {
		t.Error("dev-b went with it")
	}
	if !strings.Contains(out.String(), "1 device(s) remain") {
		t.Errorf("the outcome was not stated:\n%s", out.String())
	}
	if entries, _ := filepath.Glob(p + ".bak-*"); len(entries) != 1 {
		t.Errorf("want exactly one backup, got %v", entries)
	}
}

func TestForgettingTheLastDeviceSaysABootstrapCodeComes(t *testing.T) {
	p := writeStore(t)
	var out strings.Builder
	if err := runDevices(p, "dev-a", strings.NewReader("forget\n"), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runDevices(p, "dev-b", strings.NewReader("forget\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "bootstrap") {
		t.Errorf("removing the last device must say what happens at the next server start:\n%s", out.String())
	}
}
