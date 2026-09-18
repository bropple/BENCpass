package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The state this exists for: devices enrolled, every one of them gone.
func bootstrapStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(dir, 5)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s, dir
}

func touch(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, BootstrapFile)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestBootstrapNotAskedMintsNothing(t *testing.T) {
	s, dir := bootstrapStore(t)
	code, err := bootstrapCode(s, dir, time.Minute)
	if err != nil {
		t.Fatalf("bootstrapCode: %v", err)
	}
	if code != "" {
		t.Fatalf("minted %q without being asked", code)
	}
}

func TestBootstrapAskedMintsAndConsumes(t *testing.T) {
	s, dir := bootstrapStore(t)
	p := touch(t, dir)

	code, err := bootstrapCode(s, dir, time.Minute)
	if err != nil {
		t.Fatalf("bootstrapCode: %v", err)
	}
	if code == "" {
		t.Fatal("asked for a code and got none")
	}

	// The sentinel is gone, so the next start is ordinary. A file that
	// survived its own use would mint on every restart from here on.
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the sentinel survived: %v", err)
	}

	second, err := bootstrapCode(s, dir, time.Minute)
	if err != nil {
		t.Fatalf("second bootstrapCode: %v", err)
	}
	if second != "" {
		t.Fatalf("a second restart minted %q unasked", second)
	}
}

// The code has to be worth something: redeemable exactly once, like any other.
func TestBootstrapCodeIsRedeemableOnce(t *testing.T) {
	s, dir := bootstrapStore(t)
	touch(t, dir)

	code, err := bootstrapCode(s, dir, time.Minute)
	if err != nil {
		t.Fatalf("bootstrapCode: %v", err)
	}

	if _, err := s.Redeem(code, "mac"); err != nil {
		t.Fatalf("the bootstrap code did not enrol anything: %v", err)
	}
	if _, err := s.Redeem(code, "another"); err == nil {
		t.Fatal("the same code enrolled a second machine")
	}
}

// Minting beside a sentinel that cannot be removed would be a standing
// invitation rather than a way back, so it does not mint at all.
func TestBootstrapRefusesWhenTheSentinelCannotBeConsumed(t *testing.T) {
	s, dir := bootstrapStore(t)

	// A directory of that name cannot be removed by os.Remove while it has
	// something in it, which is the failure without needing to be root.
	p := filepath.Join(dir, BootstrapFile)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p, "keep"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, err := bootstrapCode(s, dir, time.Minute)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if code != "" {
		t.Fatalf("minted %q it could not account for", code)
	}
}
