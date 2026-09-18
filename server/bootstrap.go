package main

// Getting back in when there is nobody left to let you in.
//
// A code is normally minted by an enrolled machine over a signed request, and
// the server prints one itself only while nothing is enrolled at all. Between
// those two lies the case this file is for: devices are enrolled, and every one
// of them is gone. Nothing can sign a request for a new code, and the startup
// path stays quiet because the count is not zero — so the vault is sitting
// right there, readable by nobody.
//
// It happened. A machine was reinstalled rather than upgraded, which dropped
// the extension's storage and with it the only device key, and the way through
// was to stop the server and delete the `devices` map out of store.json with a
// Python one-liner typed at a NAS. That is a poor thing to ask of somebody on
// the day they have lost their passwords, and it is a hand-edit of the single
// file that holds the whole vault.
//
// So: touch a file in the data directory, restart, and read the log.
//
// The authorisation is the same one the startup path already relies on and
// says so in main.go — writing to the data directory means having reached the
// machine and the filesystem holding the store, which is strictly more access
// than this grants. Anyone who can create this file can already read, edit or
// delete store.json directly.
//
// The file is consumed, not just read: leaving it in place would mint a fresh
// code on every restart, which is a standing invitation rather than a way back.

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BootstrapFile is the sentinel, in the data directory beside store.json.
const BootstrapFile = "bootstrap-code"

// bootstrapCode mints and returns a code if one was asked for, and removes the
// request so the next restart is ordinary. An empty string means nothing was
// asked.
//
// The removal happens BEFORE the code is returned to be printed. A sentinel
// that survives its own use because minting failed halfway, or because the
// process died between the two, is the standing invitation this exists to
// avoid — so the file goes first and the code is only minted once it is gone.
func bootstrapCode(store *Store, dir string, ttl time.Duration) (string, error) {
	path := filepath.Join(dir, BootstrapFile)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	if err := os.Remove(path); err != nil {
		// Refusing to mint is the safe half of this. A code minted beside a
		// sentinel that could not be removed would be minted again on every
		// restart from here on, and nobody would be told.
		return "", fmt.Errorf("cannot consume %s, so no code was minted: %w", path, err)
	}

	code, err := store.NewCode(ttl)
	if err != nil {
		return "", fmt.Errorf("cannot mint bootstrap code: %w", err)
	}
	return code, nil
}
