// Package devices lists and removes enrolled devices in a sync server's
// store.json, with the server stopped.
//
// This is the one thing in the rescue tool that writes to the file it was
// given, and it exists for one day: every machine is lost or wiped, so nothing
// can mint an enrolment code — minting needs an enrolled device to sign the
// request, and the server prints a bootstrap code only while NO device is
// enrolled. The dead machines hold the door shut, and until this existed the
// answer was hand-editing JSON on the NAS.
//
// The vault package's read-only guarantee is untouched: nothing in
// internal/vault opens a file for writing, and nothing here parses a record.
// Every top-level field except `devices` — the header, the sealed records, the
// sequence, the codes, and anything a future server adds — is carried as raw
// bytes this package cannot alter, so even a bug here cannot rewrite an
// envelope it never decoded. Within `devices`, each entry it keeps is likewise
// raw: its signing key and any field a later server put beside it pass through
// verbatim. The first draft decoded devices into a struct, and would have
// silently dropped every kept device's key on the way back out — the exact
// kind of damage a rescue tool is not allowed to do.
//
// The other half of the guarantee is procedural and lives in Save: a backup
// copy of the whole file is written first, refusing to overwrite, and nothing
// proceeds if it cannot be; the replacement then goes through a temporary file
// and a rename, so an interruption leaves the original in place.
package devices

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Device is a device as this tool needs to see it: enough to name one to a
// person. The signing key is deliberately not here — listing devices must
// never be a way to read keys, and removal does not need them.
type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
}

// Store is a server store held mostly as bytes: only the device map is
// decoded, and only one level deep.
type Store struct {
	Path string

	raw  []byte                     // the file exactly as read, for the backup
	top  map[string]json.RawMessage // every top-level field, verbatim
	devs map[string]json.RawMessage // devices by id, each verbatim
}

// Load reads a server store, or the data directory holding one.
//
// An encrypted backup is refused by name: it has no devices — enrolment is the
// server's affair — and someone pointing this at the wrong file should be told
// which file the right one is, not shown an empty list that reads as "already
// done".
func Load(path string) (*Store, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return Load(strings.TrimRight(path, "/\\") + string(os.PathSeparator) + "store.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("%s is not JSON this tool recognises: %w", path, err)
	}
	if _, isBackup := top["envelopes"]; isBackup {
		return nil, fmt.Errorf("%s is an encrypted backup, which has no devices — "+
			"this works on a sync server's store.json", path)
	}
	devRaw, ok := top["devices"]
	if !ok {
		return nil, fmt.Errorf("%s has no devices field — it is not a server store", path)
	}

	var devs map[string]json.RawMessage
	if err := json.Unmarshal(devRaw, &devs); err != nil {
		return nil, fmt.Errorf("%s: the devices field is not the shape a server writes: %w", path, err)
	}
	if devs == nil {
		devs = map[string]json.RawMessage{}
	}
	return &Store{Path: path, raw: raw, top: top, devs: devs}, nil
}

// List is the enrolled devices, oldest first — the order the server's own
// listing uses, so the two can be compared by eye.
func (s *Store) List() ([]Device, error) {
	out := make([]Device, 0, len(s.devs))
	for id, raw := range s.devs {
		var d Device
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("device %s would not decode: %w", id, err)
		}
		if d.ID == "" {
			d.ID = id
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created < out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Forget removes one device, by its exact id. Exact on purpose: -show matches
// titles loosely because reading is safe to fumble; removal is not, and the id
// is on the listing this tool just printed.
//
// The last device CAN be removed here, unlike over the server's API
// (ErrLastDevice) — offline, an empty device list is not lockout but the whole
// point: the server prints a fresh bootstrap enrolment code at startup only
// while nothing is enrolled.
func (s *Store) Forget(id string) (Device, error) {
	raw, ok := s.devs[id]
	if !ok {
		return Device{}, fmt.Errorf("no device has the id %q — -devices lists them", id)
	}
	var d Device
	if err := json.Unmarshal(raw, &d); err != nil {
		return Device{}, fmt.Errorf("device %s would not decode: %w", id, err)
	}
	if d.ID == "" {
		d.ID = id
	}
	delete(s.devs, id)
	return d, nil
}

// Save writes the store back, having first written a backup copy of the
// original beside it. It returns the backup's path.
//
// The backup is not optional and not best-effort: this file is the last copy
// of the vault, and the documented manual procedure began with `cp` for the
// same reason. If the backup cannot be written, nothing else happens.
func (s *Store) Save() (string, error) {
	fi, err := os.Stat(s.Path)
	if err != nil {
		return "", err
	}

	// Timestamped, refusing to overwrite, and numbered past the first within
	// the same second — removing several dead devices back-to-back is exactly
	// what the lost-every-machine day looks like, and the first version told
	// the person to wait between them.
	stamp := time.Now().Format("20060102-150405")
	var bf *os.File
	var backup string
	for n := 1; ; n++ {
		backup = fmt.Sprintf("%s.bak-%s", s.Path, stamp)
		if n > 1 {
			backup = fmt.Sprintf("%s.bak-%s.%d", s.Path, stamp, n)
		}
		bf, err = os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
		if err == nil {
			break
		}
		if os.IsExist(err) && n < 100 {
			continue
		}
		return "", fmt.Errorf("cannot write the backup, so nothing was changed: %w", err)
	}
	if _, err := bf.Write(s.raw); err == nil {
		err = bf.Sync()
	}
	if err != nil {
		bf.Close()
		os.Remove(backup)
		return "", fmt.Errorf("cannot write the backup, so nothing was changed: %w", err)
	}
	if err := bf.Close(); err != nil {
		return "", fmt.Errorf("cannot write the backup, so nothing was changed: %w", err)
	}

	devRaw, err := json.Marshal(s.devs)
	if err != nil {
		return backup, err
	}
	s.top["devices"] = devRaw
	out, err := json.Marshal(s.top)
	if err != nil {
		return backup, err
	}

	// Through a temporary file and a rename, exactly as the server's own save
	// does: an interruption leaves the previous store intact rather than a
	// truncated one. The mode and — where this process is allowed — the owner
	// are the original's: on TrueNAS the container runs as 568 and this tool
	// usually runs as root, and a root-owned replacement would stop the server
	// from opening its own store on the next start.
	tmp := s.Path + ".rescue-tmp"
	if err := os.WriteFile(tmp, out, fi.Mode().Perm()); err != nil {
		return backup, err
	}
	if err := os.Chmod(tmp, fi.Mode().Perm()); err != nil {
		os.Remove(tmp)
		return backup, err
	}
	preserveOwner(tmp, fi)
	if err := os.Rename(tmp, s.Path); err != nil {
		os.Remove(tmp)
		return backup, err
	}
	if dir, err := os.Open(dirOf(s.Path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return backup, nil
}

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[:i+1]
	}
	return "."
}
