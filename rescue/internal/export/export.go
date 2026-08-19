// Package export writes an opened vault back out as plaintext.
//
// The formats are the extension's own, from src/core/transfer.js, so anything
// this writes can be imported again — into a rebuilt BENCpass, or into whatever
// the user is moving to. A rescue tool whose output only it can read has not
// finished the job.
//
// Everything here produces plaintext. That is the point of it, and it is also
// the most dangerous thing this program does, so the caller writes the file
// with a restrictive mode and the interface says plainly what is in it.
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"ropple.net/bencpass/rescue/internal/vault"
)

// The envelope of a JSON export, matching EXPORT_FORMAT and EXPORT_VERSION in
// src/core/transfer.js. The importer is strict about these two and forgiving
// about the rest, so they have to be exact.
const (
	Format  = "bencpass-export"
	Version = 1

	// Stated inside the file as well as in the interface, because this will be
	// found later in a downloads folder by someone who has forgotten what it is.
	Warning = "This file contains your passwords in plain text. Anyone who can read it can read them."
)

type document struct {
	Format     string           `json:"format"`
	Version    int              `json:"version"`
	ExportedAt string           `json:"exportedAt"`
	Warning    string           `json:"warning"`
	Records    []map[string]any `json:"records"`
}

// JSON is the whole vault: both record types, every field, no loss.
//
// This is the format to keep. The CSV below is for handing to another program
// and silently drops everything a spreadsheet has no column for.
func JSON(records []vault.Record, now time.Time) ([]byte, error) {
	doc := document{
		Format:     Format,
		Version:    Version,
		ExportedAt: now.UTC().Format("2006-01-02T15:04:05.000Z"),
		Warning:    Warning,
		Records:    make([]map[string]any, 0, len(records)),
	}
	for _, r := range records {
		// id and rev live on the envelope rather than in the sealed body, and
		// the extension's export carries them, so they go back in here.
		out := map[string]any{"id": r.ID, "rev": r.Rev}
		for k, v := range r.Fields {
			// history is bookkeeping that means nothing outside the vault it
			// came from — dropped by the extension's export for the same reason.
			if k != "history" {
				out[k] = v
			}
		}
		doc.Records = append(doc.Records, out)
	}
	// Indented to match, and unescaped so that a password containing < or & is
	// not silently rewritten into < on its way out. Go's default HTML
	// escaping is for embedding JSON in a page, which this is not.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var csvColumns = []string{"name", "url", "username", "password", "note"}

// CSV is the logins, in the shape the other managers read.
//
// Addresses are deliberately absent, exactly as in the extension: they do not
// fit five columns without inventing a layout nothing else reads, and a file
// that claims to hold the vault while quietly holding half of it is worse than
// one that says what it is.
func CSV(records []vault.Record) []byte {
	var b strings.Builder
	b.WriteString(strings.Join(csvColumns, ","))
	b.WriteString("\r\n")
	for _, r := range records {
		if r.IsAddress() {
			continue
		}
		url := ""
		if u := r.URLs(); len(u) > 0 {
			url = u[0]
		}
		row := []string{r.Title(), url, r.Username(), r.Password(), r.Notes()}
		for i, cell := range row {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(csvCell(cell))
		}
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// Quote when the value could otherwise change the shape of the row, and double
// any quote inside it. RFC 4180.
var needsQuoting = regexp.MustCompile(`["\,\r\n]`)

func csvCell(s string) string {
	if needsQuoting.MatchString(s) {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// WriteReplacing writes an export to a path the user has already agreed to
// replace — the window's save dialog asks, so refusing here would be asking
// twice and answering differently.
//
// It exists because the obvious version was wrong in a way nothing showed. The
// toolkit's save dialog creates the file itself, before handing back a path,
// so by the time this runs the file exists — and the mode argument to
// OpenFile applies only when a file is *created*. Every export written from
// the window landed 0644 while a dialog three lines earlier promised it was
// "created readable only by you". The chmod is not belt and braces; it is the
// only thing setting the mode at all.
//
// The symlink check is the other half. O_EXCL gives the command line a free
// refusal of a planted link; a path the dialog has already agreed to replace
// has no such protection, and the dialog's default filename is predictable
// enough to plant one for.
func WriteReplacing(path string, content []byte) error {
	// Two checks for one property, and the order matters. The Lstat is for the
	// error message; O_NOFOLLOW is the actual refusal, because a check and an
	// open are two calls and anything between them is a race an attacker with
	// write access to the directory can win.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link — writing every password through it "+
			"would put them somewhere you did not choose", path)
	}

	f, err := openForReplacing(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Before the plaintext goes in, not after.
	if err := f.Chmod(0o600); err != nil {
		// Windows has no unix modes to set and says so; the write is still
		// worth doing there.
		if runtime.GOOS != "windows" {
			return fmt.Errorf("could not make %s readable only by you: %w", path, err)
		}
	}
	if _, err := f.Write(content); err != nil {
		return err
	}
	// On disk before the program says it is. This file is written by somebody
	// whose machine is already misbehaving, and a rescue export lost to a power
	// cut moments later is the whole exercise wasted.
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// openForReplacing is the half of WriteReplacing that the kernel enforces.
//
// Separate so that a test can reach it without the Lstat in front of it: with
// both, a test cannot tell which one refused the symlink, and the racy version
// this replaced would pass just as well.
func openForReplacing(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%s could not be opened for writing "+
			"(a symbolic link is refused here): %w", path, err)
	}
	return f, nil
}

// ToFile writes an export, refusing to overwrite anything.
//
// O_EXCL rather than a prompt: this program is reached for in a hurry, often
// more than once, and the second run naming the file the first one wrote is a
// realistic way to destroy the thing just recovered. Choosing another name
// costs a moment; the alternative costs the vault.
//
// 0600 because the content is every password the user has.
func ToFile(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists — choose another name rather than write over it", path)
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
