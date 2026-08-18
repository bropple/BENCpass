package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"ropple.net/bencpass/rescue/internal/export"
	"ropple.net/bencpass/rescue/internal/vault"
)

// The headless half. Everything the window can do, for a machine with no
// desktop on it — a NAS holding the store.json, a recovery shell, a script.
//
// Passwords are never printed unless they were asked for by name. `-list` shows
// what is in the vault; `-show` shows one record and says what it is about to
// do first. A terminal keeps scrollback, and a shell keeps history, and neither
// forgets on request.

func describe(f *vault.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", f.Path)
	fmt.Fprintf(&b, "  %s, format %d\n", f.Kind, vault.Format)
	fmt.Fprintf(&b, "  created %s\n", time.UnixMilli(f.Created()).Format(time.RFC3339))
	fmt.Fprintf(&b, "  %d sealed records\n", f.Count())
	fmt.Fprintf(&b, "  key derivation: %s\n", f.KDFDescription())

	ways := []string{"master password"}
	if f.HasRecovery() {
		ways = append(ways, "recovery code")
	}
	fmt.Fprintf(&b, "  ways in: %s\n", strings.Join(ways, ", "))
	if f.HasBiometric() {
		// Worth saying rather than leaving the user to wonder why the
		// fingerprint they enrolled is not offered.
		b.WriteString("  a fingerprint is enrolled, and cannot be used here:\n" +
			"    that secret lives in the authenticator and is only released to a browser.\n")
	}
	return b.String()
}

// askSecret reads a password or recovery code without echoing it.
//
// From a pipe when there is one, so this works in a script, and from the
// terminal otherwise. Reading from a pipe deliberately does not print the
// prompt: it would end up in the middle of whatever the caller was capturing.
func askSecret(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unlock(f *vault.File, useRecovery bool) (*vault.Vault, error) {
	if useRecovery && !f.HasRecovery() {
		return nil, vault.ErrNoRecovery
	}
	prompt := "Master password: "
	if useRecovery {
		prompt = "Recovery code: "
	}
	secret, err := askSecret(prompt)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, errors.New("no secret given")
	}

	// Said before the wait rather than after it, because at 128 MiB this takes
	// long enough that silence reads as a hang.
	fmt.Fprintf(os.Stderr, "Deriving the key (%s)...\n", f.KDFDescription())

	if useRecovery {
		return f.UnlockWithRecoveryCode(secret)
	}
	return f.UnlockWithPassword(secret)
}

func report(w io.Writer, v *vault.Vault) {
	if v.Deleted > 0 {
		fmt.Fprintf(w, "%d deleted record(s) skipped.\n", v.Deleted)
	}
	if len(v.Damaged) > 0 {
		// Never silent. A rescue tool returning fewer records than the file
		// holds, without saying so, is lying at the worst possible moment.
		fmt.Fprintf(w, "%d record(s) would not open and are NOT listed below:\n", len(v.Damaged))
		for _, id := range v.Damaged {
			fmt.Fprintf(w, "  %s\n", id)
		}
	}
}

func list(v *vault.Vault) {
	report(os.Stderr, v)
	fmt.Printf("%d record(s).\n\n", len(v.Records))
	for _, r := range v.Records {
		kind := "login"
		if r.IsAddress() {
			kind = "address"
		}
		fmt.Printf("  %-8s %s\n", kind, r.Title())
		if u := r.Username(); u != "" {
			fmt.Printf("           %s\n", u)
		}
		if urls := r.URLs(); len(urls) > 0 {
			fmt.Printf("           %s\n", strings.Join(urls, " "))
		}
		fmt.Printf("           %s\n", r.ID)
	}
	fmt.Println("\nPasswords are not shown. Use -show <id or title>, or -export.")
}

// show prints one record in full, passwords included, having said so.
func show(v *vault.Vault, want string) error {
	want = strings.ToLower(want)
	var hits []vault.Record
	for _, r := range v.Records {
		if strings.ToLower(r.ID) == want || strings.Contains(strings.ToLower(r.Title()), want) {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("nothing matches %q", want)
	case 1:
	default:
		// Printing every match would put passwords on screen that nobody asked
		// for. Name them and let the user choose.
		fmt.Fprintf(os.Stderr, "%d records match %q:\n", len(hits), want)
		for _, r := range hits {
			fmt.Fprintf(os.Stderr, "  %s  %s\n", r.ID, r.Title())
		}
		return errors.New("be more specific, or use the id")
	}

	fmt.Fprintln(os.Stderr, "This prints secrets to your terminal, which keeps scrollback.")
	r := hits[0]
	for _, k := range []string{"title", "username", "password", "totp", "notes"} {
		if val := r.Str(k); val != "" {
			fmt.Printf("%-10s %s\n", k, val)
		}
	}
	for _, u := range r.URLs() {
		fmt.Printf("%-10s %s\n", "url", u)
	}
	if r.IsAddress() {
		for k, val := range r.Fields {
			s, ok := val.(string)
			if !ok || s == "" || k == "title" || k == "notes" || k == "type" {
				continue
			}
			fmt.Printf("%-10s %s\n", k, s)
		}
	}
	return nil
}

func exportTo(v *vault.Vault, path string) error {
	var body []byte
	var err error
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		body = export.CSV(v.Records)
	case ".json":
		body, err = export.JSON(v.Records, time.Now())
	default:
		return fmt.Errorf("name the file .json or .csv so it is clear what is in it (got %q)", filepath.Ext(path))
	}
	if err != nil {
		return err
	}
	if err := export.ToFile(path, body); err != nil {
		return err
	}
	report(os.Stderr, v)
	fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes, mode 0600).\n", path, len(body))
	fmt.Fprintln(os.Stderr, "It holds your passwords in plain text. Move it somewhere safe, or delete it when done.")
	return nil
}
