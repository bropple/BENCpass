package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"ropple.net/bencpass/rescue/internal/devices"
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
	// Ctrl-C during the prompt would otherwise kill the process between
	// term.ReadPassword disabling echo and its deferred restore, leaving the
	// shell silently typing nothing back. The person reaching for this tool is
	// already having a bad day; handing back a terminal that looks broken is a
	// poor addition to it.
	fd := int(os.Stdin.Fd())
	state, err := term.GetState(fd)
	if err == nil {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		defer func() {
			signal.Stop(stop)
			close(stop)
		}()
		go func() {
			if _, ok := <-stop; !ok {
				return
			}
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			os.Exit(130) // 128 + SIGINT, what a shell expects
		}()
	}

	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
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
	// Said here too, and this is the mode where it matters most: somebody
	// asking for one password by name. If that record is the damaged one, the
	// answer without this line is "nothing matches", which reads as "you never
	// saved it" rather than "it is here and will not open".
	report(os.Stderr, v)

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
	printRecord(os.Stdout, hits[0])
	return nil
}

// printRecord is the whole of one record, secrets included. Separate from show
// so a test can point it at a buffer; show is the part that finds the record
// and says what is about to happen.
func printRecord(w io.Writer, r vault.Record) {
	for _, k := range []string{"title", "username", "password", "totp", "notes"} {
		if val := r.Str(k); val != "" {
			fmt.Fprintf(w, "%-10s %s\n", k, val)
		}
	}
	// Previous passwords, newest first, each with the date it was set — the
	// same "set <date>" / "undated" the manager shows. They are printed
	// because the older password is sometimes the one that is needed: a
	// rotation that a site silently rejected leaves the site on the previous
	// password, and on the day the browser will not start, this tool is the
	// only place left to read it.
	for _, h := range r.History() {
		when := "undated"
		if h.Changed > 0 {
			when = "set " + time.UnixMilli(h.Changed).Format("2006-01-02")
		}
		fmt.Fprintf(w, "%-10s %s  (%s)\n", "previous", h.Password, when)
	}
	for _, u := range r.URLs() {
		fmt.Fprintf(w, "%-10s %s\n", "url", u)
	}
	if r.IsAddress() {
		for k, val := range r.Fields {
			s, ok := val.(string)
			if !ok || s == "" || k == "title" || k == "notes" || k == "type" {
				continue
			}
			fmt.Fprintf(w, "%-10s %s\n", k, s)
		}
	}
}

// runDevices lists the devices enrolled on a sync server store, and — asked
// twice, backed up first — removes one.
//
// This is the tool's one write, and it exists because the alternative was
// documented in TRUENAS-DEPLOY.md as a python heredoc run by hand on the NAS:
// when every machine is lost, the enrolled-but-dead devices stop the server
// from ever printing another bootstrap code, and hand-editing the last copy of
// the vault is a poor thing to ask of somebody on that day. See
// internal/devices for what keeps the write contained.
//
// in and stdout are parameters so a test can drive the confirmation; prompts
// and progress go to stderr like everywhere else in this file, so piped output
// stays clean.
func runDevices(path, forget string, in io.Reader, stdout io.Writer) error {
	s, err := devices.Load(path)
	if err != nil {
		return err
	}
	list, err := s.List()
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "%d device(s) enrolled on %s:\n\n", len(list), s.Path)
	for _, d := range list {
		fmt.Fprintf(stdout, "  %s  %-12s %s\n",
			time.UnixMilli(d.Created).Format("2006-01-02"), d.Name, d.ID)
	}
	if forget == "" {
		if len(list) > 0 {
			fmt.Fprintln(stdout, "\nTo remove one: -devices -forget <id>, with the server stopped.")
		}
		return nil
	}

	d, err := s.Forget(forget) // in memory only; nothing is written until Save
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, `
About to remove  %s  %s  (enrolled %s)
from             %s

STOP THE SERVER FIRST. A running server keeps the whole store in memory and
writes the old device list straight back over this change on its next save.
This tool cannot tell whether it is running, so it has to be your word.

A backup copy of the file is written beside it before anything changes.

`, d.Name, d.ID, time.UnixMilli(d.Created).Format("2006-01-02"), s.Path)

	answer, err := askLine(`Type "forget" to continue: `, in)
	if err != nil {
		return err
	}
	if answer != "forget" {
		return errors.New("not confirmed — nothing was written")
	}

	backup, err := s.Save()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Backup written: %s\n", backup)
	fmt.Fprintf(stdout, "\nRemoved %s (%s).\n", d.Name, d.ID)

	remaining := len(list) - 1
	if remaining == 0 {
		fmt.Fprintln(stdout, "No devices remain. Start the server: it will print a fresh bootstrap")
		fmt.Fprintln(stdout, "enrolment code, and joining with that code and the same master password")
		fmt.Fprintln(stdout, "opens the same vault — the header and every record are untouched.")
	} else {
		fmt.Fprintf(stdout, "%d device(s) remain.\n", remaining)
	}
	return nil
}

// askLine reads one echoed line — a confirmation, not a secret.
func askLine(prompt string, in io.Reader) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
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
