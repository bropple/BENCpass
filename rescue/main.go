// BENCpass Rescue opens a BENCpass vault without a browser.
//
// It exists for the days the extension cannot help: a profile that will not
// load, a machine that is gone, a Firefox that will not install. Given an
// encrypted backup or the sync server's store.json, and either the master
// password or the printed recovery code, it lists what is inside and writes it
// back out in a form something else can read.
//
// It never touches the network, and it never writes to the file it was given —
// with one deliberate exception: -forget rewrites a sync server's device list,
// offline, after writing a backup copy of the whole file first. That is for the
// day every machine is lost and the dead devices hold the enrolment door shut;
// see internal/devices for why it is built the way it is. The vault itself is
// still never written: internal/vault has no write path at all.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"ropple.net/bencpass/rescue/internal/vault"
	"ropple.net/bencpass/rescue/internal/winconsole"
)

// Version is stamped at build time:
//
//	go build -ldflags "-X main.Version=0.11.0"
var Version = "dev"

const usage = `BENCpass Rescue — open a BENCpass vault without a browser.

  bencpass-rescue <file>                 open it in a window
  bencpass-rescue -info <file>           say what the file is, without unlocking
  bencpass-rescue -list <file>           list what is inside
  bencpass-rescue -show <what> <file>    print one record, secrets included
  bencpass-rescue -export <out> <file>   write it all out as .json or .csv

  bencpass-rescue -devices <store>       list the machines enrolled on a sync server
  bencpass-rescue -devices -forget <id> <store>
                                         remove one, with the server STOPPED

<file> is either:
  - an encrypted backup, from BENCpass -> Settings -> Your data
  - a sync server's store.json, or the data directory holding it
<store> is only the second: enrolment is the server's affair, so a backup
has no devices in it.

Options:
  -recovery    unlock with the printed recovery code instead of the password
  -version     print the version and exit

The secret is read from the terminal without echoing, or from standard input
when it is piped:

  printf '%s' "$PASSWORD" | bencpass-rescue -list backup.json

-forget exists for the day every machine is lost or wiped: nothing can mint an
enrolment code then, because minting needs an enrolled machine to sign for it,
and the server prints a bootstrap code only while NO device is enrolled. Remove
the dead devices here and the next server start prints a fresh code; joining
with it and the same master password opens the same vault.

This program never uses the network, and never writes to the file it was given
— except -forget, which rewrites the store's device list after writing a backup
copy of the whole file beside it. It asks before it does either.
`

func main() {
	// On Windows this is a GUI binary with no console of its own, so every
	// headless mode would otherwise print into nothing. Does nothing anywhere
	// else, and nothing when output is already redirected.
	winconsole.Attach()

	var (
		info     = flag.Bool("info", false, "describe the file without unlocking it")
		listing  = flag.Bool("list", false, "list the records")
		showWhat = flag.String("show", "", "print one record, by id or title")
		out      = flag.String("export", "", "write everything to this .json or .csv file")
		devs     = flag.Bool("devices", false, "list the devices enrolled on a sync server store")
		forget   = flag.String("forget", "", "remove this device id from the store, server stopped")
		recovery = flag.Bool("recovery", false, "unlock with the recovery code")
		version  = flag.Bool("version", false, "print the version")
	)
	flag.Usage = func() { io.WriteString(os.Stderr, usage) }
	flag.Parse()

	if *version {
		fmt.Printf("bencpass-rescue %s (vault format %d)\n", Version, vault.Format)
		return
	}

	args := flag.Args()
	devMode := *devs || *forget != ""
	headless := *info || *listing || *showWhat != "" || *out != "" || devMode

	if len(args) == 0 {
		if headless {
			fmt.Fprintln(os.Stderr, "which file? See -help.")
			os.Exit(2)
		}
		// No file and no flags: open the window and let it ask.
		os.Exit(runGUI(""))
	}
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "one file at a time, got %d\n", len(args))
		os.Exit(2)
	}
	path := args[0]

	if !headless {
		os.Exit(runGUI(path))
	}

	if devMode {
		// Its own path entirely: no unlocking, no secret, and — alone in this
		// program — a write at the end of it. Mixing it with a vault mode
		// would blur which of the two is about to happen.
		if *info || *listing || *showWhat != "" || *out != "" {
			fmt.Fprintln(os.Stderr, "-devices works on its own; drop the other flags")
			os.Exit(2)
		}
		if err := runDevices(path, *forget, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(path, *info, *listing, *showWhat, *out, *recovery); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		os.Exit(1)
	}
}

func run(path string, info, listing bool, showWhat, out string, recovery bool) error {
	f, err := vault.Read(path)
	if err != nil {
		return err
	}

	// -info deliberately needs no secret. It is how somebody with three
	// candidate files works out which one is the vault.
	fmt.Fprint(os.Stderr, describe(f))
	if info {
		return nil
	}

	v, err := unlock(f, recovery)
	if err != nil {
		return err
	}
	defer v.Close()

	switch {
	case showWhat != "":
		return show(v, showWhat)
	case out != "":
		return exportTo(v, out)
	default:
		list(v)
		return nil
	}
}
