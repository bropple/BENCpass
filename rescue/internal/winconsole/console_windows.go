//go:build windows

package winconsole

import (
	"os"

	"golang.org/x/sys/windows"
)

// Attach connects this process to the console it was launched from.
//
// A Windows GUI-subsystem binary has no console of its own, so -version, -help
// and every headless mode print into nothing at all. Attaching the parent's
// console gives them somewhere to go.
//
// Only when output is not already going somewhere: if the caller redirected to
// a file or a pipe, reopening the standard handles onto CONOUT$ would take the
// output away from whoever asked for it, which is worse than the problem this
// fixes.
func Attach() {
	if redirected(os.Stdout) && redirected(os.Stderr) {
		return
	}
	if r, _, _ := attachConsoleProc.Call(uintptr(attachParentProcess)); r == 0 {
		// No parent console — launched from Explorer or a shortcut. There is
		// nothing to attach to and nothing to say about it.
		return
	}
	if !redirected(os.Stdout) {
		if f := conout(); f != nil {
			os.Stdout = f
		}
	}
	if !redirected(os.Stderr) {
		if f := conout(); f != nil {
			os.Stderr = f
		}
	}
}

// x/sys/windows does not wrap AttachConsole, so it is called directly. Found
// by type-checking this file with GOOS=windows from a Linux machine, which is
// the whole reason this package has no toolkit import.
var attachConsoleProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// The pseudo-process-id meaning "the console of the parent".
const attachParentProcess = ^uint32(0) // (DWORD)-1

// redirected reports whether a handle already points somewhere real. A GUI
// binary started from Explorer has handles that are simply invalid, which is
// the case worth attaching for.
func redirected(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0 && info.Size() >= 0
}

func conout() *os.File {
	name, err := windows.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(h), "CONOUT$")
}
