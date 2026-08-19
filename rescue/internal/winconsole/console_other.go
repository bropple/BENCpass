//go:build !windows

// Package winconsole gives a GUI-subsystem program somewhere to print.
//
// Kept out of package main, and free of any toolkit import, so that
// `GOOS=windows go build ./internal/winconsole` type-checks it from a Linux
// machine. The rest of this program needs cgo and a Windows toolchain to
// cross-compile, which means the Windows-only file would otherwise be written
// blind and first compiled by a release.
package winconsole

// Attach does nothing anywhere except Windows. Every other platform starts a
// program with its standard handles already connected.
func Attach() {}
