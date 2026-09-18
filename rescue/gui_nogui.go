//go:build nogui

package main

import (
	"fmt"
	"os"
)

// The window, in the build that has none.
//
// Fyne is linked at load time whatever flags are passed to it, so a binary
// with the toolkit compiled in needs libGL, libX11 and a Wayland client
// present just to reach main(). A headless server has none of those, and the
// headless commands -- -devices and -forget, the way back when every enrolled
// machine is gone -- are exactly the ones that have to run there. The GUI
// build died in the dynamic linker before it could decline to draw anything.
//
// So this build exists to link nothing but libc. Everything the tool can do
// without a window it still does; asking for the window says where to get one.
func runGUI(path string) int {
	_ = path
	fmt.Fprintln(os.Stderr, `this is bencpass-rescue-cli, built without a window.

It does everything the tool can do from a terminal:

  bencpass-rescue-cli -info    <file>   describe it without unlocking
  bencpass-rescue-cli -list    <file>   list the records
  bencpass-rescue-cli -export  <out>    write everything out
  bencpass-rescue-cli -devices <store>  devices on a sync server's store
  bencpass-rescue-cli -help             all of it

For the window, use the bencpass-rescue build from the same release.`)
	return 2
}
