//go:build !windows

package devices

import (
	"os"
	"syscall"
)

// preserveOwner gives the replacement file the original's owner, where this
// process may. Best-effort by design: run as the file's own user nothing needs
// doing, and run as root — the usual case on a NAS shell — the chown succeeds.
// The case in between (a third user with group write) is left to the person,
// exactly as the mode-only `cp` in the old manual procedure left it.
func preserveOwner(path string, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
