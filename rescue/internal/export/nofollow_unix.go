//go:build !windows

package export

import "syscall"

// noFollow makes the kernel refuse a symlink as part of the open itself.
//
// Without it the refusal is an Lstat followed by an OpenFile — two calls, and
// therefore a race: an attacker who can write to the directory can replace the
// path with a link in between, and the export lands wherever they chose. The
// Lstat is kept for the sake of a readable error, but this is the check.
const noFollow = syscall.O_NOFOLLOW
