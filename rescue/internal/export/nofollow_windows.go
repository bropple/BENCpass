//go:build windows

package export

// Windows has no O_NOFOLLOW. Its reparse points are a different mechanism with
// different defaults, and there is no flag here to ask for; the Lstat check in
// WriteReplacing is what stands, with the race it implies.
const noFollow = 0
