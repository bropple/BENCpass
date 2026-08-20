//go:build windows

package devices

import "os"

// preserveOwner is a no-op on Windows: there is no unix owner to carry over,
// and the store this operates on lives on a NAS in practice anyway.
func preserveOwner(string, os.FileInfo) {}
