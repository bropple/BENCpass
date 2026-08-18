package main

import (
	"fmt"
	"os"
)

func runGUI(path string) int {
	fmt.Fprintln(os.Stderr, "the window is not built into this binary yet; see -help")
	return 2
}
