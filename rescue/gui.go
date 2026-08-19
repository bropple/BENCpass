package main

import "ropple.net/bencpass/rescue/internal/ui"

// The window. Kept behind one function so main.go says nothing about a
// toolkit, and so a build that cannot draw one has a single thing to replace.
func runGUI(path string) int { return ui.Run(path, Version) }
