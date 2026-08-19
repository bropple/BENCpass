// Package ui is the window: the same interface as the extension's manager,
// drawn with a different toolkit.
//
// Every colour here is copied from src/ui/style.css rather than chosen, and
// the fonts are the same two files the extension ships, converted from woff2
// to TrueType because that is what a desktop toolkit will load. Someone who
// has used BENCpass should recognise this on sight; someone who has not should
// find nothing here that the manager would not also do.
package ui

import (
	_ "embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

//go:embed icon.png
var iconPNG []byte

//go:embed fonts/share-tech-mono.ttf
var shareTechMono []byte

//go:embed fonts/vt323.ttf
var vt323 []byte

// Icon is P. Gon carrying a medical kit — the window icon and the program
// icon, from assets/brand/benco-gon-medic.svg.
var Icon = fyne.NewStaticResource("bencpass-rescue.png", iconPNG)

var (
	fontBody    = fyne.NewStaticResource("share-tech-mono.ttf", shareTechMono)
	fontDisplay = fyne.NewStaticResource("vt323.ttf", vt323)
)

// The palette, from src/ui/style.css.
//
// The accent is P. Gon blue rather than canonical green: the one documented
// departure from the house style guide, recorded in ARCHITECTURE.md §7. Green
// is not dropped, it is promoted to meaning — it is what "this worked" looks
// like and nothing else.
var (
	colBg       = hex(0x080d14) // --bg
	colBg2      = hex(0x0c1420) // --bg-2
	colPanel    = hex(0x141d2a) // --panel
	colBorder   = hex(0x1e2c3d) // --border
	colText     = hex(0xc3d9ee) // --text
	colTextDim  = hex(0x7d93a8) // --text-dim
	colAccent   = hex(0x3d7dbf) // --accent, P. Gon fill
	colAccentHi = hex(0x254d75) // --accent-edge, P. Gon edge
	colGood     = hex(0x78b946) // --good
	colWarn     = hex(0xe8b23d) // --warn
	colBad      = hex(0xd84a3a) // --bad
)

func hex(v uint32) color.Color {
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}

type bencoTheme struct{}

// Theme is the BENCpass look, for both light and dark system settings.
//
// It does not answer to the system's light mode. The extension's interface is
// dark whatever the desktop is doing, and a rescue tool that turned white on
// one machine and not another would be a different program to describe.
var Theme fyne.Theme = bencoTheme{}

func (bencoTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colBg
	case theme.ColorNameForeground, theme.ColorNameForegroundOnPrimary:
		return colText
	case theme.ColorNamePrimary, theme.ColorNameFocus:
		return colAccent
	case theme.ColorNameHyperlink:
		return colAccent
	case theme.ColorNameButton:
		return colPanel
	case theme.ColorNameInputBackground:
		return colBg2
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return colBorder
	case theme.ColorNameDisabled, theme.ColorNamePlaceHolder:
		return colTextDim
	case theme.ColorNameDisabledButton:
		return colBg2
	case theme.ColorNameHover:
		return colBorder
	case theme.ColorNameSelection:
		return colAccentHi
	case theme.ColorNameError:
		return colBad
	case theme.ColorNameSuccess:
		return colGood
	case theme.ColorNameWarning:
		return colWarn
	case theme.ColorNameShadow:
		// No decorative shadow. Nothing in the extension's interface has one.
		return color.NRGBA{A: 0}
	case theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return colPanel
	case theme.ColorNameScrollBar:
		return colBorder
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

// Font maps the two fonts the extension uses onto the one axis a toolkit theme
// gives us to choose between them.
//
// Share Tech Mono is the body font and the default here. VT323 is the display
// font — titles only, one per screen — and bold is how this file asks for it.
// Nothing else in the window is set bold, which is what keeps the mapping
// honest.
func (bencoTheme) Font(s fyne.TextStyle) fyne.Resource {
	if s.Bold {
		return fontDisplay
	}
	return fontBody
}

func (bencoTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (bencoTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	// Radii stay small — 2 to 4px — per the style guide. Fyne's default is
	// larger and reads as a different family of software immediately.
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 3
	case theme.SizeNameInputBorder:
		return 1
	}
	return theme.DefaultTheme().Size(name)
}
