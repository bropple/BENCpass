package ui

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"ropple.net/bencpass/rescue/internal/vault"
)

// Rendering each screen without a display.
//
// A GUI that is only ever looked at by the person who wrote it, on the one
// machine they wrote it on, is a GUI that breaks silently. Fyne can draw into
// an image with no window server involved, so every screen is built and drawn
// here — which catches a layout that panics, a nil widget, a screen that
// cannot be constructed from a real vault — and CI runs it on all three
// platforms.
//
// Set BENCPASS_SCREENS=<dir> to also write the images out and look at them.

func TestMain(m *testing.M) {
	// The real theme, not Fyne's test one. Without this the images come back
	// in the toolkit's default grey and orange, which proves the layout and
	// nothing about the thing being matched.
	a := test.NewApp()
	a.Settings().SetTheme(Theme)
	os.Exit(m.Run())
}

func draw(t *testing.T, name string, obj fyne.CanvasObject) {
	t.Helper()
	w := test.NewWindow(obj)
	defer w.Close()
	w.Resize(fyne.NewSize(940, 640))

	img := w.Canvas().Capture()
	if img == nil {
		t.Fatalf("%s drew nothing", name)
	}
	if b := img.Bounds(); b.Dx() < 100 || b.Dy() < 100 {
		t.Fatalf("%s drew %dx%d", name, b.Dx(), b.Dy())
	}

	dir := os.Getenv("BENCPASS_SCREENS")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

func openFixture(t *testing.T) (*vault.File, *vault.Vault) {
	t.Helper()
	f, err := vault.Read(filepath.Join("..", "vault", "testdata", "backup.json"))
	if err != nil {
		t.Skipf("fixtures missing — run: node internal/vault/testdata/gen.mjs (%v)", err)
	}
	v, err := f.UnlockWithPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return f, v
}

func TestDrawsTheChooser(t *testing.T) {
	s := &session{app: fyne.CurrentApp()}
	draw(t, "1-chooser", s.buildChooser(""))
	// The refusal path is a screen too, and the one most likely to be wrong.
	draw(t, "1-chooser-problem", s.buildChooser("that file is vault format 2 and this tool understands 1"))
}

func TestDrawsTheUnlockScreen(t *testing.T) {
	f, _ := openFixture(t)
	s := &session{app: fyne.CurrentApp(), file: f}
	draw(t, "2-unlock", s.buildUnlock(""))
	draw(t, "2-unlock-wrong", s.buildUnlock("wrong secret, or the vault is damaged"))
}

func TestDrawsTheVault(t *testing.T) {
	f, v := openFixture(t)
	s := &session{app: fyne.CurrentApp(), file: f, vlt: v}
	draw(t, "3-vault", s.buildVault())
}

// The detail pane is built per selection, so it gets its own pass — including
// the address record, which takes a different branch entirely.
func TestDrawsRecordDetail(t *testing.T) {
	f, v := openFixture(t)
	s := &session{app: fyne.CurrentApp(), file: f, vlt: v}

	var login, address *vault.Record
	for i := range v.Records {
		r := &v.Records[i]
		if r.IsAddress() && address == nil {
			address = r
		}
		if !r.IsAddress() && login == nil {
			login = r
		}
	}
	if login == nil || address == nil {
		t.Fatal("the fixture needs both a login and an address")
	}

	for name, rec := range map[string]*vault.Record{"4-detail-login": login, "4-detail-address": address} {
		box := newDetailBox()
		s.fillDetail(box, *rec)
		if len(box.Objects) == 0 {
			t.Fatalf("%s built an empty detail pane", name)
		}
		draw(t, name, box)
	}
}

// A vault whose records would not open must say so on screen, not quietly show
// a shorter list.
func TestSaysWhenRecordsAreMissing(t *testing.T) {
	f, v := openFixture(t)
	v.Damaged = append(v.Damaged, "0000-damaged")
	v.Deleted = 2
	s := &session{app: fyne.CurrentApp(), file: f, vlt: v}

	obj := s.buildVault()
	draw(t, "3-vault-damaged", obj)

	var texts []string
	collect(obj, &texts)
	joined := strings.Join(texts, "\n")
	// Both messages, pinned separately. An earlier version of this test looked
	// for "would not open", which the empty detail pane also says — so deleting
	// the footer warning entirely left the test green. Each sentence is now
	// matched on a phrase only it contains.
	for _, want := range []string{
		"1 record(s) would not open and are not listed.", // the footer
		"would not open. They are not in the list",       // the detail pane
		"2 deleted record(s) not shown.",                 // the tombstones
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the user is never told %q. On screen:\n%s", want, joined)
		}
	}
}

// collect walks a built screen and gathers every piece of text on it, so a
// test can assert what the user is actually told rather than what the code
// meant to tell them.
func collect(obj fyne.CanvasObject, out *[]string) {
	switch o := obj.(type) {
	case *canvas.Text:
		*out = append(*out, o.Text)
	case *widget.Label:
		*out = append(*out, o.Text)
	case *widget.Button:
		*out = append(*out, o.Text)
	case *widget.Check:
		*out = append(*out, o.Text)
	case *fyne.Container:
		for _, c := range o.Objects {
			collect(c, out)
		}
	case *container.Split:
		collect(o.Leading, out)
		collect(o.Trailing, out)
	case *container.Scroll:
		collect(o.Content, out)
	}
}
