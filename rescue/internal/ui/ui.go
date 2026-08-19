package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"ropple.net/bencpass/rescue/internal/export"
	"ropple.net/bencpass/rescue/internal/vault"
)

// Run opens the window. path may be empty, in which case it asks for a file.
func Run(path, version string) int {
	a := fyneapp.NewWithID("net.ropple.bencpass.rescue")
	a.Settings().SetTheme(Theme)
	a.SetIcon(Icon)

	w := a.NewWindow("BENCpass Rescue")
	w.SetIcon(Icon)
	w.Resize(fyne.NewSize(940, 640))
	w.CenterOnScreen()

	s := &session{app: a, win: w, version: version}
	if path != "" {
		s.load(path)
	} else {
		s.showChooser("")
	}

	w.ShowAndRun()
	s.close()
	return 0
}

type session struct {
	app     fyne.App
	win     fyne.Window
	version string

	file   *vault.File
	vlt    *vault.Vault
	shown  []vault.Record // what the list is currently displaying
	status *canvas.Text   // the line under the vault list, for transient notes
}

// The show* pair with each build*: the builders are pure so that a test can
// render a screen to an image without a display, which is the only way to look
// at this interface on a machine that has none.
func (s *session) showChooser(problem string) { s.win.SetContent(s.buildChooser(problem)) }
func (s *session) showUnlock(problem string)  { s.win.SetContent(s.buildUnlock(problem)) }
func (s *session) showVault()                 { s.win.SetContent(s.buildVault()) }

func (s *session) close() {
	if s.vlt != nil {
		s.vlt.Close()
	}
}

// ---- chrome ----------------------------------------------------------------

// title is the one place bold appears, which is how the theme is asked for
// VT323. One glowing title per screen, as the style guide puts it — except
// there is no glow, because a text shadow is not a thing a toolkit gives you
// and the guide rations it anyway.
func title(text string) *canvas.Text {
	t := canvas.NewText(text, colText)
	t.TextStyle = fyne.TextStyle{Bold: true}
	t.TextSize = 34
	return t
}

func dim(text string) *canvas.Text {
	t := canvas.NewText(text, colTextDim)
	t.TextSize = 13
	return t
}

func header(subtitle string) fyne.CanvasObject {
	logo := canvas.NewImageFromResource(Icon)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(52, 52))

	words := container.NewVBox(title("BENCpass Rescue"), dim(subtitle))
	return container.NewBorder(nil, nil, logo, nil, container.NewPadded(words))
}

// note renders a line of explanation. Deadpan, and never an exclamation.
func note(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Wrapping = fyne.TextWrapWord
	return l
}

func (s *session) fail(err error) {
	dialog.ShowError(err, s.win)
}

// ---- 1. which file ---------------------------------------------------------

func (s *session) buildChooser(problem string) fyne.CanvasObject {
	body := container.NewVBox(
		note("Open an encrypted backup, or a sync server's store.json.\n\n" +
			"A backup comes from BENCpass → Settings → Your data → Save an encrypted backup. " +
			"A server's copy is the store.json in its data directory. Either one holds the whole vault, " +
			"and neither can be read without your master password or your recovery code."),
	)
	if problem != "" {
		p := canvas.NewText(problem, colBad)
		p.TextSize = 13
		body.Add(p)
	}

	choose := widget.NewButton("Choose a file...", func() {
		d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			path := r.URI().Path()
			r.Close()
			s.load(path)
		}, s.win)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		d.Resize(fyne.NewSize(760, 520))
		d.Show()
	})
	choose.Importance = widget.HighImportance

	// Dropping the file on the window is how most people will actually do it.
	if s.win != nil {
		s.win.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) {
			if len(uris) > 0 {
				s.load(uris[0].Path())
			}
		})
	}

	return container.NewBorder(
		container.NewPadded(header("open a vault without a browser")),
		container.NewPadded(dim("This program never writes to the file you give it, and never uses the network.")),
		nil, nil,
		container.NewPadded(container.NewVBox(body, container.NewHBox(choose))),
	)
}

// ---- 2. unlock -------------------------------------------------------------

func (s *session) load(path string) {
	f, err := vault.Read(path)
	if err != nil {
		s.showChooser(err.Error())
		return
	}
	s.file = f
	s.showUnlock("")
}

func (s *session) buildUnlock(problem string) fyne.CanvasObject {
	f := s.file

	facts := widget.NewForm(
		widget.NewFormItem("File", widget.NewLabel(filepath.Base(f.Path))),
		widget.NewFormItem("Kind", widget.NewLabel(string(f.Kind))),
		widget.NewFormItem("Created", widget.NewLabel(time.UnixMilli(f.Created()).Format("2 January 2006"))),
		widget.NewFormItem("Holds", widget.NewLabel(fmt.Sprintf("%d sealed records", f.Count()))),
		widget.NewFormItem("Key", widget.NewLabel(f.KDFDescription())),
	)

	secret := widget.NewPasswordEntry()
	secret.SetPlaceHolder("Master password")

	useRecovery := widget.NewCheck("Use my recovery code instead", nil)
	if !f.HasRecovery() {
		useRecovery.Disable()
	}
	useRecovery.OnChanged = func(on bool) {
		if on {
			secret.SetPlaceHolder("Recovery code — dashes and spacing do not matter")
		} else {
			secret.SetPlaceHolder("Master password")
		}
		secret.Refresh()
	}

	status := canvas.NewText(problem, colBad)
	status.TextSize = 13

	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	unlock := widget.NewButton("Unlock", nil)
	unlock.Importance = widget.HighImportance

	attempt := func() {
		if strings.TrimSpace(secret.Text) == "" {
			return
		}
		unlock.Disable()
		secret.Disable()
		progress.Show()
		// Argon2 at 128 MiB takes long enough that doing it on the UI thread
		// would look exactly like a crash. Off the thread, and every touch of
		// a widget afterwards goes back through fyne.Do.
		status.Text = "Deriving the key. This is meant to be slow."
		status.Color = colTextDim
		status.Refresh()

		go func() {
			var v *vault.Vault
			var err error
			if useRecovery.Checked {
				v, err = s.file.UnlockWithRecoveryCode(secret.Text)
			} else {
				v, err = s.file.UnlockWithPassword(secret.Text)
			}
			fyne.Do(func() {
				progress.Hide()
				unlock.Enable()
				secret.Enable()
				if err != nil {
					status.Text = err.Error()
					status.Color = colBad
					status.Refresh()
					return
				}
				s.vlt = v
				s.showVault()
			})
		}()
	}
	unlock.OnTapped = attempt
	secret.OnSubmitted = func(string) { attempt() }

	ways := container.NewVBox(secret, useRecovery, container.NewHBox(unlock), progress, status)

	if f.HasBiometric() {
		// Say why the fingerprint they enrolled is not on offer, rather than
		// leaving them to conclude they have the wrong file.
		ways.Add(dim("A fingerprint is enrolled on this vault and cannot be used here: " +
			"that secret stays inside the authenticator and is only released to a browser."))
	}

	back := widget.NewButton("Choose another file", func() { s.showChooser("") })

	// Focused here rather than after the return, which is where the mechanical
	// split of this function first put it.
	if s.win != nil {
		s.win.Canvas().Focus(secret)
	}

	return container.NewBorder(
		container.NewPadded(header("unlock")),
		container.NewPadded(container.NewHBox(back)),
		nil, nil,
		container.NewPadded(container.NewVBox(facts, widget.NewSeparator(), ways)),
	)
}

// ---- 3. the vault -----------------------------------------------------------

func (s *session) buildVault() fyne.CanvasObject {
	v := s.vlt
	s.shown = v.Records

	detail := container.NewVBox()
	// An empty pane looks like a failure to load. Say what to do instead.
	blank := func() {
		detail.RemoveAll()
		detail.Add(dim("Choose a record on the left."))
		if len(v.Damaged) > 0 {
			// Repeated here because this is where somebody hunting for a
			// missing record will actually be looking.
			detail.Add(dim(fmt.Sprintf("%d record(s) in this file would not open. "+
				"They are not in the list, and are not in an export.", len(v.Damaged))))
		}
		detail.Refresh()
	}
	blank()
	list := widget.NewList(
		func() int { return len(s.shown) },
		func() fyne.CanvasObject {
			return container.NewVBox(widget.NewLabel("title"), dim("subtitle"))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(s.shown) {
				return
			}
			r := s.shown[i]
			box := o.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(r.Title())
			sub := r.Username()
			if r.IsAddress() {
				sub = "address"
			}
			t := box.Objects[1].(*canvas.Text)
			t.Text = sub
			t.Refresh()
		},
	)
	list.OnSelected = func(i widget.ListItemID) {
		if i < len(s.shown) {
			s.fillDetail(detail, s.shown[i])
		}
	}

	search := widget.NewEntry()
	search.SetPlaceHolder("Search")
	search.OnChanged = func(q string) {
		q = strings.ToLower(strings.TrimSpace(q))
		s.shown = nil
		for _, r := range v.Records {
			if q == "" || strings.Contains(strings.ToLower(r.Title()+" "+r.Username()+" "+strings.Join(r.URLs(), " ")), q) {
				s.shown = append(s.shown, r)
			}
		}
		list.UnselectAll()
		list.Refresh()
	}

	left := container.NewBorder(search, nil, nil, nil, list)
	right := container.NewVScroll(container.NewPadded(detail))
	split := container.NewHSplit(left, right)
	split.Offset = 0.36

	// What was skipped, always said out loud. A rescue tool that returns fewer
	// records than the file holds without mentioning it is lying at the worst
	// possible moment.
	var warnings []fyne.CanvasObject
	if v.Deleted > 0 {
		warnings = append(warnings, dim(fmt.Sprintf("%d deleted record(s) not shown.", v.Deleted)))
	}
	if len(v.Damaged) > 0 {
		t := canvas.NewText(fmt.Sprintf("%d record(s) would not open and are not listed.", len(v.Damaged)), colBad)
		t.TextSize = 13
		warnings = append(warnings, t)
	}

	exportBtn := widget.NewButton("Export everything...", s.exportAll)
	exportBtn.Importance = widget.HighImportance

	s.status = dim("")
	bottom := container.NewVBox(
		container.NewHBox(exportBtn, layout.NewSpacer(),
			widget.NewButton("Lock and choose another", func() {
				s.vlt.Close()
				s.vlt = nil
				// Close nils the vault's own slice, but this one is a separate
				// header still pointing at every decrypted record. Go cannot
				// truly wipe those strings — the same admission wipe() makes —
				// so dropping the reference is all there is, and keeping it
				// would hold the whole vault in a locked session.
				s.shown = nil
				s.showChooser("")
			})),
		container.NewVBox(warnings...),
		s.status,
	)

	return container.NewBorder(
		container.NewPadded(header(fmt.Sprintf("%d records from %s", len(v.Records), filepath.Base(s.file.Path)))),
		container.NewPadded(bottom), nil, nil,
		container.NewPadded(split),
	)
}

// flash writes a transient line into the vault screen's status area. Nil-safe,
// because the detail pane is also built by tests that have no status line.
func (s *session) flash(text string) {
	if s.status == nil {
		return
	}
	s.status.Text = text
	s.status.Color = colTextDim
	s.status.Refresh()
}

func (s *session) fillDetail(box *fyne.Container, r vault.Record) {
	box.RemoveAll()

	head := canvas.NewText(r.Title(), colText)
	head.TextSize = 20
	box.Add(head)

	copyBtn := func(what, value string) fyne.CanvasObject {
		return widget.NewButton("Copy "+what, func() {
			s.app.Clipboard().SetContent(value)
			// The clipboard is shared with everything else running, and
			// nothing here can clear it later — this program may well be
			// closed first. Better to say so than to imply otherwise.
			s.flash(fmt.Sprintf("%s copied. It stays on the clipboard until something replaces it.", what))
		})
	}

	row := func(label, value string) {
		if value == "" {
			return
		}
		box.Add(dim(strings.ToUpper(label)))
		e := widget.NewEntry()
		e.SetText(value)
		// Readable and selectable, but this tool does not edit a vault, and an
		// entry that accepts a keystroke it will never save is a lie about what
		// the program does.
		e.Disable()
		box.Add(e)
	}

	if !r.IsAddress() {
		row("username", r.Username())
		if r.Username() != "" {
			box.Add(container.NewHBox(copyBtn("username", r.Username())))
		}

		pw := widget.NewPasswordEntry()
		pw.SetText(r.Password())
		pw.Disable()
		box.Add(dim("PASSWORD"))
		box.Add(pw)
		box.Add(container.NewHBox(copyBtn("password", r.Password())))

		row("one-time code secret", r.Str("totp"))
		for _, u := range r.URLs() {
			row("site", u)
		}
	} else {
		for _, k := range []string{"name", "organization", "address-line1", "address-line2",
			"address-level2", "address-level1", "postal-code", "country", "tel", "email"} {
			row(strings.ReplaceAll(k, "-", " "), r.Str(k))
		}
	}

	row("notes", r.Notes())
	box.Add(widget.NewSeparator())
	box.Add(dim("id " + r.ID))
	box.Refresh()
}

func (s *session) exportAll() {
	warn := dialog.NewConfirm("Export everything",
		"This writes every password in the vault to a file, in plain text.\n\n"+
			"Anyone who can read that file can read them. The file is created "+
			"readable only by you, but that protection ends the moment it is "+
			"copied somewhere else.\n\nName it .json to keep everything, or "+
			".csv for logins only.",
		func(ok bool) {
			if !ok {
				return
			}
			d := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
				if err != nil || wc == nil {
					return
				}
				path := wc.URI().Path()
				// Closed straight away and written by hand: the toolkit's
				// writer does not promise a file mode, and this one has to be
				// 0600.
				wc.Close()
				s.writeExport(path)
			}, s.win)
			d.SetFileName("bencpass-export.json")
			d.Resize(fyne.NewSize(760, 520))
			d.Show()
		}, s.win)
	warn.SetConfirmText("I understand")
	warn.Show()
}

func (s *session) writeExport(path string) {
	var body []byte
	var err error
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		body = export.CSV(s.vlt.Records)
	case ".json":
		body, err = export.JSON(s.vlt.Records, time.Now())
	default:
		s.fail(fmt.Errorf("name the file .json or .csv, so that what is in it is obvious later"))
		return
	}
	if err != nil {
		s.fail(err)
		return
	}
	// The save dialog has already asked about replacing, so this truncates
	// rather than refusing — unlike the command line, where nothing asked.
	// Writing it is export's business, including the file mode the dialog just
	// promised: see WriteReplacing for why that needs an explicit chmod.
	if err := export.WriteReplacing(path, body); err != nil {
		s.fail(err)
		return
	}
	dialog.ShowInformation("Written",
		fmt.Sprintf("%s\n\n%d records, in plain text. Move it somewhere safe, or delete it when you are done.",
			path, len(s.vlt.Records)), s.win)
}

// newDetailBox is the container fillDetail writes into. Named so that a test
// can build one without standing up the whole vault screen.
func newDetailBox() *fyne.Container { return container.NewVBox() }
