package main

// The status page.
//
// Exists because hitting the endpoint in a browser otherwise returns 404, which
// tells you nothing about whether you have the right host, the right port, or a
// running server. TrueNAS's app Portal button needs somewhere to land, and this
// is it.
//
// Unauthenticated on purpose, and therefore deliberately thin: it says the
// service is alive, which /v1/health already revealed, and nothing that would
// help anyone who should not be here.

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
)

// Set by the linker; see tools/build-server.sh.
var version = "dev"

// One source for the artwork — tools/make-icons.sh copies it here from
// assets/icon/. Embedding keeps the binary self-contained, which is the whole
// premise of shipping it as a scratch container.
//
//go:embed static/bencpass.svg
var pgonSVG string

var statusPage = template.Must(template.New("status").Parse(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BENCpass</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
  :root {
    --accent: #3d7dbf; --bg: #080d14; --panel: #141d2a;
    --border: #1e2c3d; --text: #c3d9ee; --dim: #7d93a8; --good: #78b946;
  }
  html { background: var(--bg); color: var(--text);
         font: 15px/1.6 ui-monospace, Consolas, monospace; }
  body { max-width: 34rem; margin: 6rem auto; padding: 0 1.5rem; }
  .mark { width: 72px; height: 72px; display: block; }
  h1 { font-size: 1.6rem; font-weight: normal; letter-spacing: 2px; margin: 1rem 0 0; }
  p.sub { color: var(--dim); margin: .25rem 0 2rem; letter-spacing: 1px; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: .4rem 1.5rem;
       background: var(--panel); border: 1px solid var(--border);
       border-radius: 3px; padding: 1rem; margin: 0; }
  dt { color: var(--dim); letter-spacing: 1px; }
  dd { margin: 0; }
  .ok { color: var(--good); }
  footer { color: var(--dim); margin-top: 2rem; font-size: 13px; }
</style>
<svg class="mark" viewBox="0 0 512 512" aria-hidden="true">{{.Mark}}</svg>
<h1>BENCPASS</h1>
<p class="sub">sync endpoint</p>
<dl>
  <dt>Status</dt><dd class="ok">running</dd>
  <dt>Version</dt><dd>{{.Version}}</dd>
  <dt>Sequence</dt><dd>{{.Seq}}</dd>
  <dt>Devices</dt><dd>{{.Devices}} enrolled</dd>
</dl>
<footer>
  This server stores ciphertext and holds no key. It cannot read a record,
  and neither can anyone who takes the disk it sits on &mdash; though they can
  attack the master password offline, so choose it accordingly.
</footer>
`))

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	// ServeMux's "GET /" matches everything unmatched, so an actual 404 has to
	// be produced here or every typo returns the status page and looks fine.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// The device count is shown because the question this page exists to answer
	// is "did my enrolment work". It is a number on a machine already reachable
	// only over the tailnet or the LAN, and it names nothing.
	data := struct {
		Mark    template.HTML
		Version string
		Seq     int64
		Devices int
	}{
		Mark:    template.HTML(innerSVG(pgonSVG)),
		Version: version,
		Seq:     s.store.Seq(),
		Devices: s.store.DeviceCount(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := statusPage.Execute(w, data); err != nil {
		fmt.Fprint(w, "BENCpass")
	}
}

func (s *server) favicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, pgonSVG)
}

// innerSVG strips the outer <svg> wrapper so the artwork can be dropped inside
// the page's own sized <svg>. Crude, and adequate for one file this repository
// generates itself — it is not a parser and is not asked to be.
func innerSVG(doc string) string {
	start := indexAfter(doc, ">")
	end := lastIndex(doc, "</svg>")
	if start < 0 || end < 0 || end < start {
		return ""
	}
	return doc[start:end]
}

func indexAfter(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i + len(sub)
		}
	}
	return -1
}

func lastIndex(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
