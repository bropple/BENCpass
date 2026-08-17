// The menu drawn against a field.
//
// A separate document on the extension's own origin, embedded in the page as an
// iframe. The page can move it, cover it or remove it, but it cannot read the
// usernames listed here and it cannot synthesise a click that this document
// would believe — which is the whole reason it is not rendered into the page.
//
// It never receives a password either. It sends back the id of the entry the
// user picked; the background decides whether that entry may be filled and
// sends the secret straight to the content script.

import { MSG } from './protocol.js';

// The session id arrives by postMessage from the content script that framed
// this document, never in the URL.
//
// A URL would be readable by the page — this document is framed inside it, and
// the iframe element is in the page's DOM — and with the id in hand the page
// could open its own copy of this web-accessible document, which would satisfy
// every "is this an extension page" check the background makes, and clickjack a
// fill out of it. A message to a cross-origin contentWindow the page cannot
// listen to closes that off.
let sessionId = null;

const $ = (id) => document.getElementById(id);

function row({ title, sub, onPick, className = '' }) {
  const b = document.createElement('button');
  b.className = `row ${className}`.trim();
  b.type = 'button';

  const t = document.createElement('span');
  t.className = 'title';
  t.textContent = title;
  b.append(t);

  if (sub) {
    const s = document.createElement('span');
    s.className = 'sub';
    s.textContent = sub;
    b.append(s);
  }

  b.addEventListener('click', onPick);
  return b;
}

async function render() {
  const reply = await browser.runtime.sendMessage({ type: MSG.SESSION, sessionId });
  const list = $('list');
  list.replaceChildren();

  const candidates = reply?.candidates ?? [];
  const kind = reply?.kind ?? 'login';
  $('head').textContent = kind === 'address' ? 'Addresses' : 'BENCpass';

  if (kind === 'locked') {
    // Deliberately a button that opens the toolbar popup, not a password box
    // here.
    //
    // A master password typed into a panel floating over a page teaches exactly
    // the habit that makes phishing work: any site can draw a convincing
    // imitation of this menu, and the person has no way to tell them apart. The
    // toolbar popup is browser chrome, which a page cannot draw over.
    list.append(
      row({
        title: 'Unlock BENCpass',
        sub: 'Opens the manager in a tab',
        className: 'gen',
        onPick: async () => {
          // Two tiers, because the obvious calls here can fail without saying
          // so. browserAction.openPopup() has no button to hang off when the
          // chrome is hidden, which Zen's compact mode does by default; it
          // resolves and shows nothing, so not even a catch can tell.
          //
          // The sidebar is tried first because it keeps the page in view. If it
          // refuses — opening it needs a user gesture, and a click inside a
          // frame embedded in a page may not count as one — the background
          // opens a tab, which needs no gesture and cannot quietly do nothing.
          //
          // Still not a password box in the page: see the note above.
          try {
            await browser.sidebarAction.open();
            return;
          } catch (err) {
            console.warn('BENCpass: sidebar refused, falling back to a tab', err);
          }
          await browser.runtime.sendMessage({ type: MSG.OPEN_MANAGER });
        },
      }),
    );
    return;
  }

  if (!candidates.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'Nothing for this site.';
    list.append(p);
    return;
  }

  for (const c of candidates) {
    list.append(
      row({
        title: c.title || '(untitled)',
        sub: kind === 'address' ? c.summary : c.username,
        onPick: async () => {
          await browser.runtime.sendMessage({ type: MSG.CHOOSE, sessionId, recordId: c.id });
        },
      }),
    );
  }

  if (kind === 'login') {
    list.append(
      row({
        title: 'Generate a password',
        className: 'gen',
        onPick: async () => {
          await browser.runtime.sendMessage({ type: MSG.GENERATE, sessionId });
        },
      }),
    );
  }

  // Keyboard first: the menu opens under a field someone is typing in.
  list.querySelector('button')?.focus();
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && sessionId) {
    browser.runtime.sendMessage({ type: MSG.CLOSE, sessionId });
  }
});

window.addEventListener('message', (event) => {
  // Checked by source, NOT by origin. The sender is the content script, which
  // posts from the page's context — so event.origin is the page's origin, never
  // this extension's. Comparing them dropped every message including the real
  // one, and the menu came up empty.
  //
  // Not a weakening: the page can already post here, but the payload is an
  // opaque 128-bit id that the background validates against a session it
  // created. A guess fails; the value is never trusted on its face.
  if (event.source !== window.parent) return;

  const data = event.data;
  if (!data || data.bencpass !== 'session') return;

  const id = String(data.sessionId ?? '').slice(0, 64);
  if (!id || id === sessionId) return;

  // Deliberately not locked to the first message: a page that posted a junk id
  // first would otherwise block the real one behind it.
  sessionId = id;
  render();
});
