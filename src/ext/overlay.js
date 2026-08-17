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
        sub: 'Or press Alt+Shift+B for the sidebar',
        className: 'gen',
        onPick: async () => {
          // A tab, and deliberately not the sidebar or the toolbar popup.
          // Both were tried and both are closed to this document:
          //
          //   sidebarAction        not exposed to an extension page framed
          //                        inside a web page — the API is simply absent
          //   sidebarAction, from  "may only be called from a user input
          //   the background       handler", and a message handler has none
          //   browserAction        no button to anchor to when the chrome is
          //   .openPopup()         hidden; resolves and shows nothing
          //
          // No context has both the API and a gesture — from here. A keyboard
          // command does have one, and Firefox reserves the command name
          // `_execute_sidebar_action` for exactly this, opening the sidebar
          // itself with no API call to refuse. That is in the manifest, bound
          // to Alt+Shift+B, and is the way to get a sidebar rather than a tab.
          //
          // This row cannot press it for you, so it opens the manager. The
          // background closes that tab again once the vault opens and returns
          // to this page.
          //
          // Still not a password box in the page: see the note above.
          // One thing not yet actually measured: whether this document even
          // has browserAction. sidebarAction turned out to be absent here
          // rather than merely refusing, and the two were never told apart for
          // openPopup — it was assumed to be failing for want of a toolbar to
          // anchor to. If the popup does open, it is the better landing: it
          // unlocks in place and carries its own Sidebar button.
          let popup = 'unavailable';
          try {
            if (browser.browserAction?.openPopup) {
              await browser.browserAction.openPopup();
              popup = 'opened';
            }
          } catch (err) {
            popup = `refused: ${err?.message ?? err}`;
          }

          await browser.runtime.sendMessage({
            type: MSG.OPEN_MANAGER,
            popup,
            needsTab: popup !== 'opened',
          });
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
