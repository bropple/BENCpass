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
    // A fingerprint, when there is one to use. This is the row that matters:
    // meeting a locked vault at a login field is the common case, and sending
    // someone to another tab to type a master password there is precisely the
    // errand the fingerprint was enrolled to save.
    //
    // Note what is *not* being done here. The prompt belongs to the operating
    // system and is raised by the background page; this document only asks. It
    // never sees the device secret, and a page that drew a convincing imitation
    // of this row would achieve nothing but a real Touch ID prompt it cannot
    // answer.
    if (reply.bio?.available && reply.bio?.enrolled) {
      const name =
        reply.bio.biometrics === 'touchid'
          ? 'Touch ID'
          : reply.bio.biometrics === 'hello'
            ? 'Windows Hello'
            : 'your fingerprint';
      list.append(
        row({
          title: `Unlock with ${name}`,
          sub: 'Then pick an entry',
          className: 'gen',
          onPick: async () => {
            const done = await browser.runtime.sendMessage({ type: MSG.BIO_UNLOCK });
            // On success the background reopens this menu against the same
            // field, now holding entries. On a cancel there is nothing to say
            // that the person does not already know.
            if (!done?.ok && done?.reason !== 'cancelled') render();
          },
        }),
      );
    }

    // The master password, deliberately not as a box here.
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
          // A tab, and not for want of trying anything nicer. Measured, not
          // assumed:
          //
          //   sidebarAction, here          absent — the API is not exposed to
          //                                an extension page framed in a web page
          //   browserAction, here          absent, for the same reason
          //   sidebarAction, background    "may only be called from a user
          //                                input handler"
          //
          // So the page-to-chrome boundary is closed in both directions: this
          // document has no chrome APIs, and the contexts that do have no
          // gesture. No click originating in a page can open a sidebar or a
          // popup, and that is a Firefox boundary rather than a missing trick.
          //
          // What does work is a keyboard command, because Firefox handles the
          // keypress itself: `_execute_sidebar_action` is bound to Alt+Shift+B
          // in the manifest. This row cannot press a key on anyone's behalf, so
          // it opens the manager — and the background closes that tab again the
          // moment the vault opens, returning to this page.
          //
          // Still not a password box in the page: see the note above.
          await browser.runtime.sendMessage({ type: MSG.OPEN_MANAGER });
        },
      }),
    );
    return;
  }

  if (kind === 'signup') {
    $('head').textContent = 'New password';
    list.append(
      row({
        title: 'Generate a password',
        sub: '20 characters, saved when you submit',
        className: 'gen',
        onPick: () => browser.runtime.sendMessage({ type: MSG.GENERATE, sessionId }),
      }),
    );
    list.querySelector('button')?.focus();
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
