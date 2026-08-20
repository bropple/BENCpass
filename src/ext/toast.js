// The save prompt that appears in the corner of the page.
//
// A separate document on the extension's own origin, framed into the page — the
// same arrangement as the menu, for the same reasons. The page can cover it or
// remove it, but it cannot read it and cannot synthesise a click this document
// would believe.
//
// It holds no secret. The credential it is offering to save is already in the
// page's own form, and the address likewise; this document is told only what to
// print. Pressing Save sends an id back and the background does the writing.

import { MSG } from './protocol.js';

// The notice id arrives by postMessage from the content script that framed this
// document, never in the URL — the iframe element lives in the page's DOM, so
// anything in its src is readable by the page. With the id in hand a page could
// frame its own copy of this document (it is web-accessible) and save a pending
// capture without anyone agreeing to it. Small harm, since the page supplied
// the credential in the first place, but writing to the vault should take a
// person saying so.
let noticeId = null;

const $ = (id) => document.getElementById(id);

/** A sentence with one emphasised part, built without innerHTML. */
function say(before, strong, after) {
  const p = $('text');
  p.replaceChildren();
  p.append(document.createTextNode(before));
  if (strong) {
    const b = document.createElement('b');
    b.textContent = strong;
    p.append(b);
  }
  if (after) p.append(document.createTextNode(after));
}

async function render() {
  const n = await browser.runtime.sendMessage({ type: MSG.NOTICE_STATE, noticeId });
  if (!n?.kind) {
    // Saved or dismissed from somewhere else — the popup, or another tab.
    close();
    return;
  }

  if (n.kind === 'address') {
    say('Keep this address?', n.summary ? ` ${n.summary}` : '');
    $('name-row').hidden = false;
    $('name').value = n.suggestedName ?? '';
    $('name').focus();
    $('name').select();
    return;
  }

  if (n.update) say('Update the password for ', n.username || 'this login', ` on ${n.host}?`);
  else say('Save ', n.username || 'this login', ` for ${n.host}?`);
  $('save').focus();
}

// Where the page that framed this document lives, learned from the message
// that handed over the notice id — the content script posts from the page's
// context, so that message's origin is the page's own.
//
// Kept so the close can be addressed rather than broadcast. It carries no
// secret, and a page that framed this document already knows it did, so '*'
// disclosed nothing; but a wildcard postMessage in a password manager is a
// thing a reader has to stop and reason about, and not having one is cheaper
// than explaining it. Sandboxed and about:blank parents report the opaque
// origin "null", which is not a valid target, so those fall back to '*'.
let parentOrigin = '*';

// The value is the page's own origin in every case but an opaque one, and the
// payload is the constant above. The scanner cannot see either and flags the
// fallback, so it is silenced here — on this line, with its reason beside it —
// rather than by dropping the rule for the whole repository.
// nosemgrep: javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration
const close = () => window.parent.postMessage({ bencpass: 'toast-close' }, parentOrigin);

$('save').addEventListener('click', async () => {
  const reply = await browser.runtime.sendMessage({
    type: MSG.SAVE,
    noticeId,
    title: $('name').value.trim(),
  });
  // Say so before going, rather than vanishing and leaving it ambiguous whether
  // anything was written.
  say(reply?.ok ? (reply.merged ? 'Updated.' : 'Saved.') : 'Could not save.');
  $('name-row').hidden = true;
  $('save').hidden = true;
  $('never').hidden = true;
  $('dismiss').textContent = 'Close';
  setTimeout(close, 1400);
});

$('dismiss').addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: MSG.DISCARD, noticeId });
  close();
});

$('never').addEventListener('click', async () => {
  const reply = await browser.runtime.sendMessage({ type: MSG.NEVER, noticeId });
  // Say what actually happened before going: the person may be on a subdomain
  // of the site they just silenced, and this is the one moment to say which
  // site that was and that it can be undone. A silent close here would make
  // the next unprompted sign-in on this site read as breakage.
  say(
    reply?.ok
      ? `BENCpass will stop offering to save for ${reply.site || 'this site'}. Undo under the gear in Settings → Filling.`
      : 'Could not do that.',
  );
  $('name-row').hidden = true;
  $('save').hidden = true;
  $('never').hidden = true;
  $('dismiss').textContent = 'Close';
  setTimeout(close, 3500);
});

// Escape closes it, the way any dismissible thing should.
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') close();
});

// Same check as the overlay: the sender is the content script, which posts from
// the *page's* origin, so comparing origins would reject every message. What
// matters is that it came from the frame that embedded this one.
window.addEventListener('message', (event) => {
  if (event.source !== window.parent) return;
  if (event.data?.bencpass !== 'notice' || noticeId) return;
  if (event.origin && event.origin !== 'null') parentOrigin = event.origin;
  noticeId = String(event.data.noticeId ?? '');
  render();
});
