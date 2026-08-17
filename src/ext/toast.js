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

const close = () => window.parent.postMessage({ bencpass: 'toast-close' }, '*');

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
  $('dismiss').textContent = 'Close';
  setTimeout(close, 1400);
});

$('dismiss').addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: MSG.DISCARD, noticeId });
  close();
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
  noticeId = String(event.data.noticeId ?? '');
  render();
});
