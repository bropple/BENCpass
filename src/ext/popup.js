// The toolbar dropdown.
//
// Holds no state of its own — it asks the background for a picture of the world
// each time it opens, because a popup is destroyed and rebuilt on every click
// and anything it remembered would be a stale copy of the vault.

import { MSG } from './protocol.js';

const $ = (id) => document.getElementById(id);
const send = (msg) => browser.runtime.sendMessage(msg);

let state = null;

async function refresh() {
  try {
    state = await send({ type: MSG.STATE });
  } catch (err) {
    // Almost always the background page having failed to load. Both panels
    // start hidden, so without this the popup is an empty rectangle that says
    // nothing about what went wrong or where to look.
    $('fatal').textContent =
      'BENCpass background page is not responding. Open about:debugging -> This Firefox -> BENCpass -> Inspect to see why.';
    $('fatal').hidden = false;
    return;
  }
  if (!state) return;

  $('fatal').hidden = true;
  $('locked').hidden = !state.locked;
  $('unlocked').hidden = state.locked;

  // With no vault there is nothing to unlock, so the form is replaced rather
  // than merely annotated — a password box above the words "no vault on this
  // machine" is a question with no answer.
  $('no-vault').hidden = state.hasVault;
  $('unlock-form').hidden = !state.hasVault;

  if (state.locked) {
    if (state.hasVault) renderLocked();
    return;
  }

  $('host').textContent = state.host || 'no site';
  renderCapture();
  renderList(state.candidates);
}

// ---- unlocking --------------------------------------------------------------
//
// A fingerprint that has been enrolled is the way in, not one of two equal
// options. Enrolment already cost the master password once; being asked for it
// again every time afterwards is the thing the fingerprint was meant to spare
// you, and it is what "I still have to type my password" means.

const bioName = (kind) =>
  kind === 'touchid' ? 'Touch ID' : kind === 'hello' ? 'Windows Hello' : 'your fingerprint';

// Only ever raised once per opening of this popup. A prompt that reappears the
// instant it is dismissed cannot be dismissed.
let promptedThisOpen = false;

function renderLocked() {
  const bio = state.bio ?? {};
  const usable = Boolean(bio.available && bio.enrolled);

  $('bio-unlock').hidden = !usable;
  $('unlock-form').hidden = usable && !showPasswordBox;

  if (!usable || showPasswordBox) {
    $('pw').focus();
  }
  if (!usable) return;

  $('bio-text').textContent = `Unlock with ${bioName(bio.biometrics)}.`;
  $('bio-retry').textContent = `Unlock with ${bioName(bio.biometrics)}`;

  if (!promptedThisOpen) {
    promptedThisOpen = true;
    unlockWithBiometrics();
  }
}

let showPasswordBox = false;

async function unlockWithBiometrics() {
  $('bio-text').textContent = 'Waiting for you…';
  const reply = await send({ type: MSG.BIO_UNLOCK });
  if (reply?.ok) {
    await refresh();
    return;
  }

  // Cancelling is a decision, not a fault. Offer the password rather than
  // scolding, and do not raise the prompt again unasked.
  if (reply?.reason === 'cancelled') {
    $('bio-text').textContent = 'Cancelled.';
    return;
  }
  if (reply?.reason === 'stale-secret') {
    $('bio-text').textContent =
      'That no longer matches this vault, so it has been turned off. Use your master password.';
    showPasswordBox = true;
    renderLocked();
    return;
  }
  $('bio-text').textContent = 'Not available just now.';
  showPasswordBox = true;
  renderLocked();
}

$('bio-retry').addEventListener('click', unlockWithBiometrics);

$('use-password').addEventListener('click', () => {
  showPasswordBox = true;
  renderLocked();
});

function renderCapture() {
  const p = state.pending;
  $('capture').hidden = !p;
  $('capture-name-row').hidden = !p || p.kind !== 'address';
  if (!p) return;

  // An address is not filed under the site it was typed into. It belongs to the
  // person, gets a name they choose, and is then offered on every checkout —
  // which is the whole difference between an address and a login.
  if (p.kind === 'address') {
    $('capture-text').textContent = p.summary
      ? `Keep this address? (${p.summary})`
      : 'Keep this address?';
    $('capture-name').value = p.suggestedName ?? '';
    return;
  }

  $('capture-text').textContent = p.update
    ? `Update the password for ${p.username || 'this login'} on ${p.host}?`
    : `Save ${p.username || 'this login'} for ${p.host}?`;
}

function row(c) {
  const b = document.createElement('button');
  b.className = 'row';
  b.type = 'button';

  const t = document.createElement('span');
  t.className = 't';
  t.textContent = c.title || '(untitled)';

  const s = document.createElement('span');
  s.className = 's';
  s.textContent = c.username || c.summary || '';

  b.append(t, s);
  b.addEventListener('click', async () => {
    // No origin is passed. The background resolves the active tab itself, so a
    // popup cannot ask for a credential to be typed into a page of its choosing.
    const reply = await send({ type: MSG.CHOOSE, recordId: c.id, active: true });
    if (reply?.ok) window.close();
    else say(reason(reply?.reason));
  });
  return b;
}

function renderList(candidates) {
  const list = $('list');
  list.replaceChildren(...candidates.map(row));
  $('empty').hidden = candidates.length > 0;
  $('empty').textContent = $('search').value.trim()
    ? 'Nothing matches.'
    : 'Nothing for this site.';
}

const reason = (r) =>
  ({
    'origin-mismatch': 'That entry is for a different site.',
    'cross-origin-frame': 'That form belongs to another site.',
    'insecure-page': 'This page is not encrypted.',
    locked: 'Vault is locked.',
    'no-tab': 'No page to fill.',
  })[r] ?? 'Could not fill.';

let sayTimer;
function say(text) {
  $('status').textContent = text;
  clearTimeout(sayTimer);
  sayTimer = setTimeout(() => ($('status').textContent = ''), 4000);
}

// ---- events ---------------------------------------------------------------

$('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('unlock-btn');
  btn.disabled = true;
  btn.textContent = 'Deriving key';
  $('unlock-error').hidden = true;

  const reply = await send({ type: MSG.UNLOCK, password: $('pw').value });
  $('pw').value = '';
  btn.disabled = false;
  btn.textContent = 'Unlock';

  if (reply?.ok) {
    $('visor').setAttribute('fill', '#78b946');
    await refresh();
  } else {
    $('unlock-error').textContent =
      reply?.reason === 'no-vault'
        ? 'No vault here yet — open the manager to create one.'
        : 'Wrong password, or this vault is damaged.';
    $('unlock-error').hidden = false;
  }
});

$('lock-btn').addEventListener('click', async () => {
  await send({ type: MSG.LOCK });
  await refresh();
});

$('search').addEventListener('input', async () => {
  const q = $('search').value.trim();
  if (!q) return renderList(state.candidates);
  const reply = await send({ type: MSG.SEARCH, query: q });
  renderList(reply?.results ?? []);
});

$('save-btn').addEventListener('click', async () => {
  const reply = await send({ type: MSG.SAVE, title: $('capture-name').value.trim() });
  say(reply?.ok ? (reply.merged ? 'Updated.' : 'Saved.') : 'Could not save.');
  await refresh();
});

$('discard-btn').addEventListener('click', async () => {
  await send({ type: MSG.DISCARD });
  await refresh();
});

$('sync-btn').addEventListener('click', async () => {
  say('Syncing…');
  const reply = await send({ type: MSG.SYNC });
  if (!reply?.ok) {
    say(reply?.reason === 'not-configured' ? 'No server set.' : `Sync failed: ${reply?.reason}`);
    return;
  }
  say(
    reply.conflicts
      ? `${reply.conflicts} conflict${reply.conflicts === 1 ? '' : 's'} — open the manager`
      : `Synced (${reply.pulled} in, ${reply.pushed} out)`,
  );
  await refresh();
});

function openManager() {
  browser.runtime.openOptionsPage();
  window.close();
}

$('manage-btn').addEventListener('click', openManager);
$('create-btn').addEventListener('click', openManager);

// The sidebar is easy to close and, in Zen, not obvious to reopen — there is no
// menu entry where a Firefox user would look for one. Opening it needs a user
// gesture, which this click is.
$('sidebar-btn').addEventListener('click', async () => {
  try {
    await browser.sidebarAction.open();
    window.close();
  } catch {
    say('Could not open the sidebar.');
  }
});

refresh();

// Shown in the footer so "am I running the build I just installed?" has an
// answer that does not involve reading files off disk.
$('version').textContent = `v${browser.runtime.getManifest().version}`;
