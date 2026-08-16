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
  state = await send({ type: MSG.STATE });

  $('locked').hidden = !state.locked;
  $('unlocked').hidden = state.locked;
  $('no-vault').hidden = state.hasVault;

  if (state.locked) {
    $('pw').focus();
    return;
  }

  $('host').textContent = state.host || 'no site';
  renderCapture();
  renderList(state.candidates);
}

function renderCapture() {
  const p = state.pending;
  $('capture').hidden = !p;
  if (!p) return;
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
  const reply = await send({ type: MSG.SAVE });
  say(reply?.ok ? 'Saved.' : 'Could not save.');
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

$('manage-btn').addEventListener('click', () => {
  browser.runtime.openOptionsPage();
  window.close();
});

refresh();
