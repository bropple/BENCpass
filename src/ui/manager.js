// BENCpass manager UI.
//
// Holds no secret of its own: everything readable comes out of an unlocked
// Vault and goes back into the DOM, and lock() drops both at once. If this file
// ever needs to remember a password between two functions, something upstream
// is wrong.

import { Vault } from '../core/vault.js';
import { pickStorage } from '../core/storage.js';
import { generate, entropyBits } from '../core/generate.js';

const $ = (id) => document.getElementById(id);

const store = pickStorage();

const state = {
  vault: null,
  selected: null,
  editing: null, // null | 'new' | <id>
  revealed: false, // the detail view's password
  editRevealed: false, // the editor's password field
};

// ---- timers ----------------------------------------------------------------

const AUTOLOCK_MS = 15 * 60 * 1000;
const CLIPBOARD_MS = 30 * 1000;

// A revealed password re-hides on the same schedule as the clipboard clears.
// Auto-lock is fifteen minutes away, which is a long time for a password to sit
// on a screen someone has walked away from.
const REVEAL_MS = 30 * 1000;

let autolockAt = 0;
let clipboardTimer = null;
let revealTimer = null;

function bumpAutolock() {
  autolockAt = Date.now() + AUTOLOCK_MS;
}

setInterval(() => {
  if (!state.vault || state.vault.locked) return;
  const left = autolockAt - Date.now();
  if (left <= 0) return lock('Auto-locked.');
  $('foot-lock').textContent = `auto-lock in ${Math.ceil(left / 60000)}m`;
}, 1000);

// ---- boot ------------------------------------------------------------------

async function boot() {
  const persisted = await store.read();
  if (persisted) {
    state.vault = Vault.load(persisted);
    setGate('unlock');
  } else {
    setGate('setup');
  }
}

function setGate(mode) {
  const setup = mode === 'setup';
  $('gate-confirm-field').hidden = !setup;
  $('gate-pw2').required = setup;
  $('gate-go').textContent = setup ? 'Create vault' : 'Unlock';
  $('gate-hint').textContent = setup ? 'No vault on this machine.' : 'Locked.';
  $('gate-note').textContent = setup
    ? 'The master password is not recoverable. Nothing here, and nothing on the server, can open the vault without it.'
    : '';
  $('gate-pw').autocomplete = setup ? 'new-password' : 'current-password';
  $('gate').dataset.mode = mode;
  $('gate-pw').focus();
}

// ---- gate ------------------------------------------------------------------

$('gate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('gate-pw').value;
  const err = $('gate-error');
  err.hidden = true;

  const btn = $('gate-go');
  const label = btn.textContent;
  // Argon2 at 128 MiB blocks this thread for ~400 ms. Say so rather than
  // letting the button look dead — but say it flatly.
  btn.disabled = true;
  btn.textContent = 'Deriving key';
  await new Promise((r) => setTimeout(r, 0));

  try {
    if ($('gate').dataset.mode === 'setup') {
      if (pw !== $('gate-pw2').value) throw new Error('The two entries do not match.');
      if (pw.length < 8) throw new Error('Use at least 8 characters.');
      state.vault = await Vault.create({ password: pw });
      await persist();
    } else {
      await state.vault.unlock(pw);
    }
    enterApp();
  } catch (ex) {
    // The one deliberately ambiguous message in the app. It stays ambiguous —
    // saying which of the two it was would tell someone holding the file
    // whether a guess was close.
    err.textContent =
      ex.code === 'unwrap-failed'
        ? 'Wrong password, or this vault is damaged.'
        : ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = label;
    $('gate-pw').value = '';
    $('gate-pw2').value = '';
  }
});

function enterApp() {
  $('visor').setAttribute('fill', 'var(--good)');
  $('gate').hidden = true;
  $('app').hidden = false;
  bumpAutolock();
  render();
  $('search').focus();
}

function lock(why = '') {
  state.vault?.lock();
  state.selected = null;
  state.editing = null;
  clearTimeout(revealTimer);
  state.revealed = false;
  state.editRevealed = false;

  // Clear the DOM as well as the vault. A locked vault with the last password
  // still sitting in a span is not locked.
  $('list').replaceChildren();
  $('d-password').textContent = '';
  $('d-username').textContent = '';
  $('d-notes').textContent = '';
  $('e-password').value = '';
  $('search').value = '';

  $('app').hidden = true;
  $('gate').hidden = false;
  $('visor').setAttribute('fill', 'var(--bad)');
  $('gate-hint').textContent = why || 'Locked.';
  $('gate-pw').focus();
}

$('lock-btn').addEventListener('click', () => lock());
for (const ev of ['keydown', 'pointerdown']) {
  document.addEventListener(ev, bumpAutolock, { passive: true });
}

// ---- persistence -----------------------------------------------------------

const persist = () => store.write(state.vault.toJSON());

// ---- rendering -------------------------------------------------------------

function render() {
  renderList();
  renderDetail();
  const n = state.vault.list().length;
  $('foot-count').textContent = `${n} ${n === 1 ? 'entry' : 'entries'}`;
}

function renderList() {
  const items = state.vault
    .search($('search').value)
    .sort((a, b) => (a.title || '').localeCompare(b.title || ''));

  $('list-empty').hidden = items.length > 0;
  $('list-empty').textContent = $('search').value.trim()
    ? 'Nothing matches.'
    : 'No entries.';

  $('list').replaceChildren(
    ...items.map((r) => {
      const li = document.createElement('li');
      li.setAttribute('aria-selected', String(r.id === state.selected));
      li.tabIndex = 0;

      const title = document.createElement('span');
      title.className = 'li-title';
      title.textContent = r.title || '(untitled)';

      const sub = document.createElement('span');
      sub.className = 'li-sub';
      sub.textContent = r.username || host(r.urls?.[0]) || '—';

      li.append(title, sub);
      li.addEventListener('click', () => select(r.id));
      li.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(r.id); }
      });
      return li;
    }),
  );
}

function select(id) {
  state.selected = id;
  state.editing = null;
  // Revealing one entry must not carry over to the next one clicked.
  clearTimeout(revealTimer);
  state.revealed = false;
  state.editRevealed = false;
  render();
}

function renderDetail() {
  const editing = state.editing !== null;
  const r = state.selected ? state.vault.get(state.selected) : null;

  $('edit-form').hidden = !editing;
  $('detail-view').hidden = editing || !r;
  $('detail-empty').hidden = editing || !!r;

  if (editing || !r) return;

  $('d-title').textContent = r.title || '(untitled)';
  $('d-username').textContent = r.username || '—';
  $('d-password').textContent = state.revealed ? r.password : '•'.repeat(12);
  $('reveal-btn').textContent = state.revealed ? 'Hide' : 'Reveal';

  $('d-urls-row').hidden = !r.urls?.length;
  $('d-urls').textContent = (r.urls ?? []).join('\n');
  $('d-notes-row').hidden = !r.notes;
  $('d-notes').textContent = r.notes ?? '';

  renderMeta(r);
}

function renderMeta(r) {
  const dl = $('d-meta');
  dl.replaceChildren();

  const add = (term, node) => {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    if (typeof node === 'string') dd.textContent = node;
    else dd.append(node);
    dl.append(dt, dd);
  };

  add('Created', date(r.created));

  // The whole reason `passwordChanged` is kept separate from `updated`: only
  // this can answer the question, and only if renaming an entry never touched it.
  const days = Math.floor((Date.now() - r.passwordChanged) / 86_400_000);
  const age = document.createElement('span');
  age.textContent = `${date(r.passwordChanged)} (${days} ${days === 1 ? 'day' : 'days'})`;
  age.className = days > 1095 ? 'age-bad' : days > 365 ? 'age-warn' : 'age-good';
  add('Password set', age);

  add('Last used', r.lastUsed ? `${date(r.lastUsed)} (${r.timesUsed}×)` : 'never');

  if (r.history?.length) add('Previous', `${r.history.length} kept`);

  // Reuse is checked across the whole vault, not against a breach list — no
  // network call, and nothing leaves the machine to find it out.
  const shared = state.vault
    .list()
    .filter((o) => o.id !== r.id && o.password && o.password === r.password);
  if (shared.length) {
    const warn = document.createElement('span');
    warn.className = 'age-warn';
    warn.textContent = `also on ${shared.map((o) => o.title || '(untitled)').join(', ')}`;
    add('Reused', warn);
  }

  if (r.claimedTime) {
    const note = document.createElement('span');
    note.className = 'age-warn';
    note.textContent = `source claimed ${date(r.claimedTime)}`;
    add('Imported', note);
  }
}

const date = (ms) => new Date(ms).toISOString().slice(0, 10);

function host(url) {
  try { return new URL(url).host; } catch { return url ?? ''; }
}

// ---- search ----------------------------------------------------------------

$('search').addEventListener('input', renderList);

// ---- copying ---------------------------------------------------------------

for (const btn of document.querySelectorAll('[data-copy]')) {
  btn.addEventListener('click', () => copy(btn.dataset.copy));
}

async function copy(field) {
  const r = state.vault.get(state.selected);
  if (!r?.[field]) return;

  try {
    await navigator.clipboard.writeText(r[field]);
  } catch {
    say('Clipboard refused.');
    return;
  }

  if (field === 'password') {
    state.vault.touchUsed(state.selected).then(persist).then(render);
  }

  say(`${field} copied — clears in ${CLIPBOARD_MS / 1000}s`);

  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(async () => {
    // Best effort, and worth being honest about: a clipboard manager has
    // already taken a copy by now, and this cannot reach into one.
    try { await navigator.clipboard.writeText(''); } catch { /* not focused */ }
    say('Clipboard cleared.');
  }, CLIPBOARD_MS);
}

let sayTimer = null;
function say(msg) {
  $('status').textContent = msg;
  clearTimeout(sayTimer);
  sayTimer = setTimeout(() => { $('status').textContent = ''; }, 4000);
}

// ---- reveal / edit / delete ------------------------------------------------

/** Put the editor's field into whatever state.editRevealed says. */
function applyEditMask() {
  $('e-password').type = state.editRevealed ? 'text' : 'password';
  $('e-reveal-btn').textContent = state.editRevealed ? 'Hide' : 'Show';
}

function hideSecrets(note) {
  clearTimeout(revealTimer);
  revealTimer = null;
  state.revealed = false;
  state.editRevealed = false;
  applyEditMask();
  renderDetail();
  if (note) say(note);
}

/** Restart the countdown whenever something is newly shown. */
function armRevealTimer() {
  clearTimeout(revealTimer);
  revealTimer = setTimeout(() => hideSecrets('Password hidden.'), REVEAL_MS);
}

$('reveal-btn').addEventListener('click', () => {
  state.revealed = !state.revealed;
  if (state.revealed) armRevealTimer();
  else hideSecrets();
  renderDetail();
});

$('e-reveal-btn').addEventListener('click', () => {
  state.editRevealed = !state.editRevealed;
  applyEditMask();
  if (state.editRevealed) armRevealTimer();
  else clearTimeout(revealTimer);
});

$('new-btn').addEventListener('click', () => openEditor('new'));
$('edit-btn').addEventListener('click', () => openEditor(state.selected));
$('cancel-btn').addEventListener('click', () => { state.editing = null; render(); });

function openEditor(which) {
  state.editing = which;
  const r = which === 'new' ? null : state.vault.get(which);

  $('edit-heading').textContent = r ? 'Edit entry' : 'New entry';
  $('e-title').value = r?.title ?? '';
  $('e-username').value = r?.username ?? '';
  $('e-password').value = r?.password ?? '';
  $('e-urls').value = (r?.urls ?? []).join('\n');
  $('e-notes').value = r?.notes ?? '';

  // Opening the editor never puts an existing password on screen by itself.
  clearTimeout(revealTimer);
  state.editRevealed = false;
  applyEditMask();

  render();
  $('e-title').focus();
}

$('edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fields = {
    title: $('e-title').value.trim(),
    username: $('e-username').value,
    password: $('e-password').value,
    urls: $('e-urls').value.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
    notes: $('e-notes').value,
  };

  if (state.editing === 'new') {
    state.selected = await state.vault.add(fields);
  } else {
    await state.vault.update(state.editing, fields);
  }

  state.editing = null;
  await persist();
  render();
});

$('delete-btn').addEventListener('click', async () => {
  const r = state.vault.get(state.selected);
  if (!r) return;
  // A tombstone still syncs, and the server keeps snapshots — but a person
  // deserves the question anyway.
  if (!confirm(`Delete "${r.title || '(untitled)'}"?`)) return;
  await state.vault.remove(state.selected);
  state.selected = null;
  await persist();
  render();
});

// ---- generator -------------------------------------------------------------

const genOpts = () => ({
  length: Number($('g-length').value),
  lower: $('g-lower').checked,
  upper: $('g-upper').checked,
  digits: $('g-digits').checked,
  symbols: $('g-symbols').checked,
  avoidAmbiguous: $('g-ambig').checked,
});

function renderEntropy() {
  $('g-length-out').textContent = $('g-length').value;
  try {
    const bits = entropyBits(genOpts());
    $('g-entropy').textContent = `${bits.toFixed(0)} bits of entropy`;
  } catch {
    $('g-entropy').textContent = 'select at least one character set';
  }
}

for (const id of ['g-length', 'g-lower', 'g-upper', 'g-digits', 'g-symbols', 'g-ambig']) {
  $(id).addEventListener('input', renderEntropy);
}

$('gen-btn').addEventListener('click', () => {
  try {
    $('e-password').value = generate(genOpts());
    // Unmask on generate — the point of generating is to see the result — but
    // put it on the same countdown as everything else.
    state.editRevealed = true;
    applyEditMask();
    armRevealTimer();
  } catch (ex) {
    say(ex.message);
  }
});

renderEntropy();
boot();
