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

/**
 * Where the vault lives.
 *
 * Inside the extension there must be exactly one — the background page's. A
 * second instance here would have its own key and its own lock, so unlocking
 * the manager would leave autofill still locked, and saving in one would not be
 * visible to the other until a reload. Outside the extension (the preview
 * harness, a plain file) the page owns a local one.
 */
let vaultHost = null;

async function makeVaultHost() {
  const inExtension = Boolean(globalThis.browser?.runtime?.id);
  const bg = await globalThis.browser?.runtime?.getBackgroundPage?.().catch(() => null);

  // Inside the extension the background page is the only legitimate owner of a
  // vault. Falling back to a local one here is not a graceful degradation, it
  // is a second vault with its own key and its own lock — and it is what turned
  // a dead background page into a page calmly offering to create a new vault.
  if (inExtension && !bg?.bencpass) {
    throw new Error(
      'The BENCpass background page is not running, so the vault cannot be reached. ' +
        'Open about:debugging -> This Firefox -> BENCpass -> Inspect to see why.',
    );
  }

  if (bg?.bencpass) {
    return {
      shared: true,
      get vault() {
        return bg.bencpass.vault;
      },
      get autolockAt() {
        return bg.bencpass.autolockAt;
      },
      bump: () => bg.bencpass.bump(),
      setVault: (v) => bg.bencpass.setVault(v),
      persist: () => bg.bencpass.persistVault(),
      sync: () => bg.bencpass.sync(),
      lock: () => bg.bencpass.lock(),
    };
  }

  const store = pickStorage();
  let local = null;
  const raw = await store.read();
  if (raw) local = Vault.load(raw);
  return {
    shared: false,
    get vault() {
      return local;
    },
    get autolockAt() {
      return localAutolockAt;
    },
    bump: () => {
      localAutolockAt = Date.now() + AUTOLOCK_MS;
    },
    setVault: (v) => {
      local = v;
    },
    persist: () => store.write(local.toJSON()),
    sync: async () => ({ ok: false, reason: 'not-configured' }),
    lock: () => local?.lock(),
  };
}

/**
 * The address fields, in the order a person fills a form.
 *
 * Keys are the WHATWG autofill tokens, the same ones the record stores and the
 * fill code looks up — so this list is the only place the field set is written
 * down for the UI, and it cannot drift from the model.
 */
const ADDRESS_FIELDS = [
  ['name', 'Full name'],
  ['organization', 'Company'],
  ['address-line1', 'Address'],
  ['address-line2', 'Address line 2'],
  ['address-level2', 'City'],
  ['address-level1', 'State / Province'],
  ['postal-code', 'Postcode'],
  ['country', 'Country (ISO code)'],
  ['tel', 'Phone'],
  ['email', 'Email'],
];

const state = {
  vault: null,
  section: 'login', // which of the two lists is on screen
  editingType: 'login',
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

let localAutolockAt = 0; // only used when this page owns the vault
let clipboardTimer = null;
let revealTimer = null;

const bumpAutolock = () => vaultHost?.bump();

// Displays the countdown; only locks when this page is the vault's owner.
//
// Inside the extension the background owns both the vault and the timer, and
// this page must not run one of its own — every manager page shares that one
// vault, so the earliest timer among them decided for all of them, and a page
// left sitting on the gate had never started its clock at all.
setInterval(() => {
  if (!vaultHost || !state.vault || state.vault.locked) return;

  const at = vaultHost.autolockAt;
  if (!at) return;

  const left = at - Date.now();
  if (left <= 0) {
    if (!vaultHost.shared) lock('Auto-locked.');
    return;
  }
  $('foot-lock').textContent = `auto-lock in ${Math.ceil(left / 60000)}m`;
}, 1000);

// ---- boot ------------------------------------------------------------------

async function boot() {
  try {
    vaultHost = await makeVaultHost();
  } catch (err) {
    $('gate-hint').textContent = 'Not available.';
    $('gate-error').textContent = err.message;
    $('gate-error').hidden = false;
    $('gate-form').hidden = true;
    return;
  }
  state.vault = vaultHost.vault;

  if (!state.vault) {
    setGate('setup');
    return;
  }
  // The background may already be unlocked from the popup, in which case the
  // gate would be asking for a password that is not needed.
  if (!state.vault.locked) {
    enterApp();
    return;
  }
  setGate('unlock');
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
      vaultHost.setVault(state.vault);
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
  // Tell the background the vault is open. If this page was opened purely to
  // unlock — from the menu on a login form — it closes itself and puts the
  // person back where they were, rather than stranding them in a tab they did
  // not ask for.
  if (vaultHost?.shared) {
    globalThis.browser?.runtime?.sendMessage({ type: 'unlocked' }).catch(() => {});
  }

  $('visor').setAttribute('fill', 'var(--good)');
  $('gate').hidden = true;
  $('app').hidden = false;
  bumpAutolock();
  render();
  $('search').focus();
}

function lock(why = '') {
  vaultHost?.lock();
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

const persist = () => vaultHost.persist();

// ---- rendering -------------------------------------------------------------

function render() {
  renderList();
  renderDetail();
  const n = state.vault.list(state.section).length;
  const noun = state.section === 'address' ? 'address' : 'entry';
  const plural = state.section === 'address' ? 'addresses' : 'entries';
  $('foot-count').textContent = `${n} ${n === 1 ? noun : plural}`;
}

function renderList() {
  const items = state.vault
    .search($('search').value, state.section)
    .sort((a, b) => (a.title || '').localeCompare(b.title || ''));

  $('list-empty').hidden = items.length > 0;
  $('list-empty').textContent = $('search').value.trim()
    ? 'Nothing matches.'
    : state.section === 'address'
      ? 'No addresses.'
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
      sub.textContent =
        r.type === 'address'
          ? [r['address-line1'], r['address-level2']].filter(Boolean).join(', ') || '—'
          : r.username || host(r.urls?.[0]) || '—';

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

  const isAddress = r.type === 'address';
  $('d-login').hidden = isAddress;
  $('d-address').hidden = !isAddress;

  if (isAddress) {
    renderAddressDetail(r);
    renderMeta(r);
    return;
  }

  $('d-username').textContent = r.username || '—';
  $('d-password').textContent = state.revealed ? r.password : '•'.repeat(12);
  $('reveal-btn').textContent = state.revealed ? 'Hide' : 'Reveal';

  $('d-urls-row').hidden = !r.urls?.length;
  $('d-urls').textContent = (r.urls ?? []).join('\n');
  $('d-notes-row').hidden = !r.notes;
  $('d-notes').textContent = r.notes ?? '';

  renderMeta(r);
}

function renderAddressDetail(r) {
  const box = $('d-address');
  box.replaceChildren();

  for (const [key, label] of ADDRESS_FIELDS) {
    if (!r[key]) continue;
    const row = document.createElement('div');
    row.className = 'row';

    const name = document.createElement('span');
    name.className = 'label';
    name.textContent = label;

    const value = document.createElement('span');
    value.className = 'value';
    value.textContent = r[key];

    const copy = document.createElement('button');
    copy.className = 'btn btn-sm';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => copyText(r[key], label));

    row.append(name, value, copy);
    box.append(row);
  }

  if (r.notes) {
    const row = document.createElement('div');
    row.className = 'row';
    const name = document.createElement('span');
    name.className = 'label';
    name.textContent = 'Notes';
    const value = document.createElement('span');
    value.className = 'value wrap';
    value.textContent = r.notes;
    row.append(name, value);
    box.append(row);
  }
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

  if (r.type === 'address') {
    add('Updated', date(r.updated));
    if (r.claimedTime) {
      const note = document.createElement('span');
      note.className = 'age-warn';
      note.textContent = `source claimed ${date(r.claimedTime)}`;
      add('Imported', note);
    }
    return;
  }

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

for (const btn of document.querySelectorAll('.seg-btn')) {
  btn.addEventListener('click', () => {
    if (state.section === btn.dataset.section) return;
    state.section = btn.dataset.section;
    state.selected = null;
    state.editing = null;
    for (const b of document.querySelectorAll('.seg-btn')) {
      b.setAttribute('aria-selected', String(b === btn));
    }
    render();
  });
}

// ---- copying ---------------------------------------------------------------

for (const btn of document.querySelectorAll('[data-copy]')) {
  btn.addEventListener('click', () => copy(btn.dataset.copy));
}

async function copy(field) {
  const r = state.vault.get(state.selected);
  if (!r?.[field]) return;
  await copyText(r[field], field, field === 'password');
}

/** Shared by the login rows and the address rows. */
async function copyText(text, label, isSecret = false) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    say('Clipboard refused.');
    return;
  }

  if (isSecret && state.selected) {
    state.vault.touchUsed(state.selected).then(persist).then(render);
  }

  say(`${label} copied — clears in ${CLIPBOARD_MS / 1000}s`);

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
  const type = r?.type ?? state.section;
  state.editingType = type;

  const isAddress = type === 'address';
  $('e-login').hidden = isAddress;
  $('e-address').hidden = !isAddress;

  $('edit-heading').textContent = r
    ? isAddress
      ? 'Edit address'
      : 'Edit entry'
    : isAddress
      ? 'New address'
      : 'New entry';

  $('e-title').value = r?.title ?? '';
  $('e-notes').value = r?.notes ?? '';

  if (isAddress) {
    buildAddressEditor(r);
  } else {
    $('e-username').value = r?.username ?? '';
    $('e-password').value = r?.password ?? '';
    $('e-urls').value = (r?.urls ?? []).join('\n');
  }

  // Opening the editor never puts an existing password on screen by itself.
  clearTimeout(revealTimer);
  state.editRevealed = false;
  applyEditMask();

  render();
  $('e-title').focus();
}

/** The address inputs are generated from ADDRESS_FIELDS rather than written out. */
function buildAddressEditor(record) {
  const box = $('e-address');
  box.replaceChildren();

  for (const [key, label] of ADDRESS_FIELDS) {
    const wrap = document.createElement('label');
    wrap.className = 'field';

    const name = document.createElement('span');
    name.className = 'label';
    name.textContent = label;

    const input = document.createElement('input');
    input.type = key === 'email' ? 'email' : key === 'tel' ? 'tel' : 'text';
    input.dataset.addressKey = key;
    input.value = record?.[key] ?? '';
    input.autocomplete = 'off';

    wrap.append(name, input);
    box.append(wrap);
  }
}

$('edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const fields =
    state.editingType === 'address'
      ? {
          type: 'address',
          title: $('e-title').value.trim(),
          notes: $('e-notes').value,
          ...Object.fromEntries(
            [...$('e-address').querySelectorAll('[data-address-key]')].map((i) => [
              i.dataset.addressKey,
              i.value.trim(),
            ]),
          ),
        }
      : {
          type: 'login',
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
