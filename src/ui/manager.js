// BENCpass manager UI.
//
// Holds no secret of its own: everything readable comes out of an unlocked
// Vault and goes back into the DOM, and lock() drops both at once. If this file
// ever needs to remember a password between two functions, something upstream
// is wrong.

import { Vault } from '../core/vault.js';
import { pickStorage } from '../core/storage.js';
import { generate, entropyBits } from '../core/generate.js';
import { ADDRESS_SCHEMA, countryOptions, countryName, splitName } from '../core/address.js';
import { MSG } from '../ext/protocol.js';
import * as webauthn from '../ext/webauthn.js';

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
 * From the model rather than written out again here: the tokens are the WHATWG
 * autofill names, and they are simultaneously the record's keys, the editor's
 * inputs and what the fill code looks up. One list, so none of the three can
 * drift from the others.
 */
const ADDRESS_FIELDS = ADDRESS_SCHEMA;

/**
 * An address as the schema expects it.
 *
 * Records written before the name was stored in parts keep a single `name`,
 * and so do addresses captured from a form that only had one box for it. The
 * split happens on the way to the screen, so nothing has to be migrated and
 * nothing shows up blank in the meantime.
 */
function withNameParts(r) {
  if (!r?.name || r['given-name'] || r['family-name']) return r;
  return { ...r, ...splitName(r.name) };
}

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
  refreshBiometrics();
}

// ---- biometric unlock -------------------------------------------------------
//
// Entirely a background concern — it owns the vault and it is the only thing
// that can reach the native host — so this page only asks and reports. Outside
// the extension (the preview harness) there is no background page, and none of
// it appears.

const bio = {
  available: false, // an authenticator is present and this browser does PRF
  enrolled: false, // this vault carries the second wrapping
  credentialId: '',
  os: '',
  reason: '',
};

const toB64 = (u8) => btoa(String.fromCharCode(...u8));

// Guarded on there being something to ask rather than on `vaultHost.shared`,
// which is a statement about where the vault lives and not about whether a
// message can be sent. If the background is gone the send rejects and this
// returns null, which is the same answer by a shorter route.
const askBackground = async (type, extra = {}) => {
  if (!globalThis.browser?.runtime?.sendMessage) return null;
  try {
    return await browser.runtime.sendMessage({ type, ...extra });
  } catch {
    return null;
  }
};

/** What to call it, in the words the platform uses for itself. */
const bioName = () =>
  bio.os === 'mac' ? 'Touch ID' : bio.os === 'win' ? 'Windows Hello' : 'your security key';

/**
 * Does enrolling here cost two prompts rather than one?
 *
 * Only where the browser will not hand back the PRF output from create() and
 * it has to be read back with a second call. That is the Mac today; Windows
 * Hello gets it at creation, and an unknown platform is not promised a second
 * prompt it may never raise.
 */
const twicePrompted = () => bio.os === 'mac';

// Raised once when the gate appears. A prompt that returns the instant it is
// dismissed cannot be dismissed.
let promptedThisVisit = false;
let showPasswordBox = false;

async function refreshBiometrics() {
  const reply = await askBackground(MSG.BIO_STATE);
  // Two halves. The background knows whether this vault is enrolled; only a
  // document can ask whether there is an authenticator to enrol against.
  const here = await webauthn.available();
  Object.assign(bio, {
    available: Boolean(here.ok),
    enrolled: Boolean(reply?.enrolled),
    credentialId: reply?.credentialId ?? '',
    os: reply?.os ?? '',
    reason: here.reason ?? '',
  });

  // Usable means all three: a host is installed, the machine can take a
  // fingerprint today, and this vault carries the second wrapping. Any less and
  // the button would be one that fails.
  const usable = bio.available && bio.enrolled && $('gate').dataset.mode !== 'setup';

  $('gate-bio-panel').hidden = !usable;
  $('gate-form').hidden = usable && !showPasswordBox;
  $('gate-bio').textContent = `Unlock with ${bioName()}`;
  if (usable && !showPasswordBox) {
    $('gate-bio-text').textContent = `Unlock with ${bioName()}.`;
    // setGate focuses the password box on the way in, and it has just been
    // hidden underneath this panel.
    $('gate-bio').focus();
  }

  renderBioSetting();

  // Ask straight away rather than waiting to be clicked. Opening the manager
  // while locked *is* the request to unlock it; making someone press one more
  // button first is the errand the fingerprint was enrolled to save.
  if (usable && !showPasswordBox && !promptedThisVisit) {
    promptedThisVisit = true;
    unlockWithBiometrics();
  }
}

// True while a prompt is on screen. Without it the on-sight prompt and a
// PROMPT_BIO arriving together would raise two sheets for one intention, and
// the second would be waiting behind the first for a finger that already came.
let prompting = false;

async function unlockWithBiometrics() {
  if (prompting) return;
  prompting = true;
  $('gate-bio-text').textContent = 'Waiting for you…';

  let secret;
  try {
    // The prompt belongs to the browser and the hardware. Nothing here ever
    // sees more than the 32 bytes that come back.
    secret = await webauthn.derive({ credentialId: bio.credentialId });
  } catch (err) {
    // Cancelling is a decision, not a fault, and NotAllowedError is what a
    // dismissal and a timeout both look like. Offer the password rather than
    // scolding, and do not raise the prompt again unasked.
    $('gate-bio-text').textContent =
      err?.name === 'NotAllowedError' ? 'Cancelled.' : `${bioName()} is not available just now.`;
    showPasswordBox = true;
    prompting = false;
    refreshBiometrics();
    return;
  }

  const reply = await askBackground(MSG.BIO_UNLOCK, { secret: toB64(secret) });
  prompting = false;
  if (reply?.ok) {
    state.vault = vaultHost.vault;
    enterApp();
    return;
  }

  $('gate-bio-text').textContent =
    reply?.reason === 'stale-secret'
      ? `${bioName()} no longer matches this vault, so it has been turned off.`
      : `Could not unlock (${reply?.reason ?? 'error'}).`;
  showPasswordBox = true;
  refreshBiometrics();
}

$('gate-bio').addEventListener('click', unlockWithBiometrics);

$('gate-use-password').addEventListener('click', () => {
  showPasswordBox = true;
  refreshBiometrics();
  $('gate-pw').focus();
});

/**
 * The biometric row in Settings.
 *
 * Shown even where nothing is installed, which is the whole point. Hiding it
 * when no host was present meant a machine that could do this perfectly well
 * gave no sign the feature existed, let alone what to run — which is exactly
 * how it looked like it had not shipped.
 */
function renderBioSetting() {
  const name = bioName() || 'Biometric unlock';
  $('s-bio-name').textContent = name;
  $('s-bio-btn').hidden = !bio.available;
  $('s-bio-btn').textContent = bio.enrolled ? 'Turn off' : 'Turn on';

  if (bio.available) {
    // "Twice" is a promise, not an apology: a second prompt nobody warned you
    // about reads as the first one having failed. It is said only where it is
    // true, though. On the Mac the second fingerprint is unavoidable — Firefox
    // does not return PRF output from create() there, so the secret has to be
    // read back with a second prompt (measured; see enrol() in
    // ext/webauthn.js). Firefox does pass it back for Windows Hello, so
    // promising a second prompt there would be its own small lie.
    $('s-bio-note').textContent = bio.enrolled
      ? `On for this machine. Your master password still works, and still opens it anywhere else.`
      : `Available on this machine. You will be asked for your master password once, and for ${name}${
          twicePrompted() ? ' twice — once to create the key, once to read it back' : ' once'
        }.`;
    return;
  }

  // No authenticator, or a browser that will not derive a key from the one that
  // is there. Nothing to install and nothing to fix in either case, but they
  // are not the same sentence: the second is a browser that has not caught up,
  // and saying "no authenticator" to someone looking at their own fingerprint
  // reader reads as BENCpass failing to see hardware that plainly works.
  $('s-bio-note').textContent =
    bio.reason === 'no-webauthn'
      ? 'This browser does not support WebAuthn.'
      : bio.reason === 'no-prf'
        ? `${name} is here, but this browser will not derive a key from it, so it cannot unlock the vault. Your master password still works.`
        : 'No authenticator on this machine. A Mac with Touch ID, a PC with Windows Hello, or a plugged-in security key would each do.';
}

$('s-bio-btn').addEventListener('click', async () => {
  if (bio.enrolled) {
    await askBackground(MSG.BIO_FORGET);
    await refreshBiometrics();
    say(`${bioName()} turned off on this machine.`);
    return;
  }

  // Enrolment needs the master password again, and genuinely so: the vault key
  // is a non-extractable CryptoKey once unlocked, so a second wrapping cannot
  // be made without re-deriving it. See enrolBiometric in core/vault.js.
  $('s-bio-form').hidden = false;
  $('s-bio-error').textContent = '';
  $('s-bio-btn').hidden = true;
  $('s-bio-pw').focus();
});

const cancelBioForm = () => {
  $('s-bio-form').hidden = true;
  $('s-bio-pw').value = '';
  $('s-bio-error').textContent = '';
  $('s-bio-btn').hidden = false;
};

$('s-bio-cancel').addEventListener('click', cancelBioForm);

$('s-bio-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('s-bio-pw').value;
  if (!password) return;

  $('s-bio-error').textContent = twicePrompted()
    ? `Asking for ${bioName()} — twice, the second to read the new key back…`
    : `Asking for ${bioName()}…`;
  let enrolled;
  try {
    // Here rather than in the background, because WebAuthn needs a document and
    // the user gesture that submitted this form.
    enrolled = await webauthn.enrol();
  } catch (err) {
    $('s-bio-pw').value = '';
    // UnknownError is what Firefox passes on when Windows refuses and gives no
    // reason worth repeating — "the operation failed for an unknown transient
    // reason", which is not transient and reads as worth retrying when it is
    // not.
    //
    // Windows Hello does do PRF: measured deriving a stable 32-byte key,
    // discoverable or not (tools/webauthn-probe/variants.html). The one thing
    // it will not accept is being asked to enable PRF without evaluating it —
    // `prf: {}` fails every time where `prf: { eval: … }` succeeds — and
    // enrol() has always asked with an eval, so this branch is not that.
    //
    // Left as the honest answer to a refusal we have not seen: an authenticator
    // that will not derive is a limit rather than a fault, and nothing is lost
    // but this one convenience.
    $('s-bio-error').textContent =
      err?.name === 'NotAllowedError'
        ? 'Cancelled.'
        : err?.code === 'no-prf' || err?.name === 'UnknownError' || err?.name === 'NotSupportedError'
          ? `${bioName()} on this machine will not derive a key, so it cannot unlock the vault. Your master password still works.`
          : `Could not enroll: ${err?.message ?? err}`;
    return;
  }

  // Argon2 at 128 MiB blocks for a moment. Say so rather than looking dead.
  $('s-bio-error').textContent = 'Deriving key…';
  const reply = await askBackground(MSG.BIO_ENROL, {
    password,
    credentialId: enrolled.credentialId,
    secret: toB64(enrolled.secret),
  });
  $('s-bio-pw').value = '';

  if (reply?.ok) {
    cancelBioForm();
    await refreshBiometrics();
    say(`${bioName()} will now unlock this vault on this machine.`);
    return;
  }

  await refreshBiometrics();
  $('s-bio-btn').hidden = true; // the form stays up so it can be tried again
  // `detail` is whatever actually went wrong, passed through untouched. It is
  // not pretty and it is the only thing that distinguishes one failure from
  // another.
  $('s-bio-error').textContent =
    reply?.reason === 'bad-password'
      ? 'That is not the master password.'
      : `Could not turn it on (${reply?.reason ?? 'error'})` +
        (reply?.detail ? `: ${reply.detail}` : '.');
});

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
  refreshBiometrics();
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

  $('settings').hidden = true;
  $('app').hidden = true;
  $('gate').hidden = false;
  $('visor').setAttribute('fill', 'var(--bad)');
  $('gate-hint').textContent = why || 'Locked.';
  $('gate-pw').focus();

  // The fingerprint is offered again — including after someone chose the
  // password box last time, because that was a decision about one unlock and
  // not a standing preference. Offered, though, and deliberately not raised:
  // the on-sight prompt is left spent.
  //
  // Locking is a request for the vault to be shut, and a Touch ID sheet that
  // appears the instant you press Lock is the lock undoing itself — the only
  // way past it is to cancel a dialog nobody asked for. The auto-lock is the
  // same mistake with a sharper edge: it fires when nobody is at the machine,
  // so the sheet is raised at an empty desk, where it either waits for a
  // passer-by or simply advertises that this vault opens with a finger.
  //
  // Arriving at the gate is still a request to unlock, and still prompts:
  // boot() leaves this flag clear on the way in.
  promptedThisVisit = true;
  showPasswordBox = false;
  refreshBiometrics();
}

$('lock-btn').addEventListener('click', () => lock());

// Somebody asked to unlock from somewhere that cannot prompt: the menu on a
// password field, or the toolbar. Opening the manager fresh raises the prompt
// on its own, so this is for the surfaces that were already open and sitting
// at a locked gate -- above all the sidebar, which is not a tab and so is
// never the one the background finds and focuses.
//
// This is also what makes locking deliberately quiet safe to do. The prompt is
// not raised again until it is asked for, and asking to fill a password is
// asking for it.
// Optional-chained like every other reach for the extension APIs in this file:
// preview.sh serves these pages over plain http with no `browser` at all, and a
// listener registered at load would take the whole document down with it.
globalThis.browser?.runtime?.onMessage?.addListener((msg) => {
  if (msg?.type !== MSG.PROMPT_BIO) return;
  if (!state.vault?.locked) return;
  promptedThisVisit = false;
  showPasswordBox = false;
  refreshBiometrics();
});
for (const ev of ['keydown', 'pointerdown']) {
  document.addEventListener(ev, bumpAutolock, { passive: true });
}

// ---- persistence -----------------------------------------------------------

const persist = () => vaultHost.persist();

// ---- rendering -------------------------------------------------------------

function render() {
  // Nothing to draw from a locked vault, and every call below would throw. The
  // guard is here rather than at each caller because render() is reached from
  // several — a section switch, a save, a sync — any of which can arrive while
  // the vault is shut.
  if (!state.vault || state.vault.locked) {
    $('list').replaceChildren();
    $('foot-count').textContent = '';
    return;
  }

  renderList();
  renderDetail();
  const n = state.vault.list(state.section).length;
  const noun = state.section === 'address' ? 'address' : 'entry';
  const plural = state.section === 'address' ? 'addresses' : 'entries';
  $('foot-count').textContent = `${n} ${n === 1 ? noun : plural}`;
}

function renderList() {
  // A locked vault has nothing to list, and asking it throws. This runs from
  // render(), which anything may call — including a redraw that arrives just
  // after the vault shut — so the guard belongs here rather than at each caller.
  if (!state.vault || state.vault.locked) {
    $('list').replaceChildren();
    return;
  }

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

function renderAddressDetail(record) {
  const r = withNameParts(record);
  const box = $('d-address');
  box.replaceChildren();

  for (const { token, label, kind } of ADDRESS_FIELDS) {
    if (!r[token]) continue;
    const row = document.createElement('div');
    row.className = 'row';

    const name = document.createElement('span');
    name.className = 'label';
    name.textContent = label;

    // The country is stored as its code, which is the right thing to store and
    // the wrong thing to read: "GB" tells you less than "United Kingdom".
    const shown = kind === 'country' ? countryName(r[token]) || r[token] : r[token];

    const value = document.createElement('span');
    value.className = 'value';
    value.textContent = shown;

    const copy = document.createElement('button');
    copy.className = 'btn btn-sm';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => copyText(r[token], label));

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

// ---- settings ---------------------------------------------------------------
//
// A pane over the list rather than a page of its own, so closing it puts you
// back exactly where you were. Everything here belongs to the background: this
// reads what it reports and hands back what was typed, and the background
// validates before storing. The device key the sync server authenticates with
// is deliberately never sent this way — the panel is told *whether* this
// machine is enrolled, never with what.

const ago = (at) => {
  if (!at) return 'Never synced.';
  const mins = Math.round((Date.now() - at) / 60000);
  if (mins < 1) return 'Synced just now.';
  if (mins < 60) return `Synced ${mins}m ago.`;
  return `Synced ${Math.round(mins / 60)}h ago.`;
};

async function openSettings() {
  $('settings').hidden = false;
  $('s-error').hidden = true;
  await refreshBiometrics();
  await loadSettings();
}

async function loadSettings() {
  const s = await askBackground(MSG.SETTINGS_GET);
  if (!s) {
    // Outside the extension there is no background to ask, and the panel has
    // nothing true to show.
    $('s-error').textContent = 'Settings are only available inside the extension.';
    $('s-error').hidden = false;
    return;
  }

  $('s-autolock').value = s.autolockMinutes;
  $('s-endpoint').value = s.endpoint;
  $('s-fallback').value = s.fallbackEndpoint ?? '';
  $('s-insecure').checked = s.allowInsecure;
  $('s-enrol-note').textContent = s.enrolled
    ? `This machine is enrolled as ${s.deviceId}. Pasting a new code replaces it.`
    : 'Paste the code the server printed when it started.';
  // Which address answered is worth saying: it is the difference between "the
  // LAN is fine" and "the LAN is down and you have not noticed".
  const via = s.lastSyncVia ? ` via ${s.lastSyncVia}` : '';
  $('s-sync-note').textContent = s.endpoint ? ago(s.lastSync) + via : 'No server set.';

  const about = $('s-about');
  about.replaceChildren();
  for (const [k, v] of [
    ['Version', s.version],
    ['Entries', s.records === null ? '—' : String(s.records)],
    ['Device', s.deviceId || 'not enrolled'],
    ['Helper', bio.hostVersion ? `v${bio.hostVersion}` : 'not installed'],
  ]) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    about.append(dt, dd);
  }
}

/** Send one field, and report a refusal in the words the background used. */
async function saveSetting(patch) {
  const reply = await askBackground(MSG.SETTINGS_SET, patch);
  const problems = {
    'bad-endpoint': 'That is not a URL.',
    'insecure-endpoint':
      'Plain http is only allowed to a private address. Use https, or a LAN or Tailscale name.',
    unreachable: 'Neither address answered.',
    'bad-autolock': 'Between 1 minute and 24 hours.',
    'bad-enrolment': 'An enrollment code looks like `device-id:key`.',
  };
  if (!reply?.ok) {
    $('s-error').textContent = problems[reply?.reason] ?? 'Could not save that.';
    $('s-error').hidden = false;
    return false;
  }
  $('s-error').hidden = true;
  await loadSettings();
  return true;
}

$('settings-btn').addEventListener('click', openSettings);
$('settings-close').addEventListener('click', () => {
  $('settings').hidden = true;
});

$('s-autolock').addEventListener('change', () =>
  saveSetting({ autolockMinutes: Number($('s-autolock').value) }),
);
$('s-endpoint').addEventListener('change', () => saveSetting({ endpoint: $('s-endpoint').value }));
$('s-fallback').addEventListener('change', () =>
  saveSetting({ fallbackEndpoint: $('s-fallback').value }),
);
$('s-insecure').addEventListener('change', () =>
  saveSetting({ allowInsecure: $('s-insecure').checked }),
);
$('s-enrolment').addEventListener('change', async () => {
  const code = $('s-enrolment').value.trim();
  if (!code) return;
  if (await saveSetting({ enrolment: code })) {
    // Not left on screen: it is a credential, and it has been stored.
    $('s-enrolment').value = '';
    say('Enrolled.');
  }
});

$('s-sync-btn').addEventListener('click', async () => {
  $('s-sync-note').textContent = 'Syncing…';
  const reply = await askBackground(MSG.SYNC);
  if (reply?.ok) {
    const conflicts = reply.conflicts ? ` ${reply.conflicts} conflict(s) kept.` : '';
    $('s-sync-note').textContent = `Synced.${conflicts}`;
    render();
  } else {
    // The message carries which addresses were tried and what each said, which
    // is the whole point of having two of them.
    $('s-sync-note').textContent =
      reply?.reason === 'not-configured'
        ? 'No server set.'
        : `Failed: ${reply?.message ?? reply?.reason ?? 'error'}`;
  }
});

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

/**
 * The address inputs, generated from the schema rather than written out.
 *
 * Nineteen fields is a great many to face at once when eleven of them cover
 * almost every form ever filled in, so the rest sit behind a disclosure. They
 * are still real fields, still saved, still filled — just not in the way.
 */
function buildAddressEditor(record) {
  const box = $('e-address');
  box.replaceChildren();

  // An older record, or one captured from a form with a single "Full name"
  // box, keeps `name` and no parts. Split it on the way in so the editor shows
  // something, and so saving does not quietly drop it.
  const source = withNameParts({ ...record });

  const rare = document.createElement('details');
  rare.className = 'more-fields';
  const summary = document.createElement('summary');
  summary.textContent = 'Less common fields';
  rare.append(summary);

  for (const field of ADDRESS_FIELDS) {
    const wrap = document.createElement('label');
    wrap.className = 'field';

    const name = document.createElement('span');
    name.className = 'label';
    name.textContent = field.label;

    wrap.append(name, addressInput(field, source[field.token] ?? ''));
    (field.rare ? rare : box).append(wrap);
  }

  // Only offered when it has something in it, which it always does — but the
  // check keeps the markup honest if the schema ever loses its rare fields.
  if (rare.childElementCount > 1) box.append(rare);
}

/** One input, typed to what it holds. Country is a real list, not a code box. */
function addressInput(field, value) {
  if (field.kind === 'country') {
    const select = document.createElement('select');
    select.dataset.addressKey = field.token;

    const blank = document.createElement('option');
    blank.value = '';
    blank.textContent = '—';
    select.append(blank);

    for (const [code, label] of countryOptions()) {
      const option = document.createElement('option');
      option.value = code;
      option.textContent = label;
      select.append(option);
    }
    select.value = String(value ?? '').toUpperCase();
    return select;
  }

  const input = document.createElement('input');
  input.type = field.token === 'email' ? 'email' : field.token === 'tel' ? 'tel' : 'text';
  input.dataset.addressKey = field.token;
  input.value = value;
  if (field.placeholder) input.placeholder = field.placeholder;
  input.autocomplete = 'off';
  return input;
}

$('edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const fields =
    state.editingType === 'address'
      ? {
          type: 'address',
          title: $('e-title').value.trim(),
          notes: $('e-notes').value,
          // The editor showed the name in parts, so the whole-name key an older
          // record kept is now stale. Cleared rather than left behind, so there
          // is only ever one answer to what this address's name is.
          name: '',
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
