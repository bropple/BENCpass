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

/** What to call it, in the words the platform uses for itself. */
const bioName = () =>
  bio.os === 'mac' ? 'Touch ID' : bio.os === 'win' ? 'Windows Hello' : 'your security key';

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

  const usable = bio.available && bio.enrolled && $('gate').dataset.mode !== 'setup';

  $('gate-bio-panel').hidden = !usable;
  $('gate-form').hidden = usable && !showPasswordBox;
  $('gate-bio').textContent = `Unlock with ${bioName()}`;
  if (usable && !showPasswordBox) {
    $('gate-bio-text').textContent = `Unlock with ${bioName()}.`;
    $('gate-bio').focus();
  }

  renderBioSetting();

  if (usable && !showPasswordBox && !promptedThisVisit) {
    promptedThisVisit = true;
    unlockWithBiometrics();
  }
}

async function unlockWithBiometrics() {
  $('gate-bio-text').textContent = 'Waiting for you…';
  try {
    // The prompt belongs to the browser and the hardware. Nothing here sees
    // anything but the 32 bytes that come back.
    const secret = await webauthn.derive({ credentialId: bio.credentialId });
    const reply = await askBackground(MSG.BIO_UNLOCK, { secret: toB64(secret) });
    if (reply?.ok) {
      state.vault = vaultHost.vault;
      enterApp();
      return;
    }
    if (reply?.reason === 'stale-secret') {
      $('gate-bio-text').textContent =
        `${bioName()} no longer matches this vault, so it has been turned off.`;
    } else {
      $('gate-bio-text').textContent = `Could not unlock (${reply?.reason ?? 'error'}).`;
    }
  } catch (err) {
    // Cancelling is a decision, not a fault, and NotAllowedError is what both a
    // dismissal and a timeout look like.
    $('gate-bio-text').textContent =
      err?.name === 'NotAllowedError' ? 'Cancelled.' : `${bioName()} failed: ${err?.message ?? err}`;
    showPasswordBox = true;
    refreshBiometrics();
    return;
  }
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
  const name = bioName();
  $('s-bio-name').textContent = name;
  $('s-bio-btn').hidden = !bio.available;
  $('s-bio-btn').textContent = bio.enrolled ? 'Turn off' : 'Turn on';

  if (bio.available) {
    $('s-bio-note').textContent = bio.enrolled
      ? `On for this machine. Your master password still works, and still opens this vault anywhere else.`
      : `Available on this machine. You will be asked for your master password once, and for ${name} straight after.`;
    return;
  }

  // No authenticator, or a browser without PRF. Nothing to install and nothing
  // to fix here — it is a property of the machine in front of you.
  $('s-bio-note').textContent =
    bio.reason === 'no-webauthn'
      ? 'This browser does not support WebAuthn.'
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

  $('s-bio-error').textContent = `Asking for ${bioName()}…`;
  let credentialId;
  let secret;
  try {
    // Done here rather than in the background because WebAuthn needs a document
    // and the user gesture that submitted this form.
    ({ credentialId, secret } = await webauthn.enrol());
  } catch (err) {
    $('s-bio-pw').value = '';
    $('s-bio-error').textContent =
      err?.name === 'NotAllowedError'
        ? 'Cancelled.'
        : err?.code === 'no-prf'
          ? 'This authenticator cannot derive a key, so it cannot unlock the vault.'
          : `Could not enrol: ${err?.message ?? err}`;
    return;
  }

  // Argon2 at 128 MiB blocks for a moment. Say so rather than looking dead.
  $('s-bio-error').textContent = 'Deriving key…';
  const reply = await askBackground(MSG.BIO_ENROL, {
    password,
    credentialId,
    secret: toB64(secret),
  });
  $('s-bio-pw').value = '';

  if (reply?.ok) {
    cancelBioForm();
    await refreshBiometrics();
    say(`${bioName()} will now unlock this vault on this machine.`);
    return;
  }

  await refreshBiometrics();
  $('s-bio-btn').hidden = true;
  $('s-bio-error').textContent =
    reply?.reason === 'bad-password'
      ? 'That is not the master password.'
      : `Could not turn it on (${reply?.reason ?? 'error'}).`;
});

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
