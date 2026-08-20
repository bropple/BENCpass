// BENCpass manager UI.
//
// Holds no secret of its own: everything readable comes out of an unlocked
// Vault and goes back into the DOM, and lock() drops both at once. If this file
// ever needs to remember a password between two functions, something upstream
// is wrong.

import { Vault, VaultLockedError } from '../core/vault.js';
import { pickStorage } from '../core/storage.js';
import { generate, entropyBits } from '../core/generate.js';
import { ADDRESS_SCHEMA, countryOptions, countryName, splitName } from '../core/address.js';
import { toJson, toCsv, parse as parseTransfer, TransferError } from '../core/transfer.js';
import { newRecoveryCode, normalise as normaliseRecoveryCode, CODE_LENGTH } from '../core/recovery.js';
import { LOGIN } from '../core/model.js';
import { PROTOCOL } from '../core/sync.js';
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
    // The background reads its vault from storage asynchronously, and this
    // page used to read bg.bencpass.vault while that read was still in
    // flight: null came back, the gate took it for "no vault on this machine"
    // and offered SETUP over a vault holding hundreds of records — one typed
    // password from persisting an empty vault on top of them (the background
    // now refuses that write too, but a wrong offer is a defect on its own).
    // No gate is chosen before the answer exists.
    await bg.bencpass.ready;
    return {
      shared: true,
      get vault() {
        return bg.bencpass.vault;
      },
      get autolockAt() {
        return bg.bencpass.autolockAt;
      },
      bump: () => bg.bencpass.bump(),
      // Creation happens in the BACKGROUND's realm, never here. A Vault built
      // in this document dies with this document — Firefox nukes the
      // compartment of a closed page, and the background is left holding a
      // dead-object wrapper that throws on every touch. Only the password
      // crosses, as a string, down the same gated channel UNLOCK uses.
      create: async (password) => {
        const made = await askBackground(MSG.SETUP, { password });
        if (!made?.ok) {
          throw new Error(
            made?.reason === 'already-a-vault'
              ? 'There is already a vault on this machine. Reload this page and unlock it instead.'
              : (made?.message ?? `Could not create the vault (${made?.reason ?? 'error'}).`),
          );
        }
        return bg.bencpass.vault;
      },
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
    // The same refusal the background makes, for the same reason: creating is
    // only ever creating the FIRST vault, and the check goes to storage — the
    // copy an overwrite would destroy — not to a variable that can be blank
    // for other reasons.
    create: async (password) => {
      if (await store.read()) {
        throw new Error('There is already a vault here. Reload this page and unlock it instead.');
      }
      local = await Vault.create({ password });
      await store.write(local.toJSON());
      return local;
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

// A half-written entry, carried across a lock. The auto-lock fires when nobody
// is at the machine, which is precisely when an entry is most likely to be
// sitting half-typed in the editor — and wiping it with the rest of the DOM
// made Save-after-lock a button that silently ate the work. This deliberately
// keeps user-typed plaintext in this page's memory while the vault is shut:
// the screen is still cleared, and the alternative is destroying something the
// person typed and cannot get back. It dies with the page like everything else.
let editDraft = null;

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
    // Setup by default, with the join offered beside it. Guessing which one
    // somebody wants from whether a server happens to be configured would be
    // wrong as often as right: a machine can have an address saved and still be
    // the one that creates the vault.
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

/** What to call it, in the words the platform uses for itself. The fallback
 *  is deliberately not "your security key": enrolment pins the platform
 *  authenticator, so a plugged-in key is never what this feature means. */
const bioName = () =>
  bio.os === 'mac' ? 'Touch ID' : bio.os === 'win' ? 'Windows Hello' : "this machine's authenticator";


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
  renderRecoverySetting();
  // Fetched rather than remembered: what is enrolled is the server's answer,
  // and a stale list is how somebody revokes a machine that is already gone.
  loadDevices().catch(() => {});

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
    // about reads as the first one having failed.
    //
    // Said unconditionally, because it was measured on both platforms that have
    // one — Touch ID and Windows Hello each ask twice. Firefox does not hand
    // back the PRF output from create() on either, so the secret has to be read
    // back with a second call; see enrol() in ext/webauthn.js. This was briefly
    // conditional on the Mac, on the strength of a release note saying Windows
    // got create-time PRF in 147. The machine says otherwise.
    $('s-bio-note').textContent = bio.enrolled
      ? `On for this machine. Your master password still works, and still opens it anywhere else.`
      : `Available on this machine. You will be asked for your master password once, and for ${name} twice — once to create the key, once to read it back.`;
    return;
  }

  // No authenticator, or a browser that will not derive a key from the one that
  // is there. Nothing to install and nothing to fix in either case, but they
  // are not the same sentence: the second is a browser that has not caught up,
  // and saying "no authenticator" to someone looking at their own fingerprint
  // reader reads as BENCpass failing to see hardware that plainly works.
  // No mention of plugged-in security keys: enrolment pins the *platform*
  // authenticator (webauthn.js asks for authenticatorAttachment: 'platform'),
  // so a USB key is never asked for — and on Linux, where there is no platform
  // authenticator at all, the old sentence promised a feature that then never
  // worked. The copy and the code have to tell the same story.
  $('s-bio-note').textContent =
    bio.reason === 'no-webauthn'
      ? 'This browser does not support WebAuthn.'
      : bio.reason === 'no-prf'
        ? `${name} is here, but this browser will not derive a key from it, so it cannot unlock the vault. Your master password still works.`
        : 'No built-in authenticator on this machine. This needs a Mac with Touch ID or a PC with Windows Hello; plugged-in security keys are not supported. Your master password works everywhere.';
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

  $('s-bio-error').textContent = `Asking for ${bioName()} — twice, the second to read the new key back…`;
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
  const join = mode === 'join';

  const recover = mode === 'recover';

  $('gate-confirm-field').hidden = !setup;
  $('gate-pw2').required = setup;
  $('gate-join-fields').hidden = !join;
  $('gate-server').required = join;
  $('gate-code').required = join;

  // In recovery the code replaces the password rather than joining it: asking
  // for both would be asking for the thing they have just told us they lost.
  $('gate-recovery-field').hidden = !recover;
  $('gate-recovery').required = recover;
  $('gate-pw').closest('.field').hidden = recover;
  $('gate-pw').required = !recover;

  $('gate-go').textContent = setup
    ? 'Create vault'
    : join
      ? 'Join'
      : recover
        ? 'Recover'
        : 'Unlock';
  $('gate-hint').textContent = setup
    ? 'No vault on this machine.'
    : join
      ? 'Join the vault on your server.'
      : recover
        ? 'Open it with your recovery code.'
        : 'Locked.';

  $('gate-note').textContent = setup
    ? 'The master password is not recoverable. Nothing here, and nothing on the server, can open the vault without it.'
    : join
      ? 'The same master password as your other machine. This pulls that vault down rather than making a new one — a new one could never read its records.'
      : recover
        ? 'The code printed when this vault was set up. It opens the vault; the master password stays what it was. To actually change it, unlock with the code and use Settings → Master password — the code can prove that change too.'
        : state.vault?.pendingMeta
          ? 'The master password was changed on another machine. This one switches the first time you unlock it with the new password; until then the old password still opens it here.'
          : '';

  // Offered only when there is no vault here. With one, "join" would mean
  // replacing it, which is not a thing to put behind a link on a lock screen.
  const offer = setup || join;
  $('gate-switch').hidden = !offer;
  $('gate-switch-btn').textContent = join
    ? 'Or create a new vault on this machine'
    : 'Already have a vault on a server? Join it';

  // Only where there is a vault to recover, and only if it has a way back.
  const canRecover = Boolean(state.vault?.hasRecovery);
  $('gate-recovery-switch').hidden = !(canRecover && (mode === 'unlock' || recover));
  $('gate-recovery-btn').textContent = recover
    ? 'Use the master password instead'
    : 'Forgotten the master password? Use a recovery code';

  $('gate-pw').autocomplete = setup ? 'new-password' : 'current-password';
  $('gate').dataset.mode = mode;
  $('gate-pw').focus();
}

$('gate-switch-btn').addEventListener('click', () => {
  setGate($('gate').dataset.mode === 'join' ? 'setup' : 'join');
  $('gate-error').hidden = true;
});

$('gate-recovery-btn').addEventListener('click', () => {
  setGate($('gate').dataset.mode === 'recover' ? 'unlock' : 'recover');
  $('gate-error').hidden = true;
});

// ---- the recovery sheet -----------------------------------------------------
//
// A code that wraps the vault key a third time, generated once and shown once.
// It is not stored anywhere, which is exactly what makes it safe to print and
// exactly why it cannot be shown again — so the sheet insists on being
// acknowledged rather than letting somebody click past it.

let sheetDone;

/**
 * Mint a recovery code, put it on screen, and enrol it only once it is
 * acknowledged.
 *
 * The order is the point. This used to enrol and persist before showing the
 * sheet, so closing the tab at the sheet left a phantom: the gate offered
 * "use a recovery code" for a code that had never been on anyone's screen —
 * a way back in that nobody holds. Minting still proves the master password
 * (a wrong one fails before anything is shown); the vault only changes on
 * "I have written it down", and bailing out before that leaves everything
 * exactly as it was.
 *
 * Failing to mint is not a reason to stop: a vault with no way back is the
 * state everything was in until today, and it is better than refusing to
 * finish setup. The sheet says so rather than pretending it worked.
 */
async function showRecoverySheet(password) {
  const code = newRecoveryCode();
  let wrap = null;
  try {
    wrap = await state.vault.mintRecoveryWrap(password, code);
  } catch (err) {
    // A wrong master password is the caller's to report — at setup it cannot
    // happen, and from Settings it is the whole answer. Anything else is ours,
    // and setup carries on without a code rather than refusing to finish.
    if (err?.code === 'unwrap-failed') throw err;
    console.error('BENCpass: could not mint the recovery code', err);
  }

  $('kit-code').textContent = wrap ? code : '';
  $('kit-created').textContent = new Date().toLocaleDateString();
  $('kit-device').textContent = navigator.platform || 'this machine';

  if (!wrap) {
    $('kit-status').textContent =
      'A recovery code could not be created. Your vault is fine and your master password works — you can make one later under the gear.';
    $('kit-ack').checked = true;
    $('kit-done').disabled = false;
  }

  $('kit').hidden = false;
  await new Promise((resolve) => {
    sheetDone = resolve;
  });
  if (wrap) {
    state.vault.adoptRecoveryWrap(wrap);
    await persist();
  }
  $('kit').hidden = true;
  $('kit-code').textContent = '';
}

$('kit-ack').addEventListener('change', () => {
  $('kit-done').disabled = !$('kit-ack').checked;
});

$('kit-done').addEventListener('click', () => sheetDone?.());

$('kit-print').addEventListener('click', () => window.print());

$('kit-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('kit-code').textContent);
    // Said plainly: a clipboard is not where this belongs, and a clipboard
    // manager will have kept a copy whatever happens next.
    $('kit-status').textContent =
      'Copied. Paste it somewhere permanent now — the clipboard is not a safe place to leave it.';
  } catch {
    $('kit-status').textContent = 'Could not copy. Write it down instead.';
  }
});

// ---- gate ------------------------------------------------------------------

/**
 * Adopt the vault that is already on a server.
 *
 * Three things happen in order, and the order matters: the address is saved so
 * there is somewhere to redeem against, the code is redeemed for a device
 * credential, and only then is the header pulled and opened with the master
 * password. Each step's failure is reported as itself rather than as whatever
 * the next step made of it.
 *
 * The vault key that comes out of this is the *same* one the other machine
 * uses. That is the whole difference between joining and starting again: a new
 * vault would have its own key and could never read a record the other machine
 * wrote.
 */
async function joinExisting(password) {
  const server = $('gate-server').value.trim();
  const code = $('gate-code').value.trim();
  if (!server) throw new Error('Where is the server?');
  if (!code) throw new Error('Paste the code the server printed.');

  // Consent first: this is the moment the machine agrees to send anything
  // anywhere, and asking after the vault is open would be asking too late.
  if (!(await consentToSync())) {
    throw new Error('Joining needs permission to send your passwords and addresses to that server.');
  }

  // Redeem the code only if this machine has not already used one.
  //
  // Enrolling and joining are two steps, and the first can succeed while the
  // second fails — mistype the master password and the device is enrolled with
  // no vault to show for it. Re-running the redemption on the retry would then
  // spend an already-spent code and fail with "unknown or expired", stranding
  // somebody one keystroke from success and sending them to mint another.
  const already = await askBackground(MSG.SETTINGS_GET);
  const patch = already?.enrolled ? { endpoint: server } : { endpoint: server, enrolment: code };

  const saved = await askBackground(MSG.SETTINGS_SET, patch);
  if (!saved?.ok) {
    const why = {
      'bad-endpoint': 'That is not a URL.',
      'insecure-endpoint':
        'Plain http is only allowed to a LAN address. A Tailscale name needs https too — its range cannot be told apart from ISP NAT.',
      'bad-code': 'The server did not accept that code. They are single-use and expire after 30 minutes.',
      'bad-enrolment': 'That is not a code. Paste what the server printed, or a `device-id:key` pair.',
      unreachable: 'Nothing answered at that address.',
    };
    throw new Error(why[saved?.reason] ?? `Could not enrol: ${saved?.reason ?? 'error'}`);
  }

  const joined = await askBackground(MSG.JOIN, { password });
  if (!joined?.ok) throw new Error(joined?.message ?? 'Could not join that vault.');

  state.vault = vaultHost.vault;
}

$('gate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('gate-pw').value;
  const err = $('gate-error');
  err.hidden = true;

  const btn = $('gate-go');
  const label = btn.textContent;
  // Argon2 at 128 MiB blocks this thread for ~400 ms. Say so rather than
  // letting the button look dead — but say it flatly.
  // Ask before yielding, not after. permissions.request() is only granted from
  // a live user gesture, and awaiting anything spends it — Mozilla says so and
  // the comment beside consentToSync says so, and this handler awaited a
  // setTimeout for a repaint before ever reaching the join path. The prompt
  // never appeared, the request was refused, and every attempt to join a
  // second machine failed with a message about a permission the person was
  // never offered. Joining is the whole point of the second machine.
  // Asked here, before the yield below, and nowhere else.
  //
  // permissions.request() is granted only from a live user gesture, and
  // awaiting anything spends it — Mozilla says so and the comment beside
  // consentToSync says so. This handler awaited a setTimeout for a repaint
  // before it ever reached the join path, so by the time joinExisting asked,
  // the gesture was gone: the prompt never appeared, the request was refused,
  // and joining a second machine failed every time with a message about a
  // permission nobody was offered. Joining is the entire point of the second
  // machine.
  //
  // joinExisting still asks, and must: it is reached from other callers, and a
  // second request costs nothing once the permission is held.
  if ($('gate').dataset.mode === 'join' && $('gate-server').value.trim()) {
    let granted = false;
    try {
      granted = await consentToSync();
    } catch {
      granted = false;
    }
    if (!granted) {
      $('gate-error').textContent =
        'Joining needs permission to send your passwords and addresses to that server.';
      $('gate-error').hidden = false;
      return;
    }
  }

  btn.disabled = true;
  btn.textContent = 'Deriving key';
  await new Promise((r) => setTimeout(r, 0));

  try {
    if ($('gate').dataset.mode === 'setup') {
      if (pw !== $('gate-pw2').value) throw new Error('The two entries do not match.');
      if (pw.length < 8) throw new Error('Use at least 8 characters.');
      // Created and persisted by the vault's owner — inside the extension
      // that is the background, in its own realm, with its own refusal to
      // overwrite a vault already in storage. See makeVaultHost.
      state.vault = await vaultHost.create(pw);
      // Before the app, not after: this is the one moment the code exists in
      // memory and the person is still paying attention to setup.
      await showRecoverySheet(pw);
    } else if ($('gate').dataset.mode === 'join') {
      await joinExisting(pw);
    } else if ($('gate').dataset.mode === 'recover') {
      await state.vault.unlockWithRecoveryCode($('gate-recovery').value);
      $('gate-recovery').value = '';
    } else {
      await state.vault.unlock(pw);
      // The unlock may have adopted a header parked by a background sync — a
      // master password change made on another machine. It happened in memory
      // and must land on disk, or a restart forgets it (and re-adopts next
      // time, harmlessly, but the disk should say what the vault says).
      if (state.vault.metaUpdated) {
        state.vault.metaUpdated = false;
        await persist();
        say('This machine now uses the new master password.');
      }
    }
    enterApp();
  } catch (ex) {
    // The one deliberately ambiguous message in the app. It stays ambiguous —
    // saying which of the two it was would tell someone holding the file
    // whether a guess was close.
    err.textContent =
      ex.code === 'unwrap-failed'
        ? $('gate').dataset.mode === 'recover'
          ? 'That recovery code did not open this vault. Check it against what you printed — the dashes and the case do not matter.'
          : 'Wrong password, or this vault is damaged.'
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
  if (editDraft) restoreDraft();
}

/** Put a draft the lock interrupted back into the editor. */
function restoreDraft() {
  const d = editDraft;
  editDraft = null;

  // The editor's shape follows the section, so the section follows the draft.
  state.section = d.type === 'address' ? 'address' : 'login';
  for (const b of document.querySelectorAll('.seg-btn')) {
    b.setAttribute('aria-selected', String(b.dataset.section === state.section));
  }

  // The record may have been deleted on another machine while this one sat
  // locked; the draft still deserves a home, so it reopens as a new entry.
  const target = d.editing !== 'new' && state.vault.get(d.editing) ? d.editing : 'new';
  openEditor(target);

  $('e-title').value = d.fields.title ?? '';
  $('e-notes').value = d.fields.notes ?? '';
  if (d.type === 'address') {
    for (const input of $('e-address').querySelectorAll('[data-address-key]')) {
      const value = d.fields[input.dataset.addressKey];
      if (value !== undefined) input.value = value;
    }
  } else {
    $('e-username').value = d.fields.username ?? '';
    $('e-password').value = d.fields.password ?? '';
    $('e-urls').value = (d.fields.urls ?? []).join('\n');
  }
  say('Your unsaved edit was kept across the lock.');
}

function lock(why = '') {
  vaultHost?.lock();
  lockUi(why);
}

/**
 * The page's half of locking: clear the DOM and return to the gate.
 *
 * Separate from lock() because the vault does not always shut from here. The
 * background locks it on idle and on screen lock, and this page then has
 * nothing to tell the vault — only its own spans and inputs to clear. Calling
 * lock() for that would send the lock back to the background, which would
 * broadcast it back here, a cycle nobody needs.
 */
function lockUi(why = '') {
  // Before the wipe below: keep what was being typed, so unlocking puts the
  // person back in the editor instead of in front of an empty pane.
  if (state.editing !== null && !$('edit-form').hidden) {
    editDraft = { editing: state.editing, type: state.editingType, fields: readEditorFields() };
  }

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
  // The minted enrolment code grants a device key to whoever types it in
  // first; it does not get to outlive the session that minted it.
  clearMintedCode();

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

// The background locks the vault on its own — the idle timer, the screen
// locking — and this page used to sleep through it: the app pane stayed up
// over a vault that was shut, and a revealed password stayed readable until
// the next click threw VaultLockedError at it. The background broadcasts
// every lock; this returns to the gate and clears the DOM when it arrives.
//
// Guarded on the app pane being visible rather than on the vault's state:
// the vault is already locked by the time the message lands, and a page
// sitting at the gate has nothing to clear and no reason to repaint it.
globalThis.browser?.runtime?.onMessage?.addListener((msg) => {
  if (msg?.type !== MSG.LOCKSTATE || !msg.locked) return;
  if ($('app').hidden) return;
  lockUi('Auto-locked.');
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
  renderHealth();
  const n = state.vault.list(state.section).length;
  const noun = state.section === 'address' ? 'address' : 'entry';
  const plural = state.section === 'address' ? 'addresses' : 'entries';
  $('foot-count').textContent = `${n} ${n === 1 ? noun : plural}`;
}

/**
 * The vault's bad news, across the top of the list where it will be seen.
 *
 * Two facts land here, and each is a promise this project makes elsewhere:
 * records that would not open at the last unlock are SKIPPED, never silently
 * dropped — so the skipping has to be said, or a vault quietly holds less than
 * it did yesterday; and parked conflict copies past the safety cap are
 * DISCARDED oldest-first — so the discarding has to be said, or "kept" was a
 * lie. The second is acknowledgeable, because it is a count of past events; the
 * first stands as long as it is true.
 */
function renderHealth() {
  const v = state.vault;
  if (!v || v.locked) {
    $('health').hidden = true;
    return;
  }
  const bits = [];
  const damaged = v.damaged?.length ?? 0;
  const dropped = v.parkedDropped ?? 0;
  if (damaged) {
    bits.push(
      `${damaged} ${damaged === 1 ? 'entry' : 'entries'} could not be opened at unlock — ` +
        `the sealed data is damaged, or a server served something tampered. ` +
        `${damaged === 1 ? 'It is' : 'They are'} skipped, not deleted: an honest server or ` +
        `another machine still holds the real copy, and the next sync can heal it. ` +
        `If this persists, the server is withholding or corrupting ` +
        `${damaged === 1 ? 'that record' : 'those records'}.`,
    );
  }
  if (dropped) {
    bits.push(
      `${dropped} parked conflict ${dropped === 1 ? 'copy was' : 'copies were'} discarded ` +
        `unseen: more conflicts arrived while this vault was locked than the safety cap ` +
        `(${Vault.PARKED_MAX}) can hold, and the oldest were dropped to bound the queue. ` +
        `The newest were kept as "(conflict)" entries. That many conflicts is not normal — ` +
        `if you did not cause it, distrust the server.`,
    );
  }
  $('health').hidden = bits.length === 0;
  $('health-text').textContent = bits.join(' ');
  $('health-ack').hidden = dropped === 0;
}

// Dismissing acknowledges the eviction count — a tally of past events, told
// once — and persists the acknowledgement. The damaged notice has no dismiss:
// it re-derives at every unlock and stands exactly as long as it is true.
$('health-ack').addEventListener('click', async () => {
  if (!state.vault) return;
  state.vault.parkedDropped = 0;
  await persist();
  renderHealth();
});

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
  // hideSecrets reaches here straight from the reveal timer, which can fire
  // after the background has locked the vault — an idle lock while a password
  // sat revealed. vault.get below would then throw VaultLockedError before
  // the secret span was repainted, leaving the plaintext on screen. Clear the
  // spans and stop instead.
  if (!state.vault || state.vault.locked) {
    $('detail-view').hidden = true;
    $('detail-empty').hidden = false;
    $('d-password').textContent = '';
    $('d-username').textContent = '';
    $('d-notes').textContent = '';
    return;
  }

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

  // Shown on every kind of record, not only addresses. Two copies of the same
  // login after a sync conflict differ in exactly one readable way — when each
  // was last written — and without this the person is asked to choose between
  // them with nothing to choose on.
  if (r.updated && r.updated !== r.created) add('Updated', date(r.updated));

  if (r.type === 'address') {
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

  if (r.history?.length) add('Previous', historyList(r));

  if (r.provisional) {
    const note = document.createElement('span');
    note.className = 'age-warn';
    note.textContent =
      'Generated and saved before the sign-up finished. If the account exists, this is its password — add the username; if not, delete this entry.';
    add('Unconfirmed', note);
  }

  if (r.conflictOf) {
    const note = document.createElement('span');
    note.className = 'age-warn';
    note.textContent =
      "Another machine's version of an entry both machines edited. Compare with the current entry and delete whichever is wrong.";
    add('Sync conflict', note);
  }

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

/**
 * The old passwords applyPatch keeps, as something a person can actually open.
 *
 * "N kept" with no viewer was a safety net that could not be reached by any
 * route — not here, not in the exports, not in the rescue tool — which made it
 * no safety net at all. Each row is the password as it was, the date it was
 * set, and the two things someone recovering from a bad rotation needs: see
 * it, and copy it. Revealed values ride the same 30-second countdown as the
 * main password; the timer's redraw rebuilds this list masked and closed.
 */
function historyList(r) {
  const box = document.createElement('details');
  box.className = 'history';

  const sum = document.createElement('summary');
  sum.textContent = `${r.history.length} kept`;
  box.append(sum);

  for (const h of r.history) {
    const row = document.createElement('div');
    row.className = 'history-row';

    const when = document.createElement('span');
    when.className = 'history-when';
    when.textContent = h.changed ? `set ${date(h.changed)}` : 'undated';

    const value = document.createElement('span');
    value.className = 'value mono secret';
    value.textContent = '•'.repeat(12);
    let shown = false;

    const reveal = document.createElement('button');
    reveal.className = 'btn btn-sm';
    reveal.textContent = 'Reveal';
    reveal.addEventListener('click', () => {
      shown = !shown;
      value.textContent = shown ? h.password : '•'.repeat(12);
      reveal.textContent = shown ? 'Hide' : 'Reveal';
      if (shown) armRevealTimer();
    });

    const copy = document.createElement('button');
    copy.className = 'btn btn-sm';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => copyText(h.password, 'Old password'));

    row.append(when, value, reveal, copy);
    box.append(row);
  }
  return box;
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
    // already taken a copy by now, and this cannot reach into one. A refusal
    // — usually this page no longer having focus — must not be announced as
    // a clear: "Clipboard cleared." over a clipboard still holding the
    // password is the message teaching someone the opposite of the truth.
    try {
      await navigator.clipboard.writeText('');
    } catch {
      say('Could not clear the clipboard — it still holds what was copied.');
      return;
    }
    say('Clipboard cleared.');
  }, CLIPBOARD_MS);
}

let sayTimer = null;
// ---- the machines on this server --------------------------------------------
//
// Built with createElement rather than markup, like everything else that shows
// a name somebody else chose: a device called `<img onerror=…>` is a name, and
// it renders as one.

function deviceRow(dev, mine) {
  const li = document.createElement('li');

  const name = document.createElement('span');
  name.className = 'dev-name';
  name.textContent = dev.name || dev.id;
  li.append(name);

  if (dev.id === mine) {
    const tag = document.createElement('span');
    tag.className = 'dev-mine';
    tag.textContent = 'this machine';
    li.append(tag);
  }

  const when = document.createElement('span');
  when.className = 'dev-when';
  when.textContent = dev.created ? new Date(dev.created).toLocaleDateString() : '';
  li.append(when);

  const actions = document.createElement('span');
  actions.className = 'dev-actions';

  const rename = document.createElement('button');
  rename.type = 'button';
  rename.className = 'btn btn-sm';
  rename.textContent = 'Rename';
  rename.addEventListener('click', () => renameDevice(dev));

  const revoke = document.createElement('button');
  revoke.type = 'button';
  revoke.className = 'btn btn-sm';
  revoke.textContent = 'Revoke';
  revoke.addEventListener('click', () => revokeDevice(dev, mine));

  actions.append(rename, revoke);
  li.append(actions);
  return li;
}

async function loadDevices() {
  const list = $('s-devices');
  const note = $('s-devices-note');
  list.replaceChildren();
  note.className = 'settings-note';
  note.textContent = 'Asking the server…';

  const reply = await askBackground(MSG.DEVICES);
  if (!reply?.ok) {
    note.textContent =
      reply?.reason === 'not-configured'
        ? 'No server set, so there is nothing enrolled anywhere.'
        : `Could not ask the server: ${reply?.message ?? reply?.reason ?? 'error'}`;
    note.className = 'settings-note bad';
    return;
  }

  note.textContent = '';
  for (const dev of reply.devices) list.append(deviceRow(dev, reply.mine));
}

async function renameDevice(dev) {
  const name = window.prompt('Call this machine:', dev.name || '');
  if (name === null) return;

  const reply = await askBackground(MSG.DEVICE_RENAME, { deviceId: dev.id, name });
  const note = $('s-devices-note');
  if (!reply?.ok) {
    note.textContent = `Could not rename: ${reply?.message ?? reply?.reason ?? 'error'}`;
    note.className = 'settings-note bad';
    return;
  }
  await loadDevices();
}

async function revokeDevice(dev, mine) {
  const label = dev.name || dev.id;
  // Revoking this machine is allowed and is occasionally what somebody means —
  // a laptop about to be wiped bows out — but it is not what they mean by
  // accident, so it says which one it is about to cut off.
  const question =
    dev.id === mine
      ? `Revoke ${label} — the machine you are using?\n\nIt will stop syncing immediately and will need a new code to come back.`
      : `Revoke ${label}?\n\nIts key stops working immediately and it cannot come back without a new code.`;
  if (!window.confirm(question)) return;

  const reply = await askBackground(MSG.DEVICE_FORGET, { deviceId: dev.id });
  const note = $('s-devices-note');
  if (!reply?.ok) {
    note.textContent =
      reply?.reason === 'last-device'
        ? 'That is the only machine enrolled. Removing it would leave the server unreachable — nothing could enrol, because minting a code needs a machine to ask.'
        : `Could not revoke: ${reply?.message ?? reply?.reason ?? 'error'}`;
    note.className = 'settings-note bad';
    return;
  }

  if (reply.self) {
    // The list cannot be fetched again: the credential that would have asked
    // for it has just been dropped. Say what happened instead of showing an
    // error from a request that was never going to work.
    await loadSettings();
    $('s-devices').replaceChildren();
    note.textContent = 'This machine is no longer enrolled. Its vault is untouched; syncing is off.';
    note.className = 'settings-note';
    return;
  }
  await loadDevices();
}

$('s-rebuilt-btn').addEventListener('click', async () => {
  if (
    !window.confirm(
      'Forget what this machine has already synced?\n\n' +
        'Only do this if you rebuilt or restored the server yourself. If you did not, ' +
        'the server is not the one you think it is, and this would let it feed you an old copy.\n\n' +
        'Your vault is untouched. Everything in it will be sent again.',
    )
  ) {
    return;
  }

  const reply = await askBackground(MSG.SYNC_FORGET);
  if (!reply?.ok) {
    $('s-sync-note').textContent = `Could not forget: ${reply?.reason ?? 'error'}`;
    return;
  }
  $('s-rebuilt').hidden = true;
  $('s-sync-note').textContent = 'Forgotten. Press Sync to send everything again.';
});

$('s-devices-refresh').addEventListener('click', loadDevices);

// ---- minting a code for the next machine ------------------------------------
//
// The server prints a bootstrap code only while zero devices are enrolled.
// After machine one, a code can only be minted by a machine that already
// holds a key — this button. Until it existed, machines two and three were
// permanently locked out while the deployment guide described the button
// anyway.
//
// The code is handled the way the recovery sheet handles its code: shown
// once, never stored, and cleared when the settings pane closes or the vault
// locks. It deserves that care — whoever redeems it first enrols a device
// with full access to the vault's ciphertext and the standing to sync it.

function clearMintedCode() {
  $('s-mint-code').textContent = '';
  $('s-mint-code').hidden = true;
  $('s-mint-copy').hidden = true;
  $('s-mint-note').textContent = '';
  $('s-mint-note').className = 'settings-note';
}

$('s-mint-btn').addEventListener('click', async () => {
  clearMintedCode();
  $('s-mint-btn').disabled = true;
  $('s-mint-note').textContent = 'Asking the server…';

  const reply = await askBackground(MSG.MINT_CODE);
  $('s-mint-btn').disabled = false;

  if (!reply?.ok) {
    // The background's message already says which thing to fix — no server
    // configured, nothing reachable, a refused key, a protocol mismatch — so
    // it is shown as sent rather than rounded to "failed".
    $('s-mint-note').textContent =
      reply?.message ?? 'Could not mint a code. Settings are only available inside the extension.';
    $('s-mint-note').className = 'settings-note bad';
    return;
  }

  $('s-mint-code').textContent = reply.code;
  $('s-mint-code').hidden = false;
  $('s-mint-copy').hidden = false;
  // The lifetime is the server's to decide and comes back with the code;
  // saying a number the server did not send would be a guess dressed as fact.
  const mins = reply.ttlSeconds ? Math.round(reply.ttlSeconds / 60) : null;
  $('s-mint-note').textContent =
    (mins ? `Good once, for ${mins} minutes.` : 'Good once; the server decides for how long.') +
    ' It is not shown again — mint another if it lapses.' +
    (reply.code.includes('.')
      ? ' The part after the dot is this machine’s sync position: it lets the new machine refuse a rolled-back server, so carry the code over whole.'
      : '');
});

$('s-mint-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('s-mint-code').textContent);
    $('s-mint-note').textContent = 'Copied. It still expires on the server\'s clock.';
  } catch {
    $('s-mint-note').textContent = 'Could not copy. Type it over instead.';
  }
});

// ---- the recovery code, after setup -----------------------------------------

function renderRecoverySetting() {
  const has = Boolean(state.vault?.hasRecovery);
  $('s-recovery-note').textContent = has
    ? 'Set up. Making a new one replaces it — the old code stops working, so anything printed from it becomes waste paper.'
    : 'None. Without one, forgetting the master password loses this vault on every machine at once.';
  $('s-recovery-btn').textContent = has ? 'Replace' : 'Create';
}

$('s-recovery-btn').addEventListener('click', () => {
  $('s-recovery-form').hidden = false;
  $('s-recovery-error').textContent = '';
  $('s-recovery-pw').value = '';
  $('s-recovery-pw').focus();
});

$('s-recovery-cancel').addEventListener('click', () => {
  $('s-recovery-form').hidden = true;
  $('s-recovery-pw').value = '';
});

$('s-recovery-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('s-recovery-pw').value;
  if (!pw) return;

  $('s-recovery-error').textContent = 'Deriving key…';
  try {
    // showRecoverySheet mints, enrols and displays. Replacing goes through the
    // same path as setup so there is one place a code is ever shown, and one
    // place that insists it was written down.
    await showRecoverySheet(pw);
  } catch (err) {
    $('s-recovery-error').textContent =
      err?.code === 'unwrap-failed' ? 'Wrong master password.' : String(err?.message ?? err);
    return;
  }
  $('s-recovery-form').hidden = true;
  $('s-recovery-pw').value = '';
  $('s-recovery-error').textContent = '';
  renderRecoverySetting();
  say('Recovery code replaced.');
});

// ---- changing the master password ---------------------------------------------
//
// A re-wrap of the same vault key (core/vault.js has the crypto and the
// fail-safe). The current secret is proven first, and it can be either the
// master password or the recovery code — the second is what frees someone who
// forgot the password and came in with the code from staying on it for ever.
// Which one was typed is decided by trying: the password wrap first, and on
// refusal the recovery wrap if the input has the shape of a code. Each try
// costs one Argon2 derivation, which is the going rate for proving a secret.

const cancelPwChange = () => {
  $('s-pwchange-form').hidden = true;
  $('s-pwchange-cur').value = '';
  $('s-pwchange-new').value = '';
  $('s-pwchange-new2').value = '';
  $('s-pwchange-error').textContent = '';
};

$('s-pwchange-btn').addEventListener('click', () => {
  $('s-pwchange-form').hidden = false;
  $('s-pwchange-error').textContent = '';
  $('s-pwchange-cur').focus();
});

$('s-pwchange-cancel').addEventListener('click', cancelPwChange);

$('s-pwchange-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const cur = $('s-pwchange-cur').value;
  const next = $('s-pwchange-new').value;
  const err = (msg) => {
    $('s-pwchange-error').textContent = msg;
  };

  if (!cur) return err('Enter the current master password, or your recovery code.');
  if (next !== $('s-pwchange-new2').value) return err('The two new entries do not match.');
  if (next.length < 8) return err('Use at least 8 characters.');
  if (next === cur) return err('That is the password this vault already has.');

  err('Deriving keys — this takes a moment…');
  try {
    try {
      await state.vault.changeMasterPassword(cur, next);
    } catch (ex) {
      // Not the password. If what was typed reads as a recovery code and this
      // vault has one, prove the change with that instead.
      const looksLikeCode =
        state.vault.hasRecovery && normaliseRecoveryCode(cur).length === CODE_LENGTH;
      if (ex?.code === 'unwrap-failed' && looksLikeCode) {
        await state.vault.changeMasterPasswordWithRecovery(cur, next);
      } else {
        throw ex;
      }
    }
  } catch (ex) {
    return err(
      ex?.code === 'unwrap-failed'
        ? 'That is not the current master password' +
            (state.vault.hasRecovery ? ' or the recovery code.' : '.')
        : String(ex?.message ?? ex),
    );
  }

  state.vault.metaUpdated = false;
  await persist();
  cancelPwChange();

  // Publish through the ordinary sync (the header rides the putMeta
  // compare-and-swap), and say what actually happened either way: the change
  // is real on this machine now, and other machines switch when they unlock
  // with the new password — after this header has reached the server.
  const synced = await vaultHost.sync();
  say('Master password changed.');
  $('s-pwchange-note').textContent = synced?.ok
    ? 'Changed, and the new header is on the server. Other machines switch the first time you ' +
      'unlock them with the new password; until then each still opens with the old one. Your ' +
      'recovery code and fingerprint are untouched. Old exported backups still open with the ' +
      'old password — a re-wrap does not rewrite history.'
    : 'Changed on this machine. The server has not heard yet' +
      (synced?.reason === 'not-configured' ? ' (no server is set)' : ` (${synced?.reason ?? 'sync failed'})`) +
      ' — the new header goes up with the next successful sync, and other machines switch when ' +
      'they unlock with the new password after that. This machine is fine either way.';
});

// ---- testing an endpoint ------------------------------------------------------
//
// Sync failing is the least debuggable thing here: it happens in the
// background, against an address only the owner knows, and the answer is
// usually a typo or a machine that is not on. A button that says "answered" or
// says exactly what went wrong turns that into a five-second check.
//
// /v1/health is unauthenticated on purpose, so this works before a device is
// enrolled — which is precisely when the address is most likely wrong.

function endpointStatus(which, text, kind = '') {
  const el = $(`s-${which}-status`);
  el.textContent = text;
  el.className = `settings-note ${kind}`.trim();
}

async function testEndpoint(which) {
  const raw = $(`s-${which}`).value.trim().replace(/\/+$/, '');

  // An empty box is not a failed test, it is no test. Saying "could not reach"
  // about an address nobody has entered is a wrong answer to a question that
  // was not asked.
  if (!raw) {
    endpointStatus(which, '');
    return;
  }

  let url;
  try {
    url = new URL(`${raw}/v1/health`);
  } catch {
    endpointStatus(which, 'That is not an address.', 'bad');
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    endpointStatus(which, 'Needs to start with http:// or https://.', 'bad');
    return;
  }

  const btn = $(`s-${which}-test`);
  btn.disabled = true;
  endpointStatus(which, 'Trying…');

  try {
    // Time-boxed, because the interesting failure is an address that is simply
    // not there — which does not refuse, it just never answers, and would
    // otherwise sit here for the operating system's TCP timeout.
    const resp = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!resp.ok) {
      endpointStatus(which, `Answered ${resp.status}, which is not a BENCpass server.`, 'bad');
      return;
    }
    const body = await resp.json().catch(() => null);
    if (!body || body.ok !== true) {
      endpointStatus(which, 'Something answered, but not a BENCpass server.', 'bad');
      return;
    }

    // A server speaking a different version of the signed request format is the
    // failure worth naming. Every request to it comes back 401, and 401 is also
    // what a wrong device key gives — so without this the answer to "why has
    // sync stopped" is a credential error pointing at the wrong thing.
    const theirs = Number(body.protocol ?? 1);
    if (theirs !== PROTOCOL) {
      endpointStatus(
        which,
        theirs > PROTOCOL
          ? `That server speaks protocol ${theirs} and this BENCpass speaks ${PROTOCOL}. Update the extension.`
          : `That server speaks protocol ${theirs} and this BENCpass speaks ${PROTOCOL}. Update the server.`,
        'bad',
      );
      return;
    }

    const seq = body.seq ?? 0;
    endpointStatus(
      which,
      `Answered. ${seq} change${seq === 1 ? '' : 's'} stored${body.server ? `, server ${body.server}` : ''}.`,
      'good',
    );
  } catch (err) {
    // A timeout and a refusal are different problems with different fixes, and
    // saying which saves the guess.
    endpointStatus(
      which,
      err?.name === 'TimeoutError'
        ? 'No answer. Nothing is listening there, or a firewall is eating it.'
        : 'Could not reach it. Check the address, and that the server is running.',
      'bad',
    );
  } finally {
    btn.disabled = false;
  }
}

for (const which of ['endpoint', 'fallback']) {
  $(`s-${which}-test`).addEventListener('click', () => testEndpoint(which));
  // Editing invalidates whatever the last answer was about.
  $(`s-${which}`).addEventListener('input', () => endpointStatus(which, ''));
}

// ---- import and export -------------------------------------------------------
//
// The only place in the interface that deliberately produces plaintext. It is
// worth the risk, and the reason is the people running without a server: their
// vault exists in exactly one browser profile, which is not a thing anyone
// backs up on purpose. An export is the difference between a lost profile
// being an inconvenience and being the loss of every password they have.
//
// So the wording does not soften it. The file is dangerous, it says so on the
// button and again inside the file, and the rest is up to the person holding
// it.

function transferStatus(text, kind = '') {
  const el = $('s-transfer-status');
  el.textContent = text;
  el.className = `settings-note ${kind}`.trim();
}

/**
 * Hand the file to the browser.
 *
 * An object URL and a synthetic click, rather than browser.downloads — this
 * page runs in a sidebar as well as a tab, and the download permission is one
 * more thing to ask for to do something an anchor already does. The URL is
 * revoked straight after; it points at plaintext and there is no reason for it
 * to outlive the click.
 */
function offerFile(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const stamp = () => new Date().toISOString().slice(0, 10);

function exportVault(kind) {
  if (!state.vault || state.vault.locked) return;
  const records = state.vault.list();
  if (!records.length) {
    transferStatus('Nothing to export yet.', 'bad');
    return;
  }

  if (kind === 'csv') {
    const logins = records.filter((r) => r.type === LOGIN);
    if (!logins.length) {
      transferStatus('No logins to export. Addresses only go out as JSON.', 'bad');
      return;
    }
    offerFile(`bencpass-${stamp()}.csv`, toCsv(records), 'text/csv');
    const addresses = records.length - logins.length;
    transferStatus(
      addresses
        ? `Exported ${logins.length} login${logins.length === 1 ? '' : 's'}. ${addresses} address${addresses === 1 ? '' : 'es'} left out — CSV has nowhere to put them.`
        : `Exported ${logins.length} login${logins.length === 1 ? '' : 's'} in plain text.`,
      'good',
    );
    return;
  }

  offerFile(`bencpass-${stamp()}.json`, toJson(records), 'application/json');
  transferStatus(`Exported ${records.length} entries in plain text. Mind where it lands.`, 'good');
}

/**
 * The whole vault, still sealed.
 *
 * The other two exports are plaintext and dangerous, and say so. This one is
 * the opposite: it is the vault exactly as it sits in storage, openable only by
 * the master password or the recovery code, so it can go anywhere a person
 * would put a photo. It is the missing half of the recovery kit — a printed
 * code is no use with nothing to point it at, and browser.storage.local is not
 * a thing anyone can extract by hand.
 *
 * What goes in and what is left out is decided by Vault.backup(), beside the
 * format it belongs to, so that this page cannot get it wrong on its own. The
 * fingerprint wrapping is dropped there for a reason worth knowing here: with
 * it, this file opens to a fingerprint, and the sentence beside the button
 * would be a lie.
 *
 * Works while locked, because nothing here needs the key.
 */
function exportEncryptedVault() {
  if (!state.vault) return;
  const backup = state.vault.backup();
  // Tombstones are in the file and are not in the list, so counting envelopes
  // would report a number the user cannot find anywhere on screen.
  const count = backup.envelopes.filter((e) => !e.deleted).length;
  offerFile(
    `bencpass-vault-${stamp()}.json`,
    JSON.stringify(backup, null, 2),
    'application/json',
  );
  transferStatus(
    `Saved ${count} sealed record${count === 1 ? '' : 's'}. Still encrypted — keep it wherever you like.`,
    'good',
  );
}

$('s-export-vault').addEventListener('click', exportEncryptedVault);

$('s-export-json').addEventListener('click', () => exportVault('json'));
$('s-export-csv').addEventListener('click', () => exportVault('csv'));

$('s-import').addEventListener('click', () => $('s-import-file').click());

$('s-import-file').addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  // Cleared straight away so choosing the same file twice still fires a change.
  e.target.value = '';
  if (!file) return;
  if (!state.vault || state.vault.locked) return;

  transferStatus('Reading…');
  let records;
  try {
    records = parseTransfer(await file.text());
  } catch (err) {
    // A TransferError already says something a person can act on. Anything else
    // is ours and gets named as such rather than dressed up as the file's fault.
    transferStatus(
      err instanceof TransferError ? err.message : `Could not read that file: ${err?.message ?? err}`,
      'bad',
    );
    return;
  }

  // Added rather than merged, and never overwriting: a duplicate is a nuisance
  // somebody can delete, and a silently replaced password is one they cannot
  // get back. Deciding which of two entries is the better one is not a decision
  // to make on their behalf at three hundred records a second.
  let added = 0;
  try {
    for (const r of records) {
      // History stays. It is the safety net applyPatch keeps — the old
      // passwords a bad rotation is recovered from — and dropping it here
      // meant the one file people restore from was the one place it did not
      // survive. The timestamps are still re-stamped; see toJson's note.
      const { type, created, updated, lastUsed, timesUsed, passwordChanged, ...fields } = r;
      await state.vault.add({ ...fields, type });
      added++;
    }
    await persist();
  } catch (err) {
    await persist();
    transferStatus(`Added ${added} before failing: ${err?.message ?? err}`, 'bad');
    render();
    return;
  }

  render();
  transferStatus(`Added ${added} ${added === 1 ? 'entry' : 'entries'}. Nothing was replaced.`, 'good');
});

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
  // A refusal the background sync met while nobody was looking — tampering, a
  // rollback, a dropped write. Held by the background until a sync succeeds,
  // and shown here because the panel is where sync status lives; the timer
  // that found it reported to nobody.
  if (s.syncProblem) {
    $('s-sync-note').textContent =
      `Sync is refusing: ${s.syncProblem.message} (since ${new Date(s.syncProblem.at).toLocaleTimeString()}).`;
    $('s-rebuilt').hidden = s.syncProblem.reason !== 'rollback';
  }

  const about = $('s-about');
  about.replaceChildren();
  for (const [k, v] of [
    ['Version', s.version],
    ['Entries', s.records === null ? '—' : String(s.records)],
    ['Device', s.deviceId || 'not enrolled'],
    // No "Helper" row. It reported a native host that WebAuthn replaced, from a
    // field nothing has set since, so it read "not installed" for ever — an
    // answer to a question nobody was asking about a component that is gone.
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
      'Plain http is only allowed to a LAN address. A Tailscale name needs https too — its range cannot be told apart from ISP NAT.',
    unreachable: 'Neither address answered.',
    'bad-autolock': 'Between 1 minute and 24 hours.',
    'bad-enrolment': 'That is not a code. Paste what the server printed, or a `device-id:key` pair.',
    'no-endpoint-for-code': 'Set the server address first — a code has to be redeemed somewhere.',
    'bad-code': 'The server did not accept that code. They are single-use and expire after 30 minutes.',
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
  // The minted code leaves with the pane. Anyone who needed it has read it;
  // an enrolment credential is not a thing to leave under a settings panel.
  clearMintedCode();
});

$('s-autolock').addEventListener('change', () =>
  saveSetting({ autolockMinutes: Number($('s-autolock').value) }),
);
// ---- consent for what sync sends -------------------------------------------
//
// The manifest declares `authenticationInfo` and `personallyIdentifyingInfo` as
// *optional* data collection, which is accurate: nothing leaves the machine
// until a server is configured. But optional data-collection permissions are
// real permissions in Firefox's model — off until granted, listed in
// about:addons under Permissions and Data, and revocable there.
//
// Declaring them and never asking would mean about:addons showing both switched
// off while the vault syncs, which contradicts the extension's own declaration
// and the requirement that a person affirmatively consents before personal data
// is transmitted. So the ask happens where the decision is made: at the moment
// somebody puts an address in the box.
//
// It has to run inside the event handler. `permissions.request` needs a user
// gesture, and awaiting anything first spends it.
// Read from the manifest rather than written twice. A hand-copied list can
// drift from what is declared, and the drift is silent in the worst direction:
// the request would ask for less than sync actually sends.
const SYNC_DATA =
  globalThis.browser?.runtime?.getManifest?.()?.browser_specific_settings?.gecko
    ?.data_collection_permissions?.optional ?? [];

async function consentToSync() {
  const api = globalThis.browser?.permissions;
  if (!api?.request || !SYNC_DATA.length) return true;
  try {
    return await api.request({ data_collection: SYNC_DATA });
  } catch (err) {
    // A rejection is a refusal, not a formality.
    //
    // This used to return true, on the reasoning that a browser too old to know
    // `data_collection` would throw rather than answer. No such browser can
    // install this: strict_min_version is 142 and the key shipped in 139. So the
    // only rejections reachable here are real ones — a spent user gesture above
    // all — and swallowing them saved the address with no consent recorded at
    // all, which is precisely the state this function exists to prevent.
    console.warn('BENCpass: the data-collection prompt failed', err);
    return false;
  }
}

/** Save an address, having first asked to send anything to it. */
async function saveEndpoint(field, key) {
  const which = field === 's-endpoint' ? 'endpoint' : 'fallback';
  const value = $(field).value.trim();

  // Clearing the box is switching sync off. Nothing to consent to.
  if (value && !(await consentToSync())) {
    // The box is put back to what is actually stored rather than blanked. A
    // blank box beside a still-configured endpoint says sync is off when it is
    // not, and the refusal above did not turn anything off — it declined to
    // turn something on.
    await loadSettings();
    endpointStatus(
      which,
      'Not saved: syncing needs permission to send your passwords and addresses to that server.',
      'bad',
    );
    return;
  }
  await saveSetting({ [key]: value });
}

$('s-endpoint').addEventListener('change', () => saveEndpoint('s-endpoint', 'endpoint'));
$('s-fallback').addEventListener('change', () => saveEndpoint('s-fallback', 'fallbackEndpoint'));
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
  $('s-rebuilt').hidden = true;
  const reply = await askBackground(MSG.SYNC);
  if (reply?.ok) {
    // "Kept" is finally true: the other machine's copy is forked into its own
    // "(conflict)" entry during the sync (see settleConflicts in core/sync.js),
    // so the sentence points at something that exists in the list below it.
    const conflicts = reply.conflicts
      ? ` ${reply.conflicts} conflict(s): both versions kept — look for "(conflict)" entries and delete the wrong one.`
      : '';
    // A header at a newer generation was parked: the master password changed
    // on another machine. Nothing switches until it is proven — at the next
    // unlock, with the new password in hand — and saying so here beats a
    // password that mysteriously stops working at the next gate.
    const header = reply.headerPending
      ? ' The master password was changed on another machine — this one switches the next time you unlock it with the new password.'
      : '';
    $('s-sync-note').textContent = `Synced.${conflicts}${header}`;
    render();
  } else {
    // The message carries which addresses were tried and what each said, which
    // is the whole point of having two of them.
    $('s-sync-note').textContent =
      reply?.reason === 'not-configured'
        ? 'No server set.'
        : reply?.reason === 'no-consent'
          ? 'Sync is off: permission to send your data was withdrawn in about:addons.'
          : reply?.reason === 'rollback'
            ? 'The server is reporting fewer changes than this machine has already seen. See below.'
            : reply?.reason === 'tampered'
              ? 'Refused: the server served a record whose deletion flag contradicts its sealed contents. No client writes that — the record was tampered with on the server or in transit. Nothing was adopted. If this repeats, stop trusting that server.'
              : reply?.reason === 'dropped-push'
                ? 'Refused: the server said it accepted this machine’s changes but does not serve them back. Nothing was marked as synced, so nothing is lost here — but that server is dropping writes, and the same sync will keep failing until it stops.'
                : reply?.reason === 'conflict-locked'
                  ? 'Some records changed on two machines at once, and that cannot be settled while the vault is locked. Unlock and sync again — both versions are kept.'
                  : `Failed: ${reply?.message ?? reply?.reason ?? 'error'}`;

    // Offered only once a sync has genuinely been refused as a rollback, and
    // hidden again the moment one succeeds.
    $('s-rebuilt').hidden = reply?.reason !== 'rollback';
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

/** What the editor currently holds, in the shape add() and update() take. */
function readEditorFields() {
  return state.editingType === 'address'
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
}

$('edit-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const fields = readEditorFields();

  try {
    if (state.editing === 'new') {
      state.selected = await state.vault.add(fields);
    } else {
      await state.vault.update(state.editing, fields);
    }
  } catch (ex) {
    // The auto-lock won the race against the Save click. The button used to do
    // nothing at all here — the throw went nowhere and the draft went with the
    // gate. lockUi stashes the draft and enterApp reopens it, so losing the
    // race costs an unlock, not the work.
    if (ex instanceof VaultLockedError) {
      lockUi('Auto-locked.');
      return;
    }
    throw ex;
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
