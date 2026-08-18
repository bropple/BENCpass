// Deriving the device secret from the machine's own authenticator.
//
// This replaces the native host, and the reason is worth recording: a browser
// extension cannot ask an operating system for a fingerprint, but it can ask
// *the browser*, and the browser already has a trusted path to the hardware.
// WebAuthn's PRF extension returns a stable 32 bytes from an authenticator that
// will not act without user verification — which is precisely the thing
// hosts/macos spent a day failing to obtain from the Keychain.
//
// What it costs: nothing. No native binary, no entitlement, no provisioning
// profile, no annual renewal, no hardware token, no developer account. On a Mac
// the platform authenticator is the Secure Enclave behind Touch ID; on Windows
// it is Hello and the TPM; on Linux it is whatever FIDO2 token is plugged in.
// One implementation, hardware-enforced everywhere, measured working before it
// was written — see tools/webauthn-probe.sh.
//
// The secret never leaves this machine and is never stored. It is re-derived
// from the authenticator each time the vault is unlocked, and it wraps the vault
// key exactly as the native host's secret would have — see the second-wrapping
// section of core/vault.js, which did not need to change at all.

/** The input PRF is evaluated over. Fixed forever: change it and every enrolled
 *  machine derives a different secret and stops opening its own vault. */
const SALT = new TextEncoder().encode('bencpass:v1:device-secret');

/**
 * The relying party every credential is bound to. Also fixed forever, and for a
 * harder reason: a credential created under one RP ID cannot be found under
 * another, so changing this silently strands every enrolment ever made.
 *
 * It has to be stated rather than inferred. A moz-extension:// origin has no
 * registrable domain, so with `rp.id` unset WebAuthn cannot derive one and
 * refuses with "SecurityError: The operation is insecure" — measured, along
 * with the fact that Firefox accepts any domain the extension holds host
 * permissions for, which with <all_urls> is all of them. See
 * tools/rpid-probe.sh.
 *
 * `.invalid` because RFC 2606 reserves it: the name is guaranteed never to
 * resolve, so no real site is ever implicated, and nothing here depends on
 * anyone continuing to own a domain. WebAuthn never contacts it; only the
 * string matters.
 *
 * "Can it just say `bencpass`?" — asked, and no, twice over. What macOS puts
 * on screen is this RP ID: the Touch ID sheet shows it, and Apple's Passwords
 * app shows it as both the entry's title and its Website row (screenshot,
 * 2026-08-17). `rp.name` — already 'BENCpass' — is displayed nowhere at all,
 * so the visible string can only be changed by changing this constant. And a
 * bare dotless label is refused: rp.id 'bencpass' gets "SecurityError: The
 * operation is insecure" from an extension page while 'bencpass.invalid' and
 * 'localhost' pass — measured on Firefox 152 by re-running tools/rpid-probe.sh
 * with 'bencpass' added, so `localhost` passing is a special case and not a
 * precedent. The only remaining lever is a different *domain*, and pulling it
 * strands the working enrolment — the one thing this comment exists to
 * prevent.
 */
const RP_ID = 'bencpass.invalid';

const bytes = (b) => new Uint8Array(b);
const toB64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Is there an authenticator here, and does this browser do PRF? */
export async function available() {
  if (typeof PublicKeyCredential === 'undefined') return { ok: false, reason: 'no-webauthn' };

  let platform = false;
  try {
    platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    /* treated as absent */
  }

  // getClientCapabilities is the direct answer where it exists. Where it does
  // not, PRF may still work — so its absence is not taken as a no.
  let prf = null;
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps) prf = caps['extension:prf'] === true;
  } catch {
    /* left unknown */
  }

  // Two different noes, and they need different words. No sensor is a fact
  // about the machine; a sensor the browser will not derive a key from is a
  // fact about the browser, and telling someone with Windows Hello sitting
  // right there that they have no authenticator is how a working machine looks
  // broken.
  return {
    ok: platform && prf !== false,
    platform,
    prf,
    reason: !platform ? 'no-authenticator' : prf === false ? 'no-prf' : '',
  };
}

/**
 * Ask the authenticator for a credential and the secret behind it.
 *
 * Must be called from a document with a real user gesture — a background page
 * has none, which is why this lives in the UI and only the derived bytes cross
 * to the background.
 */
export async function enrol({ rpId = RP_ID, name = 'BENCpass' } = {}) {
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  const created = await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name },
      user: { id: random(16), name: 'bencpass', displayName: name },
      challenge: random(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        // On a Mac the platform authenticator behind this is iCloud Keychain,
        // and what comes back is a passkey: it shows up in Apple's Passwords
        // app and syncs to the account's other devices, rather than sitting
        // sealed in this one machine's Secure Enclave (seen in the Passwords
        // app, 2026-08-17). Reportedly not this flag's doing — Apple's
        // keychain makes every credential discoverable and synced regardless —
        // though that is documentation, not something measured here. The
        // tradeoff was put to the owner and accepted: the sync boundary is the
        // iCloud account, in exchange for the credential surviving this one
        // machine.
        residentKey: 'required',
      },
      // Asking for the value at creation as well as enabling the extension.
      // Some authenticators return it straight away, which makes enrolment one
      // prompt rather than two; the rest ignore it and the fallback below asks
      // again. Either is correct — this only saves a fingerprint where it can.
      //
      // Nowhere yet, on the evidence. Enrolment is two prompts on macOS and two
      // on Windows Hello (both measured, 2026-08), so Firefox is not passing
      // PRF output back from create() on either — whatever the authenticators
      // can do, and whatever the release notes say about Windows getting this
      // in 147. Left in place for the build where they meet; it costs nothing
      // to ask. Meanwhile the enrolment form says "twice" out loud — see
      // ui/manager.js — because the honest fix for an unavoidable second prompt
      // is an expected second prompt.
      extensions: { prf: { eval: { first: SALT } } },
      timeout: 120000,
    },
  });

  if (created.getClientExtensionResults()?.prf?.enabled !== true) {
    // The credential exists but cannot derive anything, so enrolling on it would
    // produce a vault that says it has a second key and does not.
    throw Object.assign(new Error('this authenticator will not do PRF'), { code: 'no-prf' });
  }

  const credentialId = toB64(bytes(created.rawId));

  const atCreation = created.getClientExtensionResults()?.prf?.results?.first;
  const secret =
    atCreation && atCreation.byteLength === 32
      ? bytes(atCreation)
      : await derive({ rpId, credentialId });

  return { credentialId, secret };
}

/**
 * Re-derive the secret. This is the call that raises the prompt, so it takes as
 * long as the person takes.
 */
export async function derive({ rpId = RP_ID, credentialId }) {
  const got = await navigator.credentials.get({
    publicKey: {
      rpId,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: fromB64(credentialId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: SALT } } },
      timeout: 120000,
    },
  });

  const first = got.getClientExtensionResults()?.prf?.results?.first;
  if (!first) {
    throw Object.assign(new Error('the authenticator returned no secret'), { code: 'no-prf' });
  }

  const secret = bytes(first);
  if (secret.length !== 32) {
    throw Object.assign(new Error(`expected 32 bytes, got ${secret.length}`), { code: 'no-prf' });
  }
  return secret;
}
