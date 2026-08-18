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

  return { ok: platform && prf !== false, platform, prf, reason: platform ? '' : 'no-authenticator' };
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
        residentKey: 'required',
      },
      // Asking for the value at creation as well as enabling the extension.
      // Some authenticators return it straight away, which makes enrolment one
      // prompt rather than two; the rest ignore it and the fallback below asks
      // again. Either is correct — this only saves a fingerprint where it can.
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
