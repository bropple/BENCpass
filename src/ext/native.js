// Talking to the native host that guards the device secret.
//
// The host exists for one reason: a browser extension cannot ask an operating
// system for a fingerprint. Touch ID lives behind LocalAuthentication and the
// Keychain, Windows Hello behind KeyCredentialManager, and neither is reachable
// from JavaScript in a page or a background script. A small native program can
// reach both, and native messaging is the only door between the two.
//
// What crosses that door is deliberately dull. The host is handed a random
// 32-byte string it cannot interpret and asked to keep it somewhere only a
// fingerprint opens; later it is asked for it back. It never sees the master
// password, never sees the vault key, and never sees a record. Everything
// cryptographic happens in src/core — see the second-wrapping section of
// vault.js for what the secret actually unlocks.
//
// A missing host is an ordinary state, not an error: most machines will not
// have one installed, and the extension has to work exactly as before on them.

import { toB64, fromB64 } from '../core/bytes.js';

/** Must match the `name` in the host's native-messaging manifest. */
export const HOST_NAME = 'net.ropple.bencpass.auth';

/** The wire version. Bumped only for a change the host could not survive. */
export const PROTOCOL = 1;

/**
 * One round trip.
 *
 * `sendNativeMessage` starts the host, sends one message, waits for one reply
 * and lets it exit. A long-lived port would be faster and is not worth it: this
 * is called when someone unlocks a vault, not in a loop, and a process that
 * only exists for the length of a prompt is a smaller thing to get wrong.
 */
async function call(op, extra = {}) {
  if (!browser.runtime?.sendNativeMessage) {
    return { ok: false, reason: 'unsupported' };
  }
  try {
    const reply = await browser.runtime.sendNativeMessage(HOST_NAME, {
      v: PROTOCOL,
      op,
      ...extra,
    });
    if (!reply || typeof reply !== 'object') return { ok: false, reason: 'bad-reply' };
    return reply;
  } catch (err) {
    // Firefox rejects with a message rather than a code when the manifest is
    // absent, the binary is missing or it exits without replying. All three
    // mean the same thing here — there is nothing to talk to.
    return { ok: false, reason: 'no-host', detail: String(err?.message ?? err) };
  }
}

/**
 * What is available on this machine.
 *
 * `biometrics` is what the host says it can actually do *now*, not what the
 * platform supports in principle: a Mac with Touch ID disabled, or a Windows
 * machine with no Hello enrolment, both answer 'none'. Enrolment is offered
 * only when the answer is something else, because an enrolment that cannot be
 * used later is worse than none — it would be a second way into the vault
 * guarded by nothing.
 */
export const capabilities = () => call('hello');

/** Hand the host a secret to keep behind the OS prompt. */
export const store = (id, secretBytes) => call('store', { id, secret: toB64(secretBytes) });

/**
 * Ask for it back. This is the call that raises the fingerprint prompt, so it
 * can take as long as the person takes, and `cancelled` is an ordinary answer.
 */
export async function retrieve(id, prompt) {
  const reply = await call('get', { id, prompt });
  if (!reply.ok || typeof reply.secret !== 'string') return reply;
  try {
    return { ok: true, secret: fromB64(reply.secret) };
  } catch {
    return { ok: false, reason: 'bad-reply' };
  }
}

/** Tell the host to drop it. */
export const forget = (id) => call('forget', { id });
