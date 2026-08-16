// BENCpass crypto core.
//
// Deliberately free of any `browser.*` API so it runs and is tested under plain
// Node. Everything that touches storage or the extension lives elsewhere.
//
//   master password ──Argon2id──▶ master key ─┐
//                                             ├─unwrap─▶ vault key ──▶ records
//   biometric secret ──native host────────────┘
//
// Two independent wrappings of the same vault key. Changing the master password
// rewraps one key rather than re-encrypting the vault, and enrolling or dropping
// biometrics touches nothing else.

import { argon2id } from './argon2.js';
import { toB64, fromB64, utf8, fromUtf8 } from './bytes.js';

export const FORMAT = 1;

// Measured on the development machine (Artix Linux, hash-wasm 4.12.0, Node
// 24.18), 2026-08-16. Cost scales linearly with memory here, so the table is
// worth keeping:
//
//    64 MiB  t=3   204 ms
//   128 MiB  t=3   399 ms   <- chosen
//   192 MiB  t=3   595 ms
//   256 MiB  t=3   791 ms
//   128 MiB  t=4   527 ms
//
// Memory is raised in preference to iterations because it is the axis a GPU or
// an ASIC finds expensive; iterations are cheap for an attacker to parallelise.
//
// This number has NOT yet been taken on the slowest machine in the fleet, which
// is the one that decides whether the default is tolerable. Re-measure there
// and adjust. Parameters travel with the vault, so raising them later does not
// strand an existing one.
export const DEFAULT_KDF = Object.freeze({
  name: 'argon2id',
  memoryKiB: 131072, // 128 MiB
  iterations: 3,
  parallelism: 1,
});

const SALT_LEN = 16;
const KEY_LEN = 32; // AES-256
const NONCE_LEN = 12; // GCM standard; anything else costs an extra GHASH pass

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export const newSalt = () => randomBytes(SALT_LEN);
export const newVaultKey = () => randomBytes(KEY_LEN);

// Domain separation. Without distinct labels a wrapped vault key and a sealed
// record are both "AES-GCM under some key", and a blob from one context can be
// offered to the other. The label is authenticated, so a swap fails to open.
const aadWrap = (wrapper) => utf8(`bencpass:v${FORMAT}:wrap:${wrapper}`);
const aadRecord = (id, rev) => utf8(`bencpass:v${FORMAT}:rec:${id}:${rev}`);

/**
 * Stretch a master password into a master key.
 *
 * WebCrypto offers only PBKDF2, which is far weaker per unit of work against a
 * GPU. There is deliberately no PBKDF2 fallback: if the WASM will not load the
 * vault does not open, because a silent downgrade to weak parameters is worse
 * than a clear failure.
 */
export async function deriveMasterKey(password, salt, params = DEFAULT_KDF) {
  if (params.name !== 'argon2id') {
    throw new Error(`unsupported kdf: ${params.name}`);
  }
  return argon2id({
    password: utf8(password),
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: KEY_LEN,
    outputType: 'binary',
  });
}

/**
 * Import raw key bytes for use.
 *
 * `extractable: false` by default so the vault key's bytes cannot be read back
 * out of the CryptoKey. This is not a substitute for zeroing memory — you
 * cannot reliably zero a Uint8Array in JavaScript, and this project does not
 * claim to — but it does keep the one long-lived key out of reach of anything
 * that later gets a foothold in the same realm.
 */
export function importKey(bytes, { extractable = false } = {}) {
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', extractable, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * A fresh random nonce per seal, never a counter.
 *
 * At 96 bits the safe ceiling for random nonces is around 2^32 messages under
 * one key. A record is re-sealed once per edit, so reaching that would take
 * billions of edits against a single vault key. Reuse of a key+nonce pair with
 * GCM is catastrophic rather than merely weak, which is why this is the only
 * place a nonce is generated.
 */
async function seal(key, plaintext, aad) {
  const nonce = randomBytes(NONCE_LEN);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad },
    key,
    plaintext,
  );
  return { n: toB64(nonce), ct: toB64(new Uint8Array(ct)) };
}

async function open(key, blob, aad) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(blob.n), additionalData: aad },
    key,
    fromB64(blob.ct),
  );
  return new Uint8Array(pt);
}

/** Wrap the vault key under a wrapping key. `wrapper` is 'password' or 'biometric'. */
export async function wrapVaultKey(vaultKeyBytes, wrappingKeyBytes, wrapper) {
  const wk = await importKey(wrappingKeyBytes, { extractable: false });
  return { wrapper, ...(await seal(wk, vaultKeyBytes, aadWrap(wrapper))) };
}

/**
 * Unwrap the vault key.
 *
 * A wrong password and a corrupted blob are indistinguishable here, and that is
 * correct: GCM's tag is the password check, and reporting which of the two went
 * wrong would tell an attacker holding the file whether a guess was close.
 */
export async function unwrapVaultKey(blob, wrappingKeyBytes) {
  const wk = await importKey(wrappingKeyBytes, { extractable: false });
  try {
    return await open(wk, blob, aadWrap(blob.wrapper));
  } catch {
    // Carries a code so the UI can say something plainer without string-matching
    // this message, and without ever learning which of the two it was.
    const err = new Error('cannot unwrap vault key: wrong secret or damaged vault');
    err.code = 'unwrap-failed';
    throw err;
  }
}

/**
 * Seal one record.
 *
 * The AAD binds the ciphertext to its own id and revision. Without that a
 * hostile or merely buggy server can swap ciphertexts between two records, or
 * hand back an old revision of one — including a password since rotated away
 * from — and the client has no way to notice. With it, either attack fails to
 * decrypt. This is one line and it is not optional.
 */
export async function sealRecord(vaultKey, id, rev, plainObject) {
  return seal(vaultKey, utf8(JSON.stringify(plainObject)), aadRecord(id, rev));
}

export async function openRecord(vaultKey, id, rev, blob) {
  try {
    return JSON.parse(fromUtf8(await open(vaultKey, blob, aadRecord(id, rev))));
  } catch {
    throw new Error(`record ${id}@${rev} failed to open: wrong key or tampering`);
  }
}
