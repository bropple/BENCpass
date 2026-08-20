// BENCpass crypto core.
//
// Deliberately free of any `browser.*` API so it runs and is tested under plain
// Node. Everything that touches storage or the extension lives elsewhere.
//
//   master password ──Argon2id──▶ master key ─┐
//                                             ├─unwrap─▶ vault key ──▶ records
//   biometric secret ──WebAuthn PRF───────────┘
//
// Two independent wrappings of the same vault key. Changing the master password
// rewraps one key rather than re-encrypting the vault, and enrolling or dropping
// biometrics touches nothing else.

import { argon2id } from './argon2.js';
import { toB64, fromB64, utf8, fromUtf8 } from './bytes.js';

// The format number is stamped on the vault header and bound into every AAD,
// so it versions the cryptography itself: bump it and nothing sealed before
// opens. Format 2 added the `deleted` flag to the record AAD; format 1 left it
// a cleartext claim anyone holding the file could flip. There is deliberately
// no code that still reads format 1 — a reader that accepts an older AAD is a
// downgrade path, since an attacker relabelling an envelope as the old format
// gets the weaker binding back. Nothing is stranded by the refusal: v0.11.0
// shipped format 1 but was never run, so no format-1 vault exists outside this
// repository's own history.
export const FORMAT = 2;

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
export const KEY_LEN = 32; // AES-256
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
// The tombstone bit rides in the AAD because it is the one routing fact that
// lives outside the ciphertext — merge() runs on a locked vault and steers by
// it. Left unbound it was a claim nobody signed: set it on a live envelope and
// the record vanishes for its owner, clear it on a tombstone and a deleted
// password comes back, and no key is needed for either. Bound, a flipped flag
// is a broken seal.
const aadRecord = (id, rev, deleted) =>
  utf8(`bencpass:v${FORMAT}:rec:${id}:${rev}:${deleted ? 1 : 0}`);
const aadHeader = () => utf8(`bencpass:v${FORMAT}:meta`);

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

// ---- the header proof --------------------------------------------------------
//
// A machine can only adopt a vault header it did not write — after a master
// password change on another machine — if it can tell a header the vault key's
// holder published from one the server invented or replayed. The server holds
// no key, so the vault key itself is the authority: the publishing side seals
// the header's canonical form (generation included) under the vault key, and
// the adopting side, having unwrapped that key with the password the person
// typed, opens the seal and compares. A replayed old header re-labelled with a
// higher generation fails the comparison; a header the server composed fails
// to open at all. What this deliberately does NOT protect is the very first
// header a joining machine sees — a join is trust-on-first-use by nature, and
// the enrolment code's sequence floor is that path's defence.

/** One stable string per header content. Key order must not matter — a header
 *  that has crossed JSON.parse can come back in any order — and the proof and
 *  the biometric wrapping are excluded by construction: the first cannot cover
 *  itself, the second never leaves the machine that made it. */
const canonJson = (x) => {
  if (Array.isArray(x)) return `[${x.map(canonJson).join(',')}]`;
  if (x && typeof x === 'object') {
    return `{${Object.keys(x)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonJson(x[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(x ?? null);
};

export function headerCanonical(meta) {
  return canonJson({
    format: meta.format,
    created: meta.created ?? null,
    gen: meta.gen ?? 0,
    changedAt: meta.changedAt ?? null,
    kdf: meta.kdf,
    wraps: {
      password: meta.wraps?.password ?? null,
      recovery: meta.wraps?.recovery ?? null,
    },
  });
}

export async function sealHeaderProof(vaultKey, meta) {
  return seal(vaultKey, utf8(headerCanonical(meta)), aadHeader());
}

/** True only if this header, exactly as it stands, was sealed by the holder of
 *  this vault key. Never throws: a proof that will not open is simply false. */
export async function verifyHeaderProof(vaultKey, meta) {
  const proof = meta?.proof;
  if (!proof?.ct || !proof?.n) return false;
  try {
    return fromUtf8(await open(vaultKey, proof, aadHeader())) === headerCanonical(meta);
  } catch {
    return false;
  }
}

/**
 * Seal one record.
 *
 * The AAD binds the ciphertext to its own id, its revision, and whether it is
 * a tombstone. Without the first two a hostile or merely buggy server can swap
 * ciphertexts between two records, or hand back an old revision of one —
 * including a password since rotated away from — and the client has no way to
 * notice. Without the third, whoever holds the file decides which records
 * exist. With all three, each attack fails to decrypt.
 *
 * The tombstone bit is read off the body being sealed, never taken as a
 * parameter, so there is no seal site at which the envelope's flag and the
 * sealed truth can be written to disagree.
 */
export async function sealRecord(vaultKey, id, rev, plainObject) {
  return seal(
    vaultKey,
    utf8(JSON.stringify(plainObject)),
    aadRecord(id, rev, Boolean(plainObject?.deleted)),
  );
}

/**
 * Open one record. `blob.deleted` is the envelope's cleartext claim, and it
 * goes into the AAD — so a claim the sealer never made fails the tag here
 * rather than being believed by whatever reads the result.
 */
export async function openRecord(vaultKey, id, rev, blob) {
  try {
    return JSON.parse(
      fromUtf8(await open(vaultKey, blob, aadRecord(id, rev, Boolean(blob.deleted)))),
    );
  } catch {
    throw new Error(`record ${id}@${rev} failed to open: wrong key or tampering`);
  }
}
