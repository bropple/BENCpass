// The local vault: envelopes at rest, plaintext only while unlocked.
//
// Storage-agnostic on purpose. This class hands out a serialisable object and
// takes one back; whether that lands in browser.storage.local, a file, or a
// test's memory is not its business.

import {
  FORMAT,
  DEFAULT_KDF,
  KEY_LEN,
  newSalt,
  newVaultKey,
  deriveMasterKey,
  importKey,
  wrapVaultKey,
  unwrapVaultKey,
  sealRecord,
  openRecord,
} from './crypto.js';
import { normalise as normaliseCode, CODE_LENGTH } from './recovery.js';
import { toB64, fromB64 } from './bytes.js';
import {
  newRecord,
  applyPatch,
  markUsed,
  normalise,
  searchableFields,
} from './model.js';

export class VaultLockedError extends Error {
  constructor() {
    super('vault is locked');
  }
}

/**
 * Are two record bodies the same thing, once the clock noise is set aside?
 *
 * Used to decide whether a parked conflict is worth forking: `updated`,
 * `lastUsed` and `timesUsed` move whenever a record is touched, so two copies
 * that differ only there are one record, not two versions of it. Key order can
 * differ between a freshly built body and one parsed back out of a seal, so
 * the comparison sorts keys rather than trusting stringify's order. Being
 * wrong here only costs a duplicate fork, which a person can delete — never a
 * lost version.
 */
function sameContent(a, b) {
  const canon = (x) => {
    if (Array.isArray(x)) return x.map(canon);
    if (x && typeof x === 'object') {
      return Object.fromEntries(
        Object.keys(x)
          .sort()
          .map((k) => [k, canon(x[k])]),
      );
    }
    return x;
  };
  const stable = ({ updated, lastUsed, timesUsed, ...rest }) => JSON.stringify(canon(rest));
  return stable(a) === stable(b);
}

/**
 * Open a stored envelope, whatever its cleartext `deleted` flag claims.
 *
 * The flag is bound into the AAD, so openRecord under a flipped flag fails the
 * tag. That single failure is ambiguous — wrong key, damage, or a lie one bit
 * wide — and the three deserve different endings: the first two are fatal, the
 * lie is an attack this vault has policy for below. So on failure the one
 * other claim the envelope could have made is tried. This is not a trust
 * fallback: both attempts authenticate the full AAD, and whichever verifies
 * proves what the sealer actually wrote — the body that comes back cannot be a
 * forgery, and its own `deleted` field equals the sealed bit by construction
 * (sealRecord reads the bit off the body). Callers keep comparing e.deleted
 * against body.deleted to spot the lie, exactly as before; what changed is
 * that the truth they compare against is now signed.
 *
 * Without the retry, one flipped bit — adopted by a locked sync, which has no
 * key to check it with — would persist an envelope that fails every unlock for
 * ever: a tampering the design already survives, upgraded into a lockout.
 */
async function openEnvelope(key, e) {
  try {
    return await openRecord(key, e.id, e.rev, e);
  } catch (err) {
    try {
      return await openRecord(key, e.id, e.rev, { ...e, deleted: !e.deleted });
    } catch {
      throw err; // the first failure stands: wrong key or damage, not a flipped flag
    }
  }
}

export class Vault {
  #key = null; // CryptoKey, non-extractable, null while locked
  #plain = new Map(); // id -> decrypted record, populated only while unlocked

  constructor(meta, envelopes = new Map(), syncedRev = new Map()) {
    this.meta = meta;
    this.envelopes = envelopes;
    this.syncedRev = syncedRev;
    // Envelopes the merge parked in a conflict: the other machine's bytes,
    // still sealed, waiting for an unlocked vault to fork them into records a
    // person can see. Persisted, because a sync can run — and conflict — while
    // the vault is locked, and a parked copy that lives only in memory is a
    // parked copy that a browser restart deletes.
    this.parked = [];
    // Which parked envelopes have already been forked (or judged empty), so a
    // conflict the merge re-detects before convergence does not fork the same
    // bytes twice. The nonce is fresh per seal, so id:rev:nonce names exactly
    // one envelope ever.
    this.forkedMarks = [];
  }

  get locked() {
    return this.#key === null;
  }

  /** A fresh vault, unlocked, with one password wrapping of a new vault key. */
  static async create({ password, kdf = DEFAULT_KDF, now = Date.now() } = {}) {
    if (!password) throw new Error('a master password is required');

    const salt = newSalt();
    const masterKey = await deriveMasterKey(password, salt, kdf);
    const vaultKeyBytes = newVaultKey();

    const meta = {
      format: FORMAT,
      created: now,
      kdf: { ...kdf, salt: toB64(salt) },
      wraps: {
        password: await wrapVaultKey(vaultKeyBytes, masterKey, 'password'),
        // Opaque to us: whatever derived the device secret. Its format is the
        // host's business, and deliberately not this module's.
        biometric: null,
      },
    };

    const v = new Vault(meta);
    v.#key = await importKey(vaultKeyBytes, { extractable: false });
    return v;
  }

  /** Rehydrate from storage. Always comes back locked. */
  static load(persisted) {
    const format = persisted.meta?.format;
    if (format !== FORMAT) {
      // Refused by name, never opened by a compatibility branch. Format 1 left
      // `deleted` outside the AAD, so a reader that still accepts it hands an
      // attacker the flippable flag back — relabel the envelope and the weaker
      // binding applies. Nobody is stranded: v0.11.0 wrote format 1 but was
      // never run, so the only format-1 vaults are this repository's own
      // fixtures. A stray one deserves a plain statement, not a quiet open.
      throw new Error(
        `unsupported vault format: ${format} — this build reads format ${FORMAT} only` +
          (typeof format === 'number' && format < FORMAT
            ? `; format ${format} was written by an older BENCpass, and its weaker sealing is refused rather than read`
            : ''),
      );
    }
    const v = new Vault(
      persisted.meta,
      new Map(persisted.envelopes.map((e) => [e.id, e])),
      new Map(Object.entries(persisted.syncedRev ?? {})),
    );
    v.parked = Array.isArray(persisted.parked) ? persisted.parked : [];
    v.forkedMarks = Array.isArray(persisted.forkedMarks) ? persisted.forkedMarks : [];
    return v;
  }

  toJSON() {
    return {
      meta: this.meta,
      envelopes: [...this.envelopes.values()],
      syncedRev: Object.fromEntries(this.syncedRev),
      parked: this.parked,
      forkedMarks: this.forkedMarks,
    };
  }

  /**
   * The vault as a file to keep: the header and the sealed records, and
   * nothing that only means something on this machine.
   *
   * The fingerprint wrapping is deliberately dropped. It wraps the same vault
   * key as the password does, and the secret that opens it is a WebAuthn PRF
   * output which the authenticator will release to any caller that can present
   * the credential — including, for a passkey that syncs, one on another of
   * the account's devices. Leaving it in would mean a file the interface calls
   * safe to email is openable by a fingerprint, which is not what "needs your
   * master password or your recovery code" says. Nothing can use it anyway:
   * the only reader of this file is a program outside the browser, and no such
   * program can talk to an authenticator.
   *
   * `syncedRev` goes for the plainer reason that it is this machine's private
   * note about what it has already sent to a server.
   *
   * Cloned rather than edited. `toJSON` hands back `this.meta` itself, so
   * blanking the wrap in place would remove the live vault's fingerprint
   * unlock as a side effect of taking a backup.
   */
  backup() {
    const { envelopes } = this.toJSON();
    return { meta: this.portableMeta, envelopes };
  }

  /**
   * The header as it should leave this machine, by any route.
   *
   * A fingerprint wrapping is the one part of the header that is local to the
   * machine that made it. The secret behind it lives in that machine's
   * authenticator, so no other machine can use it — but any machine, or any
   * server, that holds the wrap holds a way into the vault for whoever can
   * present that credential, which for a passkey that syncs is not
   * necessarily the owner.
   *
   * So it is stripped on the way out, whether the destination is a file or a
   * server. Both used to do this separately and one of them did not do it at
   * all; there is one rule and this is where it lives.
   *
   * Cloned, never edited: `meta` is the live object, and blanking the wrap in
   * place would take this machine's own fingerprint unlock with it.
   */
  get portableMeta() {
    const { wraps, ...rest } = this.meta;
    return { ...rest, wraps: { ...wraps, biometric: null } };
  }

  /**
   * A header arriving from somewhere else, made safe to adopt.
   *
   * Whatever a server hands over, this machine cannot use another machine's
   * fingerprint wrapping — the secret is in that machine's authenticator. A
   * vault that claims a fingerprint it cannot produce offers an unlock that
   * always fails, so the claim is dropped rather than inherited. It also means
   * a header published by an older version, which sent the wrap, does not
   * strand the machine that joins from it.
   */
  static adoptMeta(meta) {
    if (!meta?.wraps) return meta;
    return { ...meta, wraps: { ...meta.wraps, biometric: null } };
  }

  // ---- unlocking -----------------------------------------------------------

  async unlock(password) {
    const { kdf } = this.meta;
    const masterKey = await deriveMasterKey(password, fromB64(kdf.salt), kdf);
    const vaultKeyBytes = await unwrapVaultKey(this.meta.wraps.password, masterKey);
    await this.unlockWithVaultKey(vaultKeyBytes);
  }

  /**
   * Unlock from a vault key obtained some other way — in practice, handed back
   * by WebAuthn PRF, which the authenticator releases behind a fingerprint.
   * The two unlock paths converge here, which is the point of the hierarchy.
   */
  async unlockWithVaultKey(vaultKeyBytes) {
    const key = await importKey(vaultKeyBytes, { extractable: false });
    const plain = new Map();
    for (const e of this.envelopes.values()) {
      // Opened before it is believed. `deleted` sits beside the ciphertext in
      // the clear, so anyone who last wrote the file — the server, or anyone
      // with the profile — can flip it; skipping on it unopened would take
      // their word. It is bound into the AAD, so a flipped flag no longer
      // opens as anything: openEnvelope recovers the claim the sealer actually
      // signed, and everything after this line is policy for a detected lie,
      // not detection. Flip a live record to deleted and it must not vanish;
      // flip a tombstone to live and it must not come back.
      const body = await openEnvelope(key, e);
      // An envelope whose cleartext flag claims a deletion its sealed body
      // does not make is something no client of this code ever wrote — the
      // two are always set together — so the flag was flipped somewhere. Who
      // could have flipped it decides who wins. `overTombstone` is stamped by
      // a LOCKED applyEnvelopes when it replaces this vault's own tombstone
      // on the flag's unverifiable word; a mismatch there means the SERVER
      // lied to get past the deletion, and believing the body now would hand
      // it exactly the resurrection merge refused. The id stays deleted and
      // the live body is parked: it comes back as a visible "(conflict)"
      // record — a recovery a person performs, not one a server performs.
      // Without the stamp the envelope never crossed a tombstone, the flip
      // can only be local-file tampering, and the sealed body is the
      // authority as it always was: the record must not vanish.
      if (e.deleted && !body?.deleted && e.overTombstone) {
        this.park([e]);
        continue;
      }
      if (body?.deleted) continue;
      plain.set(e.id, body);
    }
    this.#key = key;
    this.#plain = plain;
  }

  lock() {
    this.#key = null;
    this.#plain = new Map();
  }

  // ---- the second wrapping ---------------------------------------------------
  //
  // The vault key is wrapped twice, under two independent secrets: the master
  // password, and a random 32-byte device secret the operating system's keystore
  // holds behind a fingerprint. Neither wrapping can produce the other, and
  // removing one leaves the other untouched — which is what makes "turn Touch ID
  // off on this laptop" a local act rather than a re-encryption of the vault.
  //
  // The host never sees the vault key or the master password. It keeps a random
  // string it cannot interpret, and hands it back when the OS says the right
  // person asked. Everything cryptographic stays in here.

  /** Is there a second wrapping on this machine's copy? */
  get hasBiometric() {
    return Boolean(this.meta.wraps?.biometric);
  }

  /**
   * Add the second wrapping.
   *
   * The master password is required and that is not a formality: the vault key
   * lives in a non-extractable CryptoKey once unlocked, so its bytes cannot be
   * read back out to wrap them again. They have to be re-derived, which means
   * proving you know the password — exactly the right price for granting a
   * fingerprint the same power over the vault.
   */
  async enrolBiometric(password, secretBytes) {
    if (!password) throw new Error('a master password is required');
    if (secretBytes?.length !== KEY_LEN) {
      throw new Error(`device secret must be ${KEY_LEN} bytes`);
    }

    const { kdf } = this.meta;
    const masterKey = await deriveMasterKey(password, fromB64(kdf.salt), kdf);
    const vaultKeyBytes = await unwrapVaultKey(this.meta.wraps.password, masterKey);
    this.meta.wraps.biometric = await wrapVaultKey(vaultKeyBytes, secretBytes, 'biometric');
  }

  /**
   * Wrap the vault key a third time, under a recovery code.
   *
   * The same shape as the fingerprint wrapping and for the same reason: an
   * independent secret that reaches the same key. The difference is what it is
   * for — the fingerprint saves you typing, this one saves you from having
   * forgotten.
   *
   * Costs the master password, because the vault key is a non-extractable
   * CryptoKey once unlocked and there is no way to a second wrapping except by
   * deriving it again. That is also the guarantee: only somebody who can
   * already open the vault can mint a way back into it.
   *
   * The code gets its own salt. Sharing the password's would mean one Argon2
   * derivation served both, so cracking either would be cracking both.
   */
  async enrolRecovery(password, code, now = Date.now()) {
    this.adoptRecoveryWrap(await this.mintRecoveryWrap(password, code, now));
  }

  /**
   * Build the recovery wrapping without adopting it.
   *
   * Split from enrolRecovery so the UI can show the code before the vault
   * commits to it. Enrolling first and displaying second left a phantom: close
   * the tab at the sheet and the gate offers a recovery code that was never on
   * anyone's screen — a way back in that nobody holds. Minting here still
   * proves the master password (a wrong one fails the unwrap before anything
   * is shown), but nothing changes until adoptRecoveryWrap is called with the
   * result, which the sheet does only on "I have written it down".
   */
  async mintRecoveryWrap(password, code, now = Date.now()) {
    if (!password) throw new Error('a master password is required');
    const cleaned = normaliseCode(code);
    if (cleaned.length < CODE_LENGTH) throw new Error('that is not a full recovery code');

    const { kdf } = this.meta;
    const masterKey = await deriveMasterKey(password, fromB64(kdf.salt), kdf);
    const vaultKeyBytes = await unwrapVaultKey(this.meta.wraps.password, masterKey);

    const salt = newSalt();
    const recoveryKey = await deriveMasterKey(cleaned, salt, kdf);
    return {
      ...(await wrapVaultKey(vaultKeyBytes, recoveryKey, 'recovery')),
      salt: toB64(salt),
      created: now,
    };
  }

  /** The moment the code becomes real. The caller persists. */
  adoptRecoveryWrap(wrap) {
    this.meta.wraps.recovery = wrap;
  }

  /** Is there a way back in without the master password? */
  get hasRecovery() {
    return Boolean(this.meta.wraps?.recovery);
  }

  /**
   * Open the vault with the recovery code instead of the master password.
   *
   * Deliberately does not then change the password. Recovering and choosing a
   * new password are two decisions, and doing the second silently would mean a
   * mistyped recovery attempt could leave somebody locked out of a vault they
   * had just opened.
   */
  async unlockWithRecoveryCode(code) {
    const wrap = this.meta.wraps?.recovery;
    if (!wrap) throw new Error('this vault has no recovery wrapping');

    const cleaned = normaliseCode(code);
    const recoveryKey = await deriveMasterKey(cleaned, fromB64(wrap.salt), this.meta.kdf);
    const vaultKeyBytes = await unwrapVaultKey(wrap, recoveryKey);
    await this.unlockWithVaultKey(vaultKeyBytes);
  }

  /**
   * Drop the recovery wrapping.
   *
   * Local, like forgetting a fingerprint: it removes this vault's way back,
   * and touches neither the password wrapping nor any other machine.
   */
  forgetRecovery() {
    this.meta.wraps.recovery = null;
  }

  /** Unlock from the device secret the OS keystore just released. */
  async unlockWithBiometricSecret(secretBytes) {
    if (!this.hasBiometric) throw new Error('this vault has no biometric wrapping');
    const vaultKeyBytes = await unwrapVaultKey(this.meta.wraps.biometric, secretBytes);
    await this.unlockWithVaultKey(vaultKeyBytes);
  }

  /**
   * Drop the second wrapping.
   *
   * Local and immediate: the vault key does not change, so every other machine
   * and the server are unaffected, and nothing has to be re-encrypted. Whoever
   * calls this is also responsible for telling the host to forget its secret —
   * though a secret whose wrapping is gone opens nothing.
   */
  forgetBiometric() {
    this.meta.wraps.biometric = null;
  }

  #require() {
    if (this.locked) throw new VaultLockedError();
    return this.#key;
  }

  // ---- records -------------------------------------------------------------

  async add(fields, now = Date.now()) {
    const key = this.#require();
    const id = crypto.randomUUID();
    const plain = newRecord(fields, now);
    await this.#write(key, id, 1, plain);
    return id;
  }

  async update(id, patch, now = Date.now()) {
    const key = this.#require();
    const plain = this.#plain.get(id);
    if (!plain) throw new Error(`no such record: ${id}`);
    const env = this.envelopes.get(id);
    await this.#write(key, id, env.rev + 1, applyPatch(plain, patch, now));
  }

  async touchUsed(id, now = Date.now()) {
    const key = this.#require();
    const plain = this.#plain.get(id);
    if (!plain) throw new Error(`no such record: ${id}`);
    const env = this.envelopes.get(id);
    await this.#write(key, id, env.rev + 1, markUsed(plain, now));
  }

  /**
   * Tombstone, never a hard delete — a removal has to be a fact that can sync,
   * and a record that simply vanishes is indistinguishable from one that never
   * arrived.
   *
   * The tombstone carries a sealed body rather than an empty one so that it is
   * authenticated like any other revision. A bare `deleted: true` flag would be
   * something the server could invent. The flag stays in the envelope because
   * merge.js works on a locked vault and needs to see that a removal exists —
   * and it is bound into the AAD, so the copy merge steers by is the copy the
   * sealer signed: inventing or flipping it breaks the seal at the first
   * decrypt.
   */
  async remove(id, now = Date.now()) {
    const key = this.#require();
    const env = this.envelopes.get(id);
    if (!env) throw new Error(`no such record: ${id}`);
    const blob = await sealRecord(key, id, env.rev + 1, { deleted: true, at: now });
    this.envelopes.set(id, { id, rev: env.rev + 1, deleted: true, ...blob });
    this.#plain.delete(id);
  }

  async #write(key, id, rev, plain) {
    // Re-sealed on every revision because the AAD binds id and rev together;
    // reusing the old ciphertext under a new rev would not open.
    const blob = await sealRecord(key, id, rev, plain);
    this.envelopes.set(id, { id, rev, deleted: false, ...blob });
    this.#plain.set(id, plain);
  }

  // ---- reading -------------------------------------------------------------

  get(id) {
    this.#require();
    const plain = this.#plain.get(id);
    return plain ? { id, rev: this.envelopes.get(id).rev, ...plain } : undefined;
  }

  /** All records, or only those of one type. */
  list(type = null) {
    this.#require();
    const all = [...this.#plain.keys()].map((id) => this.get(id));
    return type ? all.filter((r) => r.type === type) : all;
  }

  search(query, type = null) {
    const q = query.trim().toLowerCase();
    if (!q) return this.list(type);
    return this.list(type).filter((r) =>
      searchableFields(r)
        .filter(Boolean)
        .some((s) => String(s).toLowerCase().includes(q)),
    );
  }

  // ---- conflicts -----------------------------------------------------------
  //
  // merge() parks the losing side of a conflict — the other machine's bytes,
  // or the edit a tombstone beat. For a long time that was where the story
  // ended: nothing persisted the parked envelope, and the manager's "N
  // conflict(s) kept" described a keep that never happened. Deleting the other
  // machine's password silently is the one thing a sync must never do, so the
  // park is now real: envelopes land here (no key needed, so a background sync
  // on a locked vault keeps them too), survive in storage, and are forked into
  // ordinary records the next time the vault is open. The person then sees
  // both versions side by side and deletes the wrong one — a decision that
  // syncs like any other, so every machine converges on it.

  /** How many fork marks to remember. Far above any plausible conflict rate;
   *  the cap only stops the list growing without bound over years. */
  static MARKS_MAX = 512;

  #mark(e) {
    return `${e.id}:${e.rev}:${e.n}`;
  }

  /**
   * Keep the losing envelopes of a merge. Key-free on purpose: this is called
   * from the sync path, which runs on a locked vault.
   *
   * Deduplicated against what is already parked and what was already forked,
   * because the same conflict is re-detected on every sync until the machines
   * converge, and each detection hands over the same bytes.
   */
  park(envelopes) {
    const seen = new Set([...this.forkedMarks, ...this.parked.map((e) => this.#mark(e))]);
    let added = 0;
    for (const e of envelopes) {
      if (!e || seen.has(this.#mark(e))) continue;
      seen.add(this.#mark(e));
      this.parked.push(e);
      added++;
    }
    return added;
  }

  /**
   * Turn every parked envelope into a record a person can see.
   *
   * Each live body becomes a fresh record titled "<title> (conflict)", carrying
   * `conflictOf` so the UI can say what it is. A parked tombstone is dropped —
   * there is nothing in it to recover — and a body identical to the current
   * record (timestamps aside) is dropped too, since forking it would only
   * manufacture a duplicate of the copy that won.
   *
   * Needs the key, so it runs after unlock. The caller persists.
   *
   * @returns the ids of the records forked.
   */
  async resolveParked(now = Date.now()) {
    const key = this.#require();
    const forked = [];

    for (const e of this.parked) {
      this.forkedMarks.push(this.#mark(e));

      let body;
      try {
        // openEnvelope, because what gets parked includes the one envelope
        // whose flag is known to lie: a live edit the server dressed as a
        // tombstone to cross ours. Its flag fails the AAD; the seal beneath
        // is genuine, and that body is exactly what the person needs to see.
        body = await openEnvelope(key, e);
      } catch {
        // Sealed under a different key. This vault cannot ever read it, and
        // keeping it parked would just re-fail here forever.
        continue;
      }
      if (!body || body.deleted) continue;

      const current = this.#plain.get(e.id);
      if (current && sameContent(current, body)) continue;

      const stamp = new Date(now).toISOString().slice(0, 10);
      const changed = new Date(body.updated ?? body.created ?? now).toISOString().slice(0, 10);
      const plain = {
        ...body,
        title: `${body.title || '(untitled)'} (conflict)`,
        conflictOf: e.id,
        notes: [
          body.notes,
          `Kept from a sync conflict found on ${stamp}: another machine changed or ` +
            `deleted this entry at the same time as this copy was written. ` +
            `This copy was last changed on ${changed}. Compare it with the current ` +
            `entry, if one still exists, and delete whichever is wrong.`,
        ]
          .filter(Boolean)
          .join('\n\n'),
        // `updated` is deliberately NOT stamped to now. Deciding which of two
        // copies to keep means knowing which was written last, and stamping the
        // fork with the moment it was forked destroys exactly that — both
        // copies then claim the same date, and the one question the person has
        // becomes unanswerable. The conflict's own date is in the note above,
        // where it belongs; this field stays the date this copy was written.
        updated: body.updated ?? now,
      };

      const id = crypto.randomUUID();
      await this.#write(key, id, 1, plain);
      forked.push(id);
    }

    this.parked = [];
    if (this.forkedMarks.length > Vault.MARKS_MAX) {
      this.forkedMarks = this.forkedMarks.slice(-Vault.MARKS_MAX);
    }
    return forked;
  }

  /**
   * Re-seal a record's current content at a revision above `aboveRev`.
   *
   * This is what makes a conflict converge instead of recurring. Two machines
   * that edit from the same ancestor both count to the same rev with different
   * bytes; each one's merge keeps its own copy and pushes it, so the server
   * flips between the two forever and neither side ever fast-forwards. Sealing
   * the surviving copy one revision above both sides breaks the tie: the next
   * pull on the other machine is a plain fast-forward, and the version it lost
   * comes back to it as the forked "(conflict)" record. Revisions only ever
   * move up here, which is also what the rollback guards insist on.
   *
   * Works on tombstones as well as live records — a deletion that wins a
   * conflict at an equal rev has exactly the same tie to break.
   */
  async supersede(id, aboveRev) {
    const key = this.#require();
    const env = this.envelopes.get(id);
    if (!env) throw new Error(`no such record: ${id}`);

    const rev = Math.max(env.rev, aboveRev) + 1;
    const body = this.#plain.get(id) ?? (await openEnvelope(key, env));
    const blob = await sealRecord(key, id, rev, body);
    this.envelopes.set(id, { id, rev, deleted: Boolean(body?.deleted), ...blob });
    return rev;
  }

  // ---- sync ----------------------------------------------------------------

  /**
   * Adopt a merged envelope set.
   *
   * A locked vault takes the envelopes and nothing else, which is what allows a
   * sync to run in the background without a master password. An unlocked one
   * additionally re-opens whatever changed — and only what changed, since
   * re-decrypting an untouched vault on every poll would be the most expensive
   * thing the client does.
   */
  async applyEnvelopes(envelopes) {
    const next =
      envelopes instanceof Map ? new Map(envelopes) : new Map(envelopes.map((e) => [e.id, e]));

    // The revision comparison runs for a locked vault too — it needs only the
    // numbers, not the key. It used to live solely inside the unlocked block
    // below, which meant the one sync that runs unattended, the background
    // sync on a locked vault, was exactly the one with no belt at all. The
    // cleartext `deleted` flag is the best a locked vault can do for the
    // tombstone exception; the unlocked path re-checks against the sealed
    // body, which is the authority, the moment there is a key to open it with.
    for (const [id, e] of next) {
      const cur = this.envelopes.get(id);
      if (cur && e.rev < cur.rev && !e.deleted) {
        next.set(id, cur);
        continue;
      }
      // A locked vault replacing its own tombstone is taking the incoming
      // flag's word for the deletion continuing — the one claim it cannot
      // verify without the key. The adoption is stamped so that the unlock,
      // which can verify, knows this envelope crossed a tombstone: if its
      // sealed body then turns out to be live, the flag was flipped by the
      // server to resurrect the record, not by someone editing the local
      // file, and the deletion is honoured. Locked path only — the unlocked
      // block below verifies immediately and refuses instead.
      if (this.locked && cur?.deleted && (e.rev !== cur.rev || e.ct !== cur.ct || e.n !== cur.n)) {
        next.set(id, { ...e, overTombstone: true });
      }
    }

    if (!this.locked) {
      for (const [id, e] of next) {
        const cur = this.envelopes.get(id);
        // Unchanged means the same bytes, not the same number. Two machines
        // that edit from one ancestor both count to the same rev with
        // different ciphertext, and merge resolves that divergence — so an
        // envelope at the current rev can still be a different envelope.
        // Skipping on rev alone left the old plaintext on screen over the new
        // envelope: a same-rev tombstone was stored but the record it deleted
        // stayed visible until the next unlock quietly vanished it.
        if (cur && cur.rev === e.rev && cur.ct === e.ct && this.#plain.has(id)) continue;
        try {
          // Same reasoning as unlockWithVaultKey: the flag is the server's to
          // flip, the seal is not. openEnvelope opens under the claim the
          // sealer signed even when the stored flag lies about it.
          const body = await openEnvelope(this.#key, e);

          // The flag is bound into the AAD, but merge, key-free, still has to
          // take it at its word (it is what lets tombstone-over-tombstone
          // fast-forward). This is where the word is checked, now against a
          // sealed truth rather than a plausible one. No client ever writes
          // the flag and the body disagreeing — sealRecord reads the AAD bit
          // off the body — so a mismatch on an INCOMING envelope is tampering,
          // not a version skew; it is refused loudly like a rollback, before
          // anything is adopted. An envelope already local (a locked sync
          // adopted it on the flag's word) is not re-refused — that would turn
          // one tampered pull into a machine that never syncs again — it is
          // held to the same rule unlockWithVaultKey applies: stamped as
          // having crossed our tombstone, it stays deleted and its live body
          // is parked for a person; unstamped, the body is the authority.
          if (Boolean(e.deleted) !== Boolean(body?.deleted)) {
            const changed = !cur || cur.rev !== e.rev || cur.ct !== e.ct || cur.n !== e.n;
            if (changed) {
              const err = new Error(
                `record ${id}@${e.rev}: the envelope's deleted flag contradicts its sealed ` +
                  `body — the flag was tampered with in transit or on the server`,
              );
              err.code = 'tampered';
              throw err;
            }
            if (e.deleted && !body?.deleted && e.overTombstone) {
              this.park([e]);
              this.#plain.delete(id);
              continue;
            }
          }

          // A live record must never go backwards here.
          //
          // Belt and braces: merge() already refuses a server that serves a
          // revision below the one it had acknowledged, which is the route an
          // attacker actually has. This is the same rule one layer down, so
          // that a future caller who forgets to merge cannot hand the vault an
          // old envelope and roll a rotated-away password back. The envelope
          // would open — it was genuinely sealed at that revision, so its AAD
          // verifies — which is exactly why the check has to be here rather
          // than left to the cryptography.
          //
          // Deliberately not "refuse every lower revision": a tombstone
          // legitimately arrives below the local revision when a deletion on
          // one machine races an edit on another, and merge resolves that in
          // the tombstone's favour. Deleting is the fail-safe direction, so a
          // regression is refused only when the body says the record is alive.
          if (cur && e.rev < cur.rev && !body?.deleted) {
            next.set(id, cur);
            continue;
          }

          if (body?.deleted) {
            this.#plain.delete(id);
            continue;
          }
          this.#plain.set(id, body);
        } catch (cause) {
          if (cause?.code === 'tampered') throw cause;
          // Almost always one cause: this vault was pointed at a server holding
          // someone else's — or an older, differently-keyed — vault. Saying so
          // beats a decrypt failure on an arbitrary record, which reads like
          // corruption and invites the wrong fix.
          const err = new Error(
            `record ${id} was sealed with a different vault key — ` +
              `this endpoint holds a different vault`,
          );
          err.code = 'key-mismatch';
          throw err;
        }
      }
      for (const id of [...this.#plain.keys()]) {
        if (!next.has(id)) this.#plain.delete(id);
      }
    }

    this.envelopes = next;
  }

  // ---- import / export -----------------------------------------------------

  /**
   * Bulk import. Timestamps are normalised and future-dated ones clamped, since
   * importers are where nonsensical clocks arrive from.
   */
  async importRecords(records, now = Date.now()) {
    const key = this.#require();
    const ids = [];
    for (const input of records) {
      const id = crypto.randomUUID();
      await this.#write(key, id, 1, normalise(input, now));
      ids.push(id);
    }
    return ids;
  }

  /**
   * Plaintext export.
   *
   * Built before the importer, on purpose: a vault that data can only go into
   * is a trap, and this is the escape hatch that has to work on the worst day.
   * The caller is responsible for making its use a deliberate, warned act.
   */
  exportPlain() {
    return this.list();
  }
}
