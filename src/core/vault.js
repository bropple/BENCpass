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

export class Vault {
  #key = null; // CryptoKey, non-extractable, null while locked
  #plain = new Map(); // id -> decrypted record, populated only while unlocked

  constructor(meta, envelopes = new Map(), syncedRev = new Map()) {
    this.meta = meta;
    this.envelopes = envelopes;
    this.syncedRev = syncedRev;
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
    if (persisted.meta?.format !== FORMAT) {
      throw new Error(`unsupported vault format: ${persisted.meta?.format}`);
    }
    return new Vault(
      persisted.meta,
      new Map(persisted.envelopes.map((e) => [e.id, e])),
      new Map(Object.entries(persisted.syncedRev ?? {})),
    );
  }

  toJSON() {
    return {
      meta: this.meta,
      envelopes: [...this.envelopes.values()],
      syncedRev: Object.fromEntries(this.syncedRev),
    };
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
      if (e.deleted) continue;
      plain.set(e.id, await openRecord(key, e.id, e.rev, e));
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
   * something the server could invent.
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

    if (!this.locked) {
      for (const [id, e] of next) {
        const cur = this.envelopes.get(id);
        if (e.deleted) {
          this.#plain.delete(id);
          continue;
        }
        if (cur && cur.rev === e.rev && this.#plain.has(id)) continue;
        try {
          this.#plain.set(id, await openRecord(this.#key, id, e.rev, e));
        } catch {
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
