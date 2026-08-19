// The sync client.
//
// Talks to bencpass-server, which stores ciphertext and orders it, and does the
// merging here because the server has no key and could not merge if it wanted
// to. Nothing in this file can read a record either — it moves envelopes.

import { toB64, fromB64, utf8, toHex } from './bytes.js';
import { merge, confirmPushed } from './merge.js';

export class SyncError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

// ---- request signing -------------------------------------------------------

/**
 * The exact string the server signs, mirrored from server/auth.go.
 *
 * Both sides must agree character for character; a disagreement about a
 * trailing slash or a dropped query string surfaces as a 401 with nothing
 * pointing at the cause. That is why the integration test runs against the real
 * Go binary rather than a mock of it.
 *
 *   METHOD \n host \n /path?query \n unix-millis \n nonce \n If-Match \n sha256(body)
 *
 * The host is signed because this client holds two addresses for one server and
 * moves between them. Something listening on the address it tries first can
 * read a complete signed request and then drop the connection: the client sees
 * an unreachable address, quietly succeeds against the other one, and the
 * listener is left holding a request it can send on. Naming the host in the
 * signature makes that copy good only against the address it already reached.
 */
/**
 * The version of the signed format below, mirrored from server/auth.go.
 *
 * Bump both together whenever the canonical string changes — a field added,
 * removed, reordered or reinterpreted — because any of those makes every older
 * client's signature wrong.
 *
 * It exists because of what a mismatch looks like without it. The two sides
 * disagree about one string, every request comes back 401, and 401 is also what
 * a wrong device key returns; the format has already moved three times and each
 * time the symptom was identical to a credential problem. /v1/health reports
 * this number without a signature, so a client can find out that it is speaking
 * the wrong language rather than being told its key is bad.
 */
export const PROTOCOL = 2;

export function canonical(method, host, uri, ts, nonce, ifMatch, bodyHashHex) {
  return `${method}\n${host}\n${uri}\n${ts}\n${nonce}\n${ifMatch}\n${bodyHashHex}`;
}

/**
 * A value this request will not use twice.
 *
 * The server remembers these for as long as the clock window and refuses a
 * repeat, which is what stops a captured request being replayed inside it. 16
 * bytes, so two of them never collide by accident.
 */
const newNonce = () => toHex(crypto.getRandomValues(new Uint8Array(16)));

async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

async function hmacB64(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return toB64(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(message))));
}

// ---- client ----------------------------------------------------------------

export class SyncClient {
  /**
   * @param {string}   endpoint   e.g. https://box.tailnet.ts.net:8788
   * @param {string[]} endpoints  the same server by more than one route
   * @param {string}   deviceId   issued at enrolment
   * @param {Uint8Array} key      the device's HMAC key
   *
   * More than one address is for one server reached two ways — a LAN address
   * at home and a Tailscale name from anywhere — and they must be the same
   * server. Two different servers here would be two different vaults taking
   * turns, and the merge would treat every switch as an enormous conflict.
   */
  constructor({
    endpoint,
    endpoints,
    deviceId,
    key,
    fetch: f = globalThis.fetch,
    preferred = '',
    probeTimeoutMs = 4000,
  }) {
    const strip = (e) => String(e).replace(/\/+$/, '');
    this.endpoints = (endpoints ?? [endpoint]).filter(Boolean).map(strip);
    if (!this.endpoints.length) throw new SyncError('no endpoint configured', 'config');
    this.deviceId = deviceId;
    this.key = key;
    this.fetch = f;
    this.probeTimeoutMs = probeTimeoutMs;

    // Which address answered last. Tried first, so the common case is one
    // request to one address rather than a failure and a retry.
    //
    // Seeded by name rather than by index, because the caller persists it
    // across sessions and the list can be edited in between — an index would
    // silently come to mean the other server.
    const at = this.endpoints.indexOf(strip(preferred ?? ''));
    this.preferred = at === -1 ? 0 : at;
  }

  /** The address currently believed to work. */
  get endpoint() {
    return this.endpoints[this.preferred];
  }

  /**
   * Try each address until one answers at the transport level.
   *
   * A refusal is not a reason to try elsewhere. If the server answers 401, the
   * same server on its other address answers 401 too, and retrying only doubles
   * the noise — so only a thrown fetch, meaning nothing was reachable, moves on
   * to the next address.
   */
  async #reach(path, makeInit) {
    const order = [
      ...this.endpoints.slice(this.preferred),
      ...this.endpoints.slice(0, this.preferred),
    ];
    const failures = [];

    for (const [i, base] of order.entries()) {
      const last = i === order.length - 1;
      try {
        // Every attempt but the last is time-boxed. A LAN address on a foreign
        // network does not refuse — there is nothing there to refuse, so the
        // packets go nowhere and the connection waits out the operating
        // system's TCP timeout, which is tens of seconds. That is the whole
        // cost of being away from home, paid on every sync.
        //
        // The last attempt gets as long as it needs: by then there is nothing
        // to fall back to, and a real sync of a large vault over a slow link is
        // not a failure.
        // Signed here, per address, rather than once for the whole attempt:
        // the host is part of what is signed, so a request built for one
        // address is not valid at the other. Each attempt also draws its own
        // nonce, which is what makes a retry after a genuine timeout work —
        // the server refuses a nonce it has already seen, and a retry that
        // reused one would look exactly like the replay this defends against.
        const init = await makeInit(base);
        const resp = await this.fetch(base + path, {
          ...init,
          signal: last ? init?.signal : AbortSignal.timeout(this.probeTimeoutMs),
        });
        this.preferred = this.endpoints.indexOf(base);
        return resp;
      } catch (err) {
        failures.push(`${base}: ${err?.message ?? err}`);
      }
    }
    throw new SyncError(`no route to the server — ${failures.join('; ')}`, 'unreachable');
  }

  /**
   * Redeem a one-time enrolment code. Unauthenticated by necessity — this is
   * where a device acquires the credential everything else is signed with.
   */
  static async enrol({ endpoint, endpoints, code, name, fetch: f = globalThis.fetch }) {
    // The same failover as any other request: a device enrolling from the sofa
    // should not have to be told which of its two addresses is reachable today.
    const bases = (endpoints ?? [endpoint]).filter(Boolean).map((e) => String(e).replace(/\/+$/, ''));
    let resp = null;
    const failures = [];
    for (const base of bases) {
      try {
        resp = await f(`${base}/v1/enrol`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, name }),
        });
        break;
      } catch (err) {
        failures.push(`${base}: ${err?.message ?? err}`);
      }
    }
    if (!resp) throw new SyncError(`no route to the server — ${failures.join('; ')}`, 'unreachable');
    if (!resp.ok) throw new SyncError('enrolment refused: unknown or expired code', 'enrol');
    const out = await resp.json();
    return { deviceId: out.deviceId, key: fromB64(out.key) };
  }

  async request(method, path, body = null, headers = {}) {
    // Serialise once and sign those exact bytes — re-stringifying for the send
    // could reorder keys and invalidate the signature.
    const raw = body === null ? new Uint8Array(0) : utf8(JSON.stringify(body));
    const bodyHash = await sha256Hex(raw);

    const resp = await this.#reach(path, async (base) => {
      const ts = String(Date.now());
      const nonce = newNonce();
      // `host` and not the whole base: it is what the server reads back out of
      // the Host header, port and all, and the two have to agree exactly.
      const host = new URL(base).host;
      // If-Match is signed, not merely sent: it decides whether the write is
      // checked at all, so leaving it outside the signature would let anyone on
      // the path turn a compare-and-swap into an overwrite without touching
      // anything the signature covers.
      const ifMatch = headers['If-Match'] ?? '';
      const sig = await hmacB64(
        this.key,
        canonical(method, host, path, ts, nonce, ifMatch, bodyHash),
      );
      return {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Bencpass-Device': this.deviceId,
          'X-Bencpass-Time': ts,
          'X-Bencpass-Sig': sig,
          'X-Bencpass-Nonce': nonce,
          ...headers,
        },
        body: method === 'GET' ? undefined : raw,
      };
    });

    const out = await resp.json().catch(() => ({}));
    return { status: resp.status, body: out };
  }

  /**
   * What is at this address, and can we talk to it?
   *
   * Unauthenticated, so it answers before a device is enrolled — which is when
   * the address is most likely to be wrong.
   */
  async health() {
    const resp = await this.fetch(`${this.endpoint}/v1/health`);
    return resp.json();
  }

  /**
   * Check the server speaks our protocol, and say plainly when it does not.
   *
   * Returns `{ ok }` when it does, and otherwise a `reason` a person can act
   * on. A server that predates the protocol field reports nothing; that is
   * treated as protocol 1, because it is.
   */
  async checkProtocol() {
    let body;
    try {
      body = await this.health();
    } catch (err) {
      return { ok: false, reason: 'unreachable', detail: String(err?.message ?? err) };
    }
    if (!body?.ok) return { ok: false, reason: 'not-bencpass' };

    const theirs = Number(body.protocol ?? 1);
    if (theirs === PROTOCOL) return { ok: true, protocol: theirs, server: body.server };

    return {
      ok: false,
      reason: theirs > PROTOCOL ? 'client-too-old' : 'server-too-old',
      protocol: theirs,
      ours: PROTOCOL,
      server: body.server,
    };
  }

  /**
   * Mint a one-time enrolment code for the next machine.
   *
   * Signed like everything else, because a code buys a device key and a device
   * key is a full peer on the vault. The server prints a code by itself only
   * while zero devices are enrolled; after machine one, this request is the
   * only way in for machines two and three.
   *
   * The lifetime comes back from the server as `ttlSeconds` and is passed
   * through rather than restated here — the server decides when the code dies,
   * and a number typed on this side would drift the first time that decision
   * changed. Absent (a server too old to report it), it is null, not a guess.
   *
   * A 401 gets its own error code because the caller can act on it: it is
   * either a revoked device key or a protocol mismatch, and telling those
   * apart (via checkProtocol) beats reporting both as "could not mint".
   */
  async mintCode() {
    const { status, body } = await this.request('POST', '/v1/codes');
    if (status === 401) {
      throw new SyncError("the server refused this device's key (401)", 'unauthorised');
    }
    if (status !== 200 || !body.code) {
      throw new SyncError(
        `could not mint an enrolment code (${status}: ${body.error ?? 'unknown'})`,
        'code',
      );
    }
    const ttl = Number(body.ttlSeconds);
    return { code: body.code, ttlSeconds: ttl > 0 ? ttl : null };
  }

  async getRecords(since = 0) {
    const { status, body } = await this.request('GET', `/v1/records?since=${since}`);
    if (status !== 200) throw new SyncError(`pull failed (${status})`, 'pull');
    return body;
  }

  async putRecords(records, ifMatch) {
    const headers = ifMatch === null ? {} : { 'If-Match': String(ifMatch) };
    const { status, body } = await this.request('PUT', '/v1/records', { records }, headers);
    return { status, seq: body.seq, error: body.error };
  }

  /** Which machines are enrolled. Names and dates; never keys. */
  async devices() {
    const { status, body } = await this.request('GET', '/v1/devices');
    if (status !== 200) throw new SyncError(`could not list devices (${status})`, 'devices');
    return body.devices ?? [];
  }

  /**
   * Cut a machine off. Its key stops authenticating anything immediately.
   *
   * The server refuses to remove the last one, because a store with no devices
   * cannot be reached at all — nothing could enrol, since minting a code needs
   * a device to sign the request.
   */
  async forgetDevice(id) {
    const { status, body } = await this.request('DELETE', `/v1/devices/${encodeURIComponent(id)}`);
    if (status === 409) throw new SyncError(body?.error ?? 'that is the only device', 'last-device');
    if (status !== 200) throw new SyncError(`could not revoke (${status})`, 'revoke');
    return body;
  }

  /** Give a machine a name a person will recognise. */
  async renameDevice(id, name) {
    const { status, body } = await this.request(
      'PATCH',
      `/v1/devices/${encodeURIComponent(id)}`,
      { name },
    );
    if (status !== 200) throw new SyncError(`could not rename (${status})`, 'rename');
    return body?.name ?? name;
  }

  async getMeta() {
    const { status, body } = await this.request('GET', '/v1/meta');
    if (status !== 200) throw new SyncError(`meta pull failed (${status})`, 'meta');
    return body;
  }

  /**
   * Replace the vault header, passing the sequence it is replacing.
   *
   * `ifMatch` is null only for the first write to a fresh server. Everything
   * else has to say what it saw, because this carries the wrapped vault key: a
   * write that lands out of order puts an old wrapping back, and after a master
   * password change that quietly restores the previous password.
   */
  async putMeta(meta, ifMatch = null) {
    const headers = ifMatch === null ? {} : { 'If-Match': String(ifMatch) };
    const { status, body } = await this.request('PUT', '/v1/meta', { meta }, headers);
    if (status !== 200) throw new SyncError(`meta push failed (${status})`, 'meta');
    return body.seq;
  }
}

// ---- state -----------------------------------------------------------------

/**
 * What a client has to remember between syncs.
 *
 * `highestSeq` is separate from `seq` and is never lowered. It is the whole of
 * the rollback defence: a server — or something standing in for one on the LAN —
 * that serves an older copy of the vault would otherwise be believed, and the
 * client would helpfully restore a password it had already rotated away from.
 */
/**
 * Adopt a vault that already exists on a server.
 *
 * This is the whole of joining. The header carries the vault key wrapped under
 * the master password, so a second machine unwraps the *same* key rather than
 * inventing its own — which is the difference between two machines syncing and
 * two machines refusing to read each other.
 *
 * Records are not fetched here. The caller unlocks and then syncs normally, so
 * there is one path that moves records rather than two.
 *
 * The failure worth naming is a server holding somebody else's header: the
 * unwrap fails exactly as a mistyped password does, and saying "wrong password"
 * to a person whose password is right sends them looking in the wrong place.
 * The caller is told which it cannot distinguish.
 */
export async function joinVault({ client, password, Vault }) {
  const { meta } = await client.getMeta();
  if (!meta) {
    throw new SyncError(
      'that server is not carrying a vault yet — set one up on your first machine and let it sync once',
      'no-vault-there',
    );
  }

  let vault;
  try {
    vault = Vault.load({ meta: Vault.adoptMeta(meta), envelopes: [], syncedRev: {} });
  } catch (err) {
    throw new SyncError(`that server's vault is not readable by this version: ${err.message}`, 'bad-meta');
  }

  try {
    await vault.unlock(password);
  } catch {
    throw new SyncError(
      'that master password did not open the vault on that server. Either it is the wrong password, ' +
        'or that server holds a different vault than the one you meant.',
      'no-entry',
    );
  }
  return vault;
}

export const emptySyncState = () => ({ seq: 0, highestSeq: 0, syncedRev: {} });

export function loadSyncState(raw) {
  const s = { ...emptySyncState(), ...(raw ?? {}) };
  s.syncedRev = new Map(Object.entries(s.syncedRev ?? {}));
  return s;
}

export function dumpSyncState(state) {
  return {
    seq: state.seq,
    highestSeq: state.highestSeq,
    syncedRev: Object.fromEntries(state.syncedRev),
  };
}

// ---- the sync itself -------------------------------------------------------

/**
 * One round: pull, merge, push, retry once on a conflict.
 *
 * Returns what happened rather than logging it, so the UI can say "3 changes
 * from another machine, 1 conflict" instead of "synced".
 */
/**
 * Make sure the server is carrying this vault's header, if it is carrying none.
 *
 * The header is the wrapped vault key and the KDF parameters. Without it on the
 * server, a second machine has nothing to join: it would create its own vault
 * with its own random key, and the two would never be able to read each other's
 * records — which is what happened, because nothing ever pushed it.
 *
 * Published only when the server has none. A server that already holds a header
 * is left alone, and deliberately: the local copy diverges legitimately the
 * moment a fingerprint is enrolled (that adds a second wrapping and is local by
 * design), so treating every difference as something to upload would push one
 * machine's private business to every other. The compare-and-swap is passed the
 * sequence that was read, so two machines racing to be first cannot both win.
 */
async function shareHeader(vault, client) {
  const { meta, seq } = await client.getMeta();
  if (meta) return { published: false };

  // The sequence that was just read, including zero.
  //
  // Not `seq === 0 ? null : seq`: null omits If-Match, which the server treats
  // as "not checking" and permits only while the store is empty — so on a fresh
  // server, the one case the comment above is about, the compare-and-swap was
  // switched off and two machines could both publish, last one winning. Passing
  // 0 instead makes the check-and-increment atomic under the store's own lock,
  // and the loser gets a 409.
  // portableMeta, not meta: the header goes to a machine the user runs but does
  // not carry, and a fingerprint wrapping on it is a way into the vault for
  // whoever can present that credential. Nothing can use it there in any case —
  // a server has no authenticator, and a joining machine has its own.
  await client.putMeta(vault.portableMeta, seq);
  return { published: true };
}

/**
 * Make a merge's conflicts stick, and stop them coming back.
 *
 * Two jobs, both owed to the person whose machines disagreed:
 *
 * Park the losing side. merge() hands the other machine's bytes over in
 * `conflicts[].parked` and, until this existed, nothing kept them — the
 * manager said "kept" about a copy that was already gone, and a tombstone
 * racing an edit deleted the edit with no way back. vault.park needs no key,
 * so this holds on a locked background sync too; the parked copies become
 * visible "(conflict)" records at the next unlocked pass, and those go up
 * with the push so every machine sees the same two versions.
 *
 * Break the tie. Two machines editing from the same ancestor both count to
 * the same rev with different bytes, so each machine's merge kept its own
 * copy and re-pushed it — the server flipped between the two on every sync,
 * forever, and neither side converged. Re-sealing the kept copy above both
 * revs turns the next pull on the other machine into a plain fast-forward.
 * Only the side being pushed is bumped; when the remote side won (a
 * tombstone beating a local edit), the local copy is already gone and there
 * is nothing to supersede.
 *
 * Needs the key, so on a locked vault only the park happens and the same
 * conflict is re-detected — and re-deduplicated — until an unlocked sync
 * settles it.
 */
async function settleConflicts(vault, result) {
  vault.park(result.conflicts.map((c) => c.parked).filter(Boolean));
  if (vault.locked) return;

  for (const c of result.conflicts) {
    const at = result.toPush.findIndex((e) => e.id === c.id);
    if (at === -1) continue;
    await vault.supersede(c.id, Math.max(c.local.rev, c.remote.rev));
    result.toPush[at] = vault.envelopes.get(c.id);
  }

  // Everything parked — this round's and anything left over from locked
  // rounds — becomes a record and joins the push.
  for (const id of await vault.resolveParked()) {
    result.toPush.push(vault.envelopes.get(id));
  }
}

export async function syncOnce(vault, client, state) {
  // Before the records, because a machine that joins later needs this to exist
  // and the cost when it already does is one unauthenticated-shaped GET.
  await shareHeader(vault, client);

  const pulled = await client.getRecords(state.seq);
  guardRollback(pulled.seq, state);

  let result = merge({
    local: vault.envelopes,
    remote: pulled.records,
    syncedRev: state.syncedRev,
  });
  guardRecordRollback(result);

  await vault.applyEnvelopes(result.envelopes);
  await settleConflicts(vault, result);
  state.seq = pulled.seq;
  state.highestSeq = Math.max(state.highestSeq, pulled.seq);
  state.syncedRev = result.syncedRev;

  if (result.toPush.length === 0) {
    return { pulled: pulled.records.length, pushed: 0, conflicts: result.conflicts, seq: state.seq };
  }

  let push = await client.putRecords(result.toPush, state.seq === 0 ? null : state.seq);

  if (push.status === 409) {
    // Another machine wrote between our pull and our push. Take its version,
    // merge again, and try once more. Only once: a client that loops here
    // against a busy server is a client that never gives up the CPU, and two
    // rounds is already more than a personal vault will ever need.
    guardRollback(push.seq, state);
    const again = await client.getRecords(state.seq);
    guardRollback(again.seq, state);

    result = merge({
      local: vault.envelopes,
      remote: again.records,
      syncedRev: state.syncedRev,
    });
    guardRecordRollback(result);
    await vault.applyEnvelopes(result.envelopes);
    await settleConflicts(vault, result);
    state.seq = again.seq;
    state.highestSeq = Math.max(state.highestSeq, again.seq);
    state.syncedRev = result.syncedRev;

    push = await client.putRecords(result.toPush, state.seq);
  }

  if (push.status !== 200) {
    throw new SyncError(`push failed (${push.status}: ${push.error ?? 'unknown'})`, 'push');
  }

  // The ancestor advances only now, on the server's word. Advancing it at merge
  // time would make a push that failed look agreed, and the next round would
  // treat an unsent edit as already shared.
  state.syncedRev = confirmPushed(state.syncedRev, result.toPush);
  state.seq = push.seq;
  state.highestSeq = Math.max(state.highestSeq, push.seq);

  return {
    pulled: pulled.records.length,
    pushed: result.toPush.length,
    conflicts: result.conflicts,
    seq: state.seq,
  };
}

/**
 * Refuse a per-record rollback the way guardRollback refuses a global one.
 *
 * merge() has already done the right thing with the data — it keeps the local
 * envelope and queues it for pushing when the server serves a lower revision
 * for a record than it had already acknowledged. But healing quietly is not
 * this file's stance: a server doing that is a restored backup or something
 * standing in for the server, and the person syncing against it has to be
 * told, not corrected behind their back. The reason code is 'rollback' on
 * purpose — the manager's "This server was rebuilt" row already knows how to
 * explain this refusal, warning included.
 */
function guardRecordRollback(result) {
  const n = result.rolledBack.length;
  if (n) {
    throw new SyncError(
      `the server served an older revision than it had already acknowledged for ` +
        `${n} record${n === 1 ? '' : 's'} — refusing a rollback`,
      'rollback',
    );
  }
}

function guardRollback(seq, state) {
  if (seq < state.highestSeq) {
    throw new SyncError(
      `server reports sequence ${seq}, lower than the ${state.highestSeq} already seen — ` +
        `refusing a rollback`,
      'rollback',
    );
  }
}
