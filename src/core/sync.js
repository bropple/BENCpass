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
 *   METHOD \n /path?query \n unix-millis \n sha256(body) in lowercase hex
 */
export function canonical(method, uri, ts, bodyHashHex) {
  return `${method}\n${uri}\n${ts}\n${bodyHashHex}`;
}

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
   * @param {string} endpoint  e.g. https://box.tailnet.ts.net:8788
   * @param {string} deviceId  issued at enrolment
   * @param {Uint8Array} key   the device's HMAC key
   */
  constructor({ endpoint, deviceId, key, fetch: f = globalThis.fetch }) {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.deviceId = deviceId;
    this.key = key;
    this.fetch = f;
  }

  /**
   * Redeem a one-time enrolment code. Unauthenticated by necessity — this is
   * where a device acquires the credential everything else is signed with.
   */
  static async enrol({ endpoint, code, name, fetch: f = globalThis.fetch }) {
    const resp = await f(`${endpoint.replace(/\/$/, '')}/v1/enrol`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, name }),
    });
    if (!resp.ok) throw new SyncError('enrolment refused: unknown or expired code', 'enrol');
    const out = await resp.json();
    return { deviceId: out.deviceId, key: fromB64(out.key) };
  }

  async request(method, path, body = null, headers = {}) {
    // Serialise once and sign those exact bytes — re-stringifying for the send
    // could reorder keys and invalidate the signature.
    const raw = body === null ? new Uint8Array(0) : utf8(JSON.stringify(body));
    const ts = String(Date.now());
    const sig = await hmacB64(this.key, canonical(method, path, ts, await sha256Hex(raw)));

    const resp = await this.fetch(this.endpoint + path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Bencpass-Device': this.deviceId,
        'X-Bencpass-Time': ts,
        'X-Bencpass-Sig': sig,
        ...headers,
      },
      body: method === 'GET' ? undefined : raw,
    });

    const out = await resp.json().catch(() => ({}));
    return { status: resp.status, body: out };
  }

  async health() {
    const resp = await this.fetch(`${this.endpoint}/v1/health`);
    return resp.json();
  }

  async mintCode() {
    const { status, body } = await this.request('POST', '/v1/codes');
    if (status !== 200) throw new SyncError('could not mint an enrolment code', 'code');
    return body.code;
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

  async getMeta() {
    const { status, body } = await this.request('GET', '/v1/meta');
    if (status !== 200) throw new SyncError(`meta pull failed (${status})`, 'meta');
    return body;
  }

  async putMeta(meta) {
    const { status, body } = await this.request('PUT', '/v1/meta', { meta });
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
export async function syncOnce(vault, client, state) {
  const pulled = await client.getRecords(state.seq);
  guardRollback(pulled.seq, state);

  let result = merge({
    local: vault.envelopes,
    remote: pulled.records,
    syncedRev: state.syncedRev,
  });

  await vault.applyEnvelopes(result.envelopes);
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
    await vault.applyEnvelopes(result.envelopes);
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

function guardRollback(seq, state) {
  if (seq < state.highestSeq) {
    throw new SyncError(
      `server reports sequence ${seq}, lower than the ${state.highestSeq} already seen — ` +
        `refusing a rollback`,
      'rollback',
    );
  }
}
