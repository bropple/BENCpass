import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Vault } from '../src/core/vault.js';
import {
  SyncClient,
  syncOnce,
  emptySyncState,
  SyncError,
  canonical,
  PROTOCOL,
  joinVault,
  encodeFloor,
  decodeFloor,
  packEnrolCode,
  splitEnrolCode,
} from '../src/core/sync.js';

// These run against the real Go binary rather than a stub. The point is to
// prove the two implementations agree on the canonical signing string — a mock
// would agree with itself and prove nothing.
//
// Every test gets its own server and its own data directory. One shared server
// would mean one shared record namespace, and a test that created a fresh vault
// would pull records sealed with a different key — which is a real error, and
// has its own test at the bottom rather than being everybody's flaky failure.

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };

let binary, buildDir;

const haveGo = (() => {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

before(() => {
  if (!haveGo) return;
  buildDir = mkdtempSync(join(tmpdir(), 'bencpass-build-'));
  // The extension is explicit rather than left to the toolchain: passing -o with
  // .exe already on it makes the output name the same on every platform, so the
  // spawn below does not have to guess what Go decided to call the file.
  binary = join(buildDir, `bencpass-server${process.platform === 'win32' ? '.exe' : ''}`);
  execFileSync('go', ['build', '-o', binary, '.'], { cwd: join(root, 'server') });
});

after(() => {
  if (buildDir) rmSync(buildDir, { recursive: true, force: true });
});

const skip = !haveGo && { skip: 'go toolchain not available' };

/** A fresh server on a kernel-chosen port, torn down with the test. */
async function startServer(t) {
  const dir = mkdtempSync(join(tmpdir(), 'bencpass-data-'));
  const proc = spawn(binary, ['-addr', '127.0.0.1:0', '-dir', dir], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => {
    proc.kill();
    rmSync(dir, { recursive: true, force: true });
  });

  // The log carries both the bootstrap code and the port that was actually
  // bound — asking for :0 means there is no other way to learn the port.
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start')), 20_000);
    let seen = '';
    let code = null;
    const onData = (chunk) => {
      seen += chunk.toString();
      const c = seen.match(/bootstrap enrolment code \(valid 30 minutes\): (\S+)/);
      if (c) code = c[1];
      const addr = seen.match(/listening on https?:\/\/(\S+?)(?:\s|$)/);
      if (addr && code) {
        clearTimeout(timer);
        resolve({ endpoint: `http://${addr[1]}`, code });
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.on('error', reject);
  });
}

/**
 * Enrol a device.
 *
 * The bootstrap code is single-use, so it buys exactly one device; every later
 * one is enrolled with a code minted by an already-enrolled device. That is the
 * real topology, so the mint path gets exercised by most tests rather than one.
 */
async function device(endpoint, name, code) {
  const { deviceId, key } = await SyncClient.enrol({ endpoint, code, name });
  return new SyncClient({ endpoint, deviceId, key });
}

/** Two enrolled machines against one fresh server. */
async function pair(t) {
  const { endpoint, code } = await startServer(t);
  const a = await device(endpoint, 'machine-a', code);
  const b = await device(endpoint, 'machine-b', (await a.mintCode()).code);
  return { endpoint, a, b };
}

/** A second machine that has the vault header but none of the records yet. */
async function follower(source) {
  const v = Vault.load(source.toJSON());
  await v.applyEnvelopes(new Map());
  return v;
}

const mkVault = () => Vault.create({ password: 'hunter2', kdf: FAST });

test('the server is reachable and starts empty', { ...skip }, async (t) => {
  const { endpoint } = await startServer(t);
  const health = await (await fetch(`${endpoint}/v1/health`)).json();
  assert.equal(health.ok, true);
  assert.equal(health.seq, 0);
});

test('a signed request from an enrolled device is accepted', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'signing-check', code);
  // If the JavaScript and the Go disagreed by one character about what gets
  // signed, this is where it would surface — as a 401 with nothing to point at.
  const { seq, records } = await client.getRecords(0);
  assert.equal(typeof seq, 'number');
  assert.ok(Array.isArray(records));
});

test('a bad device key is refused', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const real = await device(endpoint, 'key-check', code);
  const forged = new SyncClient({
    endpoint,
    deviceId: real.deviceId,
    key: crypto.getRandomValues(new Uint8Array(32)),
  });
  await assert.rejects(() => forged.getRecords(0), /pull failed \(401\)/);
});

test('an enrolled machine mints a code the next machine can enrol with', { ...skip }, async (t) => {
  // The path the extension's "Add a machine" button drives. The server prints
  // a code by itself only while zero devices are enrolled, so after machine
  // one this is the only way in for machines two and three.
  const { endpoint, code } = await startServer(t);
  const first = await device(endpoint, 'machine-one', code);

  const minted = await first.mintCode();
  assert.ok(minted.code.length > 0, 'no code came back');
  // The lifetime is the server's answer, passed through — not a constant
  // restated on the client. 1800 is what server/main.go sends today; if the
  // server's decision changes, this changes with it, and so does the UI.
  assert.equal(minted.ttlSeconds, 1800);

  // The code buys exactly one enrolment, and the key it buys actually works.
  const second = await device(endpoint, 'machine-two', minted.code);
  const { seq } = await second.getRecords(0);
  assert.equal(typeof seq, 'number');

  // Single-use: the server deletes it on redemption, success or not.
  await assert.rejects(
    () => SyncClient.enrol({ endpoint, code: minted.code, name: 'machine-three' }),
    (err) => err instanceof SyncError && err.code === 'enrol',
  );
});

test('minting with a refused key reports unauthorised, not a generic failure', { ...skip }, async (t) => {
  // The manager tells a revoked key apart from a protocol mismatch, and both
  // apart from "could not mint" — which is only possible if the client
  // surfaces the 401 as itself.
  const { endpoint, code } = await startServer(t);
  const real = await device(endpoint, 'mint-check', code);
  const forged = new SyncClient({
    endpoint,
    deviceId: real.deviceId,
    key: crypto.getRandomValues(new Uint8Array(32)),
  });
  await assert.rejects(
    () => forged.mintCode(),
    (err) => err instanceof SyncError && err.code === 'unauthorised',
  );
});

test('a mint the server cannot honour fails as a mint, naming the status', async () => {
  const client = new SyncClient({
    endpoint: 'https://box.example',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch: async () => ({ ok: false, status: 500, json: async () => ({ error: 'cannot mint code' }) }),
  });
  await assert.rejects(
    () => client.mintCode(),
    (err) => err instanceof SyncError && err.code === 'code' && err.message.includes('500'),
  );
});

test('a vault reaches a second machine through the server', { ...skip }, async (t) => {
  const { a: laptopClient, b: desktopClient } = await pair(t);
  const laptop = await mkVault();
  const laptopState = emptySyncState();

  const id = await laptop.add({ title: 'BENCO', username: 'ben', password: 'hunter2' });
  const up = await syncOnce(laptop, laptopClient, laptopState);
  assert.equal(up.pushed, 1);

  // A second machine, enrolled by the first, starting from nothing.
  const desktop = await follower(laptop); // as if bootstrapped from meta
  const desktopState = emptySyncState();

  const down = await syncOnce(desktop, desktopClient, desktopState);
  assert.equal(down.pulled, 1);

  await desktop.unlock('hunter2');
  assert.equal(desktop.get(id).password, 'hunter2');
  assert.deepEqual(down.conflicts, []);
});

test('an edit on one machine reaches the other', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Router', password: 'first' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');
  assert.equal(b.get(id).password, 'first');

  // a changes it; b picks the change up and does not report a conflict, because
  // b had not touched the record since it last agreed with the server.
  await a.update(id, { password: 'second' });
  await syncOnce(a, aClient, aState);

  const round = await syncOnce(b, bClient, bState);
  assert.equal(round.pulled, 1);
  assert.deepEqual(round.conflicts, []);
  assert.equal(b.get(id).password, 'second');
});

test('two machines editing the same record produces a conflict, not a loss', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Shared', password: 'original' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');

  // Both edit while neither has seen the other — the offline case that a
  // last-writer-wins blob would silently resolve by losing one of them.
  await a.update(id, { password: 'from-a' });
  await b.update(id, { password: 'from-b' });

  await syncOnce(a, aClient, aState);
  const round = await syncOnce(b, bClient, bState);

  assert.equal(round.conflicts.length, 1);
  assert.equal(round.conflicts[0].kind, 'edit');
  // b keeps its own version on screen...
  assert.equal(b.get(id).password, 'from-b');
  // ...and a's version is parked rather than discarded.
  assert.ok(round.conflicts[0].parked.ct);
});

test('a deletion syncs as a tombstone', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Temporary', password: 'x' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');
  assert.ok(b.get(id));

  await a.remove(id);
  await syncOnce(a, aClient, aState);
  await syncOnce(b, bClient, bState);

  assert.equal(b.get(id), undefined);
});

test('a sync can run on a locked vault', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Background', password: 'quiet' });
  await syncOnce(a, aClient, aState);

  // The merge needs id, rev and the tombstone flag, all of which are outside
  // the ciphertext — so a background sync never needs the master password.
  const b = await follower(a);
  assert.equal(b.locked, true);

  const round = await syncOnce(b, bClient, emptySyncState());
  assert.equal(round.pulled, 1);
  assert.equal(b.locked, true);

  await b.unlock('hunter2');
  assert.equal(b.get(id).password, 'quiet');
});

test('the vault header round-trips so a new machine can bootstrap', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'meta-check', code);
  const a = await mkVault();
  await client.putMeta(a.meta);

  const { meta } = await client.getMeta();
  assert.equal(meta.format, a.meta.format);
  assert.equal(meta.kdf.salt, a.meta.kdf.salt);
  assert.ok(meta.wraps.password.ct);
});

test('a server serving an older sequence is refused', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'rollback-check', code);
  const vault = await mkVault();
  const state = emptySyncState();

  await vault.add({ title: 'Rotated', password: 'new-one' });
  await syncOnce(vault, client, state);
  assert.ok(state.highestSeq > 0);

  // Stand in for something on the LAN replaying an old copy of the store. It
  // would otherwise be believed, and a password already rotated away from would
  // come back.
  const rolledBack = new SyncClient({
    endpoint,
    deviceId: client.deviceId,
    key: client.key,
  });
  rolledBack.getRecords = async () => ({ seq: state.highestSeq - 1, records: [] });

  await assert.rejects(
    () => syncOnce(vault, rolledBack, state),
    (err) => err instanceof SyncError && err.code === 'rollback',
  );
});

test('re-serving an older revision of a record is refused, not healed quietly', { ...skip }, async (t) => {
  // The gap guardRollback leaves: a server — or something standing in for one —
  // that re-serves a genuinely-authentic pre-rotation envelope under a *bumped*
  // global sequence sails past the sequence check, and the old merge
  // fast-forwarded to it: the leaked password came back. merge() now keeps
  // local, but keeping quiet about it would hide the event, and from here a
  // restored backup and a hostile server look identical — the person syncing
  // has to be told either way.
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'rotation-check', code);
  const vault = await mkVault();
  const state = emptySyncState();

  const id = await vault.add({ title: 'Bank', password: 'leaked' });
  await syncOnce(vault, client, state);

  // The pre-rotation envelope exactly as the server holds it — really sealed
  // by this client, at a revision the server has acknowledged.
  const stale = (await client.getRecords(0)).records.find((r) => r.id === id);
  assert.ok(stale, 'the pushed envelope is not on the server');

  await vault.update(id, { password: 'rotated' });
  await syncOnce(vault, client, state);

  const hostile = new SyncClient({ endpoint, deviceId: client.deviceId, key: client.key });
  hostile.getRecords = async () => ({ seq: state.highestSeq + 1, records: [stale] });
  // The push is stubbed to succeed as well, because a hostile server's would:
  // without it, the inflated sequence happens to make the *real* server's
  // reply trip the global guard on the way out, and this test would pass for
  // the wrong reason — refusal by coincidence rather than by the record check.
  hostile.putRecords = async () => ({ status: 200, seq: state.highestSeq + 2 });

  await assert.rejects(
    () => syncOnce(vault, hostile, state),
    (err) =>
      err instanceof SyncError && err.code === 'rollback' && /older revision/.test(err.message),
    'the served-back old envelope was accepted',
  );
  // And the rotation held.
  assert.equal(vault.get(id).password, 'rotated');
});

test('pointing a vault at a server holding a different one says so', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const mine = await mkVault();
  await mine.add({ title: 'Mine', password: 'x' });
  await syncOnce(mine, aClient, emptySyncState());

  // A different vault entirely — a reinstall with a new master password, say,
  // pointed at the endpoint the old one was using.
  const stranger = await Vault.create({ password: 'a-different-password', kdf: FAST });
  await assert.rejects(
    () => syncOnce(stranger, bClient, emptySyncState()),
    (err) => err.code === 'key-mismatch',
  );
});

// ---- one server, two addresses ---------------------------------------------
//
// A LAN address at home and a Tailscale name from anywhere. The distinction
// that matters is between "nothing answered" and "the server said no": only the
// first is a reason to try the other route.

const stubFetch = (behaviour) => {
  const seen = [];
  const f = (url, init) => {
    seen.push(url);
    const outcome = behaviour(url);
    if (outcome instanceof Error) return Promise.reject(outcome);
    // A promise that never settles stands in for an address that blackholes —
    // the case the probe timeout exists for. Honouring the signal is what makes
    // that testable rather than a hang.
    if (outcome === 'hang') {
      return new Promise((_, reject) => {
        // The keep-alive is not belt and braces, it is what makes this test run
        // at all. AbortSignal.timeout()'s timer is unref'd, so once the only
        // pending work is that timer and this unsettled promise, Node decides
        // it has nothing left to do and exits -- and the runner reports
        // "Promise resolution is still pending but the event loop has already
        // resolved" against this test and every one after it in the file.
        //
        // It passed locally and failed in CI for three commits, because
        // concurrent tests happened to keep the loop busy here and did not
        // there. A ref'd timer removes the coincidence.
        const keepAlive = setTimeout(
          () => reject(new Error('the hanging address was never aborted')),
          5000,
        );
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(keepAlive);
          reject(new Error('TimeoutError'));
        });
      });
    }
    return Promise.resolve(outcome);
  };
  f.seen = seen;
  return f;
};

const okResponse = (body = {}) => ({
  ok: true,
  status: 200,
  json: async () => body,
});

test('the second address is used when the first cannot be reached', async () => {
  const fetch = stubFetch((url) =>
    url.startsWith('http://lan') ? new TypeError('NetworkError') : okResponse({ changes: [] }),
  );
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
  });

  const { status } = await client.request('GET', '/v1/changes?since=0');
  assert.equal(status, 200);
  assert.equal(fetch.seen.length, 2);
  assert.equal(new URL(fetch.seen[1]).origin, 'https://tail.ts.net');
});

test('the address that answered is remembered, so the dead one is not retried', async () => {
  const fetch = stubFetch((url) =>
    url.startsWith('http://lan') ? new TypeError('NetworkError') : okResponse({ changes: [] }),
  );
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
  });

  await client.request('GET', '/v1/changes?since=0');
  await client.request('GET', '/v1/changes?since=0');

  // Three requests, not four: the first call tried both, the second went
  // straight to the one that worked.
  assert.equal(fetch.seen.length, 3);
  assert.equal(client.endpoint, 'https://tail.ts.net');
});

test('a refusal is not a reason to try the other address', async () => {
  // The same server by another name will refuse in exactly the same way, so
  // retrying only doubles the noise — and, on a 401, the log lines.
  const fetch = stubFetch(() => ({ ok: false, status: 401, json: async () => ({}) }));
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
  });

  const { status } = await client.request('GET', '/v1/changes?since=0');
  assert.equal(status, 401);
  assert.equal(fetch.seen.length, 1);
});

test('when no address answers, the error names every one that was tried', async () => {
  const fetch = stubFetch(() => new TypeError('NetworkError'));
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
  });

  await assert.rejects(() => client.request('GET', '/v1/changes?since=0'), (err) => {
    assert.equal(err.code, 'unreachable');
    // includes(), not a bare regex: these are substring checks on an error
    // message and saying so plainly is clearer than a pattern that reads like
    // a host test and is scanned as one.
    assert.ok(err.message.includes('lan:8788'), err.message);
    assert.ok(err.message.includes('tail.ts.net'), err.message);
    return true;
  });
});

test('one address still works, and a trailing slash is not a second server', async () => {
  const fetch = stubFetch(() => okResponse({ changes: [] }));
  const client = new SyncClient({
    endpoint: 'https://tail.ts.net/',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
  });
  await client.request('GET', '/v1/changes?since=0');
  assert.equal(fetch.seen[0], 'https://tail.ts.net/v1/changes?since=0');
});

test('a client with no address at all refuses to be built', () => {
  assert.throws(() => new SyncClient({ endpoints: ['', null], deviceId: 'd', key: new Uint8Array(32) }));
});

/** The signature the server would compute for these exact parameters. */
async function expectedSig(keyBytes, { method, host, path, ts, nonce, ifMatch = '', body }) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
  const hex = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const msg = new TextEncoder().encode(canonical(method, host, path, ts, nonce, ifMatch, hex));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  return btoa(String.fromCharCode(...mac));
}

test('each attempt is signed for the address it is actually sent to', async () => {
  // The reason this matters is the failover itself. Something sitting on the
  // first address can read a whole signed request and then drop the
  // connection: the client sees an unreachable address, succeeds quietly
  // against the second, and the listener keeps a complete request. If the
  // signature did not name the host, that copy would work against the real
  // server.
  //
  // Checked by recomputing the signature rather than by comparing the two
  // attempts to each other. An earlier version asserted only that the two
  // signatures differed, which the differing nonces guarantee on their own --
  // so it passed even when the client was made to sign the *first* host on
  // every attempt, which is precisely the bug it was named after.
  const sent = [];
  const fetch = (url, init) => {
    sent.push({ url, headers: init.headers });
    if (url.startsWith('http://lan')) return Promise.reject(new Error('unreachable'));
    return Promise.resolve(okResponse({}));
  };

  const key = new Uint8Array(32);
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key,
    fetch,
    probeTimeoutMs: 20,
  });
  await client.request('GET', '/v1/changes?since=0');

  assert.equal(sent.length, 2, 'both addresses should have been tried');
  const hosts = ['lan:8788', 'tail.ts.net'];

  for (const [i, attempt] of sent.entries()) {
    const common = {
      method: 'GET',
      path: '/v1/changes?since=0',
      ts: attempt.headers['X-Bencpass-Time'],
      nonce: attempt.headers['X-Bencpass-Nonce'],
      body: new Uint8Array(0),
    };

    assert.equal(
      attempt.headers['X-Bencpass-Sig'],
      await expectedSig(key, { ...common, host: hosts[i] }),
      `attempt ${i} was not signed for ${hosts[i]}`,
    );

    // And demonstrably not valid at the other address, which is the property
    // the whole exercise exists for.
    assert.notEqual(
      attempt.headers['X-Bencpass-Sig'],
      await expectedSig(key, { ...common, host: hosts[1 - i] }),
      `attempt ${i} would also have been accepted by ${hosts[1 - i]}`,
    );
  }

  // A nonce is spent once. Reusing it across the two attempts would make the
  // retry look exactly like the replay the server refuses.
  assert.notEqual(
    sent[0].headers['X-Bencpass-Nonce'],
    sent[1].headers['X-Bencpass-Nonce'],
    'the second attempt reused the first attempt nonce',
  );
  assert.match(sent[0].headers['X-Bencpass-Nonce'], /^[0-9a-f]{32}$/);
});

test('the port is part of what is signed, not just the hostname', async () => {
  // Two addresses for one machine, differing only by port — a second instance,
  // or something else that answered on the port the first one used to. The
  // test above uses two different names, so a signature that quietly dropped
  // the port would still pass it; this is the case that notices.
  const sent = [];
  const fetch = (url, init) => {
    sent.push({ url, headers: init.headers });
    if (url.includes(':8788')) return Promise.reject(new Error('unreachable'));
    return Promise.resolve(okResponse({}));
  };

  const key = new Uint8Array(32);
  const client = new SyncClient({
    endpoints: ['http://box:8788', 'http://box:9999'],
    deviceId: 'd',
    key,
    fetch,
    probeTimeoutMs: 20,
  });
  await client.request('GET', '/v1/changes?since=0');

  assert.equal(sent.length, 2);
  const ports = ['box:8788', 'box:9999'];

  for (const [i, attempt] of sent.entries()) {
    const common = {
      method: 'GET',
      path: '/v1/changes?since=0',
      ts: attempt.headers['X-Bencpass-Time'],
      nonce: attempt.headers['X-Bencpass-Nonce'],
      body: new Uint8Array(0),
    };
    assert.equal(
      attempt.headers['X-Bencpass-Sig'],
      await expectedSig(key, { ...common, host: ports[i] }),
      `attempt ${i} was not signed for ${ports[i]}`,
    );
    assert.notEqual(
      attempt.headers['X-Bencpass-Sig'],
      await expectedSig(key, { ...common, host: ports[1 - i] }),
      `attempt ${i} would also have been accepted on the other port`,
    );
    // The bare hostname must not be what was signed.
    assert.notEqual(
      attempt.headers['X-Bencpass-Sig'],
      await expectedSig(key, { ...common, host: 'box' }),
      `attempt ${i} was signed for the hostname with the port dropped`,
    );
  }
});

test('an address that hangs is abandoned rather than waited out', async () => {
  // A LAN address on a foreign network does not refuse; there is nothing there
  // to refuse. Without a bound on the attempt this is a TCP timeout every sync.
  const fetch = stubFetch((url) => (url.startsWith('http://lan') ? 'hang' : okResponse({})));
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
    probeTimeoutMs: 20,
  });

  const started = Date.now();
  const { status } = await client.request('GET', '/v1/changes?since=0');
  assert.equal(status, 200);
  assert.ok(Date.now() - started < 1000, 'should give up on the first address quickly');
  assert.equal(client.endpoint, 'https://tail.ts.net');
});

test('the last address is not time-boxed, having nothing to fall back to', async () => {
  // A large vault over a slow link is a slow sync, not a failure.
  const fetch = stubFetch(() => new Promise((r) => setTimeout(() => r(okResponse({})), 60)));
  const client = new SyncClient({
    endpoint: 'https://only.example',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
    probeTimeoutMs: 5,
  });
  const { status } = await client.request('GET', '/v1/changes?since=0');
  assert.equal(status, 200);
});

test('a remembered address is tried first, and is matched by name not position', async () => {
  const fetch = stubFetch(() => okResponse({}));
  const client = new SyncClient({
    endpoints: ['http://lan:8788', 'https://tail.ts.net'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
    // As it would come back out of storage — with a trailing slash, because a
    // person typed it that way once.
    preferred: 'https://tail.ts.net/',
  });
  await client.request('GET', '/v1/changes?since=0');
  assert.equal(fetch.seen.length, 1);
  // The whole address, not a prefix: startsWith on a bare host is also true
  // of https://tail.ts.net.evil.example, which is not what this asserts.
  assert.equal(new URL(fetch.seen[0]).origin, 'https://tail.ts.net');
});

test('a remembered address that is no longer configured is ignored', async () => {
  // The list can be edited between sessions. A stale preference must not pin
  // anything, and must not throw.
  const fetch = stubFetch(() => okResponse({}));
  const client = new SyncClient({
    endpoints: ['http://lan:8788'],
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch,
    preferred: 'https://gone.example',
  });
  await client.request('GET', '/v1/changes?since=0');
  assert.ok(fetch.seen[0].startsWith('http://lan:8788'));
});

// ---- protocol version -------------------------------------------------------
//
// The wire format has changed three times, and each time a client and server
// that disagreed produced a 401 — the same answer as a wrong device key. These
// pin that the disagreement can be told apart from a credential problem, which
// is the whole reason the number is reported at all.

test('the client and the real server agree on the protocol number', { ...skip }, async (t) => {
  // Against the real binary, so the two constants cannot drift apart unnoticed:
  // the Go one and the JavaScript one are separate declarations of one fact.
  const { endpoint } = await startServer(t);
  const client = new SyncClient({ endpoint, deviceId: 'd', key: new Uint8Array(32) });

  const health = await client.health();
  assert.equal(health.protocol, PROTOCOL, 'server and client disagree about the protocol version');

  const check = await client.checkProtocol();
  assert.equal(check.ok, true);
});

test('a server speaking a newer protocol says so instead of failing as a bad key', async () => {
  const client = new SyncClient({
    endpoint: 'https://newer.example',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch: async () => okResponse({ ok: true, seq: 3, protocol: PROTOCOL + 1, server: '9.9.9' }),
  });
  const check = await client.checkProtocol();
  assert.equal(check.ok, false);
  assert.equal(check.reason, 'client-too-old');
  assert.equal(check.protocol, PROTOCOL + 1);
});

test('a server predating the protocol field is read as the version it is', async () => {
  // No field at all means the first format, because that is what it was.
  const client = new SyncClient({
    endpoint: 'https://older.example',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch: async () => okResponse({ ok: true, seq: 0 }),
  });
  const check = await client.checkProtocol();
  assert.equal(check.ok, false);
  assert.equal(check.reason, 'server-too-old');
  assert.equal(check.protocol, 1);
});

test('an address with nothing behind it is unreachable, not a protocol problem', async () => {
  const client = new SyncClient({
    endpoint: 'https://nothing.example',
    deviceId: 'd',
    key: new Uint8Array(32),
    fetch: async () => {
      throw new Error('connection refused');
    },
  });
  const check = await client.checkProtocol();
  assert.equal(check.ok, false);
  assert.equal(check.reason, 'unreachable');
});

// ---- joining a vault that already exists ------------------------------------
//
// The point of the server. Before this existed, a second machine could only
// create its own vault with its own random key, and the two could never read
// each other's records — the server carried the header the whole time and
// nothing ever pushed or pulled it.

test('a second machine joins the first machine vault and reads its records', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  // Machine one: a vault with something in it, synced.
  const first = await mkVault();
  const firstState = emptySyncState();
  const id = await first.add({ title: 'Bank', username: 'ben', password: 'hunter2' });
  await syncOnce(first, aClient, firstState);

  // Machine two knows the master password and the address, and nothing else.
  const second = await joinVault({ client: bClient, password: 'hunter2', Vault });
  const secondState = emptySyncState();
  await syncOnce(second, bClient, secondState);

  assert.equal(second.get(id).password, 'hunter2', 'the joined machine could not read the record');

  // And it is genuinely the same vault, not a copy: an edit on the second
  // machine comes back to the first.
  await second.update(id, { password: 'rotated' });
  await syncOnce(second, bClient, secondState);
  await syncOnce(first, aClient, firstState);
  assert.equal(first.get(id).password, 'rotated');
});

test('joining with the wrong password says so without blaming the password alone', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);
  const first = await mkVault();
  await first.add({ title: 'Bank', password: 'hunter2' });
  await syncOnce(first, aClient, emptySyncState());

  await assert.rejects(
    () => joinVault({ client: bClient, password: 'not the password', Vault }),
    (err) => err.code === 'no-entry',
  );
});

test('joining a server with no vault on it says that, rather than failing to unlock', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'lonely', code);

  await assert.rejects(
    () => joinVault({ client, password: 'hunter2', Vault }),
    (err) => err.code === 'no-vault-there',
  );
});

// ---- the enrolment code's sequence floor ------------------------------------
//
// A joining machine has no history, so trust-on-first-use used to be unbounded:
// a rolled-back server could seed it with an arbitrarily old but authentic copy
// of the vault. The floor rides on the enrolment code — the one channel the
// server never touches — and becomes the join's highestSeq.

test('a floor round-trips through the code, and a bare code means no floor', () => {
  for (const n of [0, 1, 30, 31, 32, 961, 12345, 999999, 2 ** 40]) {
    assert.equal(decodeFloor(encodeFloor(n)), n, `floor ${n} did not round-trip`);
  }

  const packed = packEnrolCode('k3J9fJq2QxYz', 12345);
  assert.match(packed, /^k3J9fJq2QxYz\.[A-Z2-9]+$/, 'the suffix must use the recovery alphabet');
  assert.deepEqual(splitEnrolCode(packed), { code: 'k3J9fJq2QxYz', floor: 12345 });

  // A floor of zero is no floor: nothing to vouch for, nothing appended.
  assert.equal(packEnrolCode('abc', 0), 'abc');
  assert.deepEqual(splitEnrolCode('abc'), { code: 'abc', floor: 0 });

  // Case slack on the suffix, because it is typed: the recovery alphabet is
  // upper case, and a lower-cased paste should not read as a different floor.
  assert.equal(splitEnrolCode(`abc.${encodeFloor(500).toLowerCase()}`).floor, 500);
});

test('a state seeded with the floor refuses a server below it on the first pull', async () => {
  const rolledBack = {
    getMeta: async () => ({ meta: null, seq: 3 }),
    putMeta: async () => 4,
    getRecords: async () => ({ seq: 3, records: [] }),
    putRecords: async () => ({ status: 200, seq: 4 }),
  };
  const vault = await mkVault();
  const state = emptySyncState(10); // the code vouched for at least 10
  await assert.rejects(
    () => syncOnce(vault, rolledBack, state),
    (err) => err instanceof SyncError && err.code === 'rollback',
    'a first pull below the floor must be refused as a rollback, not adopted as the baseline',
  );
});

test('joining a server rolled back below the code floor is refused at the door', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  // Machine one syncs a vault; the server is at some small sequence.
  const first = await mkVault();
  await first.add({ title: 'Bank', password: 'hunter2' });
  await syncOnce(first, aClient, emptySyncState());

  // The code claims the vault history is far longer than this server holds —
  // which is what a code minted before the server was rolled back looks like.
  await assert.rejects(
    () => joinVault({ client: bClient, password: 'hunter2', Vault, floor: 1000 }),
    (err) => err instanceof SyncError && err.code === 'rollback',
  );

  // With an honest floor the join succeeds, and the floor rides into the state.
  const second = await joinVault({ client: bClient, password: 'hunter2', Vault, floor: 2 });
  assert.ok(second, 'an honest floor must not block the join');
});

test('a packed code enrols against the real server, floor and all', { ...skip }, async (t) => {
  const { endpoint, code } = await startServer(t);
  const one = await device(endpoint, 'machine-one', code);

  // Machine one has seen the server at some sequence; the code it hands out
  // carries that as a floor. The server only ever sees the bare part.
  const minted = await one.mintCode();
  const packed = packEnrolCode(minted.code, 7);
  assert.ok(packed.includes('.'), 'a non-zero floor must be visible in the code');

  const { deviceId, key, floor } = await SyncClient.enrol({
    endpoint,
    code: packed,
    name: 'machine-two',
  });
  assert.equal(floor, 7, 'the joining side must recover the floor the minter wrote');

  // And the credential is real: a signed request with it is accepted.
  const two = new SyncClient({ endpoint, deviceId, key });
  const { seq } = await two.getRecords(0);
  assert.equal(typeof seq, 'number');
});

test('the header is published once and not overwritten afterwards', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const first = await mkVault();
  await syncOnce(first, aClient, emptySyncState());
  const published = (await aClient.getMeta()).meta;
  assert.ok(published, 'the first sync did not publish the header');

  // A second machine joins, enrols a fingerprint (which is local by design and
  // changes its own copy of the header), and syncs. The server's copy must not
  // move: that wrapping belongs to one machine.
  const second = await joinVault({ client: bClient, password: 'hunter2', Vault });
  await second.enrolBiometric('hunter2', new Uint8Array(32).fill(7));
  await syncOnce(second, bClient, emptySyncState());

  assert.deepEqual(
    (await bClient.getMeta()).meta,
    published,
    'a local biometric enrolment was pushed to the server',
  );
});

test('a master password change reaches the other machine through the server', { ...skip }, async (t) => {
  // Machine A changes the password. The next sync republishes the header
  // through the putMeta compare-and-swap; machine B's next sync — locked or
  // not, it cannot verify anything — parks the newer header, and B's first
  // unlock with the NEW password proves and adopts it. The vault key never
  // changes, so records need nothing.
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Bank', password: 'secret1' });
  await syncOnce(a, aClient, aState);

  const b = await joinVault({ client: bClient, password: 'hunter2', Vault });
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);

  await a.changeMasterPassword('hunter2', 'correct horse');
  await syncOnce(a, aClient, aState); // republishes the gen-1 header

  const onServer = (await bClient.getMeta()).meta;
  assert.equal(onServer.gen, 1, 'the server must hold the new header');

  // B syncs locked — the exact state a background sync runs in.
  b.lock();
  const res = await syncOnce(b, bClient, bState);
  assert.equal(res.headerPending, true, 'the sync must report the parked header');

  // The new password opens B and switches it; the old one stops.
  await b.unlock('correct horse');
  assert.equal(b.meta.gen, 1);
  assert.equal(b.get(id).password, 'secret1');
  b.lock();
  await assert.rejects(() => b.unlock('hunter2'), (err) => err.code === 'unwrap-failed');

  // And a machine joining fresh from here on gets the new header directly.
  const c = await joinVault({ client: bClient, password: 'correct horse', Vault });
  const cState = emptySyncState();
  await syncOnce(c, bClient, cState);
  assert.equal(c.get(id).password, 'secret1');
});

test('two machines cannot both publish the first header', { ...skip }, async (t) => {
  // Both see an empty server and both try to be the one that sets it up. One
  // has to lose, or two independently created vaults end up with the last
  // header written and records nobody can read.
  const { a: aClient, b: bClient } = await pair(t);
  const one = await mkVault();
  const two = await Vault.create({ password: 'different', kdf: FAST });

  const [first, second] = await Promise.allSettled([
    syncOnce(one, aClient, emptySyncState()),
    syncOnce(two, bClient, emptySyncState()),
  ]);

  const won = [first, second].filter((r) => r.status === 'fulfilled').length;
  assert.ok(won >= 1, 'neither machine managed to publish');

  // Whatever happened, the server carries exactly one header and it is one of
  // theirs — not a blend, and not the second silently replacing the first.
  const onServer = JSON.stringify((await aClient.getMeta()).meta);
  assert.ok(
    onServer === JSON.stringify(one.meta) || onServer === JSON.stringify(two.meta),
    'the published header belongs to neither machine',
  );
});

// ---- recovering from a rebuilt server ---------------------------------------

test('a rebuilt server is refused, and forgetting the sync state recovers it', { ...skip }, async (t) => {
  // Machine with a vault and a history of syncing.
  const { endpoint, code } = await startServer(t);
  const client = await device(endpoint, 'laptop', code);
  const vault = await mkVault();
  const state = emptySyncState();
  await vault.add({ title: 'Bank', password: 'hunter2' });
  await syncOnce(vault, client, state);
  assert.ok(state.highestSeq > 0, 'the first sync recorded nothing');

  // The server is rebuilt: new data directory, new enrolment, sequence back to
  // zero. Everything the machine remembers about what it synced is now wrong.
  const rebuilt = await startServer(t);
  const toRebuilt = await device(rebuilt.endpoint, 'laptop', rebuilt.code);

  await assert.rejects(
    () => syncOnce(vault, toRebuilt, state),
    (err) => err.code === 'rollback',
    'a server reporting a lower sequence was accepted',
  );

  // Forgetting is exactly this: drop the bookkeeping, keep the vault.
  const forgotten = emptySyncState();
  const result = await syncOnce(vault, toRebuilt, forgotten);

  assert.equal(result.pushed, 1, 'the record was not sent to the rebuilt server');
  assert.equal(vault.list().length, 1, 'the vault lost a record');
  assert.equal(vault.list()[0].password, 'hunter2');

  // And the rebuilt server is carrying the vault header again, so another
  // machine could still join it.
  assert.ok((await toRebuilt.getMeta()).meta, 'the header was not republished');
});

test('a fingerprint never reaches the server, and is never inherited', async (t) => {
  // The same rule as the encrypted backup, on the other route out. A header
  // published to a server is a header on a machine the user runs but does not
  // carry, and the secret behind a fingerprint wrapping belongs to an
  // authenticator that may sync across an account's devices.
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const v = await Vault.create({ password: 'pw' });
  await v.add({ type: 'login', title: 'bank', username: 'u', password: 'secret' });
  await v.enrolBiometric('pw', secret);
  assert.ok(v.hasBiometric, 'the vault under test must have a fingerprint');

  // What shareHeader puts on the wire.
  const published = JSON.parse(JSON.stringify(v.portableMeta));
  assert.equal(published.wraps.biometric, null, 'the fingerprint wrapping went to the server');
  assert.ok(published.wraps.password, 'the password wrapping has to survive');
  assert.ok(published.kdf.salt, 'the salt has to survive');

  // Publishing did not cost this machine its own fingerprint.
  assert.ok(v.hasBiometric, 'publishing the header removed the live fingerprint');

  // A machine joining from it does not claim a fingerprint it cannot produce —
  // including from a header published by an older version that still sent one.
  const stale = JSON.parse(JSON.stringify(v.meta));
  assert.ok(stale.wraps.biometric, 'this test needs a header that still carries one');
  const joined = Vault.load({ meta: Vault.adoptMeta(stale), envelopes: [], syncedRev: {} });
  assert.equal(joined.hasBiometric, false, 'the joining machine inherited a fingerprint');

  // And it still opens the way a joining machine actually opens it.
  await joined.unlock('pw');
});

// ---- convergence ------------------------------------------------------------
//
// The drift this project exists to eliminate, reproduced by the sync itself:
// two machines that edit from the same ancestor both count to the same rev
// with different bytes. Each machine's merge kept its own copy and re-pushed
// it, so the server flipped between the two on every sync, forever, and the
// answer to "which password is the latest" depended on who synced last. These
// tests pin the fix: the kept copy is re-sealed above both sides, the losing
// copy becomes a "(conflict)" record on every machine, and the round after
// next reports no conflict at all.

test('conflicting edits converge instead of flip-flopping forever', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Shared', password: 'original' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');

  // The offline case: both edit before either sees the other.
  await a.update(id, { password: 'from-a' });
  await b.update(id, { password: 'from-b' });

  await syncOnce(a, aClient, aState);
  const clash = await syncOnce(b, bClient, bState);
  assert.equal(clash.conflicts.length, 1, 'the disagreement is reported once');

  // From here on, silence. The old behaviour re-detected this same conflict
  // on every sync of either machine, forever.
  assert.deepEqual((await syncOnce(a, aClient, aState)).conflicts, []);
  assert.deepEqual((await syncOnce(b, bClient, bState)).conflicts, []);
  assert.deepEqual((await syncOnce(a, aClient, aState)).conflicts, []);

  // Both machines agree, byte for byte, on which version is current...
  assert.equal(a.get(id).password, 'from-b');
  assert.equal(b.get(id).password, 'from-b');
  assert.equal(a.envelopes.get(id).ct, b.envelopes.get(id).ct);

  // ...and the version that lost is a record of its own on both machines, so
  // the person — not the merge — decides which of the two was right.
  const forkA = a.list().find((r) => r.conflictOf === id);
  const forkB = b.list().find((r) => r.conflictOf === id);
  assert.equal(forkA?.password, 'from-a');
  assert.equal(forkB?.password, 'from-a');
  assert.match(forkA.title, /\(conflict\)$/);

  // Deleting the copy the person rejects converges too — that is the "choose"
  // half of the story, and it must not resurrect on the next sync.
  await a.remove(forkA.id);
  await syncOnce(a, aClient, aState);
  await syncOnce(b, bClient, bState);
  assert.equal(b.get(forkA.id), undefined);
  assert.deepEqual((await syncOnce(a, aClient, aState)).conflicts, []);
});

test('a deletion racing an edit keeps the edit as a conflict copy on every machine', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Shared', password: 'original' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');

  // a rotates the password; b deletes the record. Neither has seen the other.
  await a.update(id, { password: 'CURRENT' });
  await b.remove(id);

  await syncOnce(b, bClient, bState);
  const round = await syncOnce(a, aClient, aState);
  assert.equal(round.conflicts[0]?.kind, 'delete');

  // The tombstone wins — a deletion must not be undone by an edit racing it —
  // but the password it beat is not gone: it is its own record, here and, one
  // sync later, on the machine that deleted.
  assert.equal(a.get(id), undefined);
  const forkA = a.list().find((r) => r.conflictOf === id);
  assert.equal(forkA?.password, 'CURRENT');

  await syncOnce(b, bClient, bState);
  const forkB = b.list().find((r) => r.conflictOf === id);
  assert.equal(forkB?.password, 'CURRENT');

  // And the disagreement is settled, not re-fought every round.
  assert.deepEqual((await syncOnce(a, aClient, aState)).conflicts, []);
  assert.deepEqual((await syncOnce(b, bClient, bState)).conflicts, []);
});

test('a conflict met while locked is kept, and settles at the next unlocked sync', { ...skip }, async (t) => {
  const { a: aClient, b: bClient } = await pair(t);

  const a = await mkVault();
  const aState = emptySyncState();
  const id = await a.add({ title: 'Shared', password: 'original' });
  await syncOnce(a, aClient, aState);

  const b = await follower(a);
  const bState = emptySyncState();
  await syncOnce(b, bClient, bState);
  await b.unlock('hunter2');

  await a.update(id, { password: 'from-a' });
  await b.update(id, { password: 'from-b' });
  await syncOnce(a, aClient, aState);

  // The background sync fires while b sits locked. The conflict cannot be
  // settled without the key, but the losing bytes must not evaporate either.
  b.lock();
  // The round is refused rather than reported as a sync that finished. A
  // locked vault cannot supersede — that re-seals the kept copy and needs the
  // key — so nothing is applied, nothing is pushed, and the sequence is left
  // where it was, which is what lets the next unlocked round see the same
  // conflict and settle it. Reporting success here was how a machine could
  // quietly stop agreeing with the server for ever.
  await assert.rejects(
    () => syncOnce(b, bClient, bState),
    (err) => err.code === 'conflict-locked',
    'a locked vault should refuse a conflict it cannot settle, not report a finished sync',
  );
  assert.equal(b.parked.length, 1, 'the losing copy is parked, key or no key');

  // The park survives what a browser restart does to a vault.
  const reloaded = Vault.load(b.toJSON());
  assert.equal(reloaded.parked.length, 1);

  await reloaded.unlock('hunter2');
  await syncOnce(reloaded, bClient, bState);
  const fork = reloaded.list().find((r) => r.conflictOf === id);
  assert.equal(fork?.password, 'from-a', 'the parked copy became a record after unlock');
  assert.equal(reloaded.parked.length, 0);
});

test('fetch is called on something the browser will accept', async () => {
  // "'fetch' called on an object that does not implement interface Window".
  //
  // Storing fetch on the client and calling this.fetch(...) invokes it with
  // the client as the receiver, which the browser refuses. It shipped, and it
  // read as a routing failure — "no route to the server" — while the server
  // was reachable the whole time. Enrolment worked, because that path calls
  // the function bare, so a device could enrol and then nothing else worked.
  //
  // Every other test injects a plain function, which does not care what it is
  // called on. This one does care, which is the only reason it can fail.
  let receiver = 'never called';
  function pickyFetch() {
    receiver = this;
    return Promise.resolve(new Response('{}', { status: 200, headers: { 'x-bencpass-seq': '0' } }));
  }

  const client = new SyncClient({
    endpoint: 'http://10.0.0.9:8788',
    deviceId: 'd',
    deviceKey: Buffer.from(new Uint8Array(32).fill(7)).toString('base64'),
    fetch: pickyFetch,
  });

  await client.health().catch(() => {});
  assert.notEqual(receiver, 'never called', 'the client never called fetch at all');
  assert.ok(
    receiver === globalThis || receiver === undefined,
    `fetch was called on ${receiver?.constructor?.name ?? typeof receiver}, which a browser refuses`,
  );
});
