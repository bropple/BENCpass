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
  const b = await device(endpoint, 'machine-b', await a.mintCode());
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
  assert.ok(fetch.seen[1].startsWith('https://tail.ts.net'));
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
    assert.match(err.message, /lan:8788/);
    assert.match(err.message, /tail\.ts\.net/);
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
  assert.ok(fetch.seen[0].startsWith('https://tail.ts.net'));
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
