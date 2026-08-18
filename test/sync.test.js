import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Vault } from '../src/core/vault.js';
import { SyncClient, syncOnce, emptySyncState, SyncError, canonical } from '../src/core/sync.js';

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
