import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Vault } from '../src/core/vault.js';
import { SyncClient, syncOnce, emptySyncState, SyncError } from '../src/core/sync.js';

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
  binary = join(buildDir, 'bencpass-server');
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
