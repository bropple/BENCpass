import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  isPrivateHost,
  publicSuffix,
  registrableDomain,
  sameSite,
  hostOf,
  scoreUrl,
  matchesFor,
  canFill,
  canFillAddress,
  EXACT,
  SUBDOMAIN,
  SITE,
  NO_MATCH,
} from '../src/core/match.js';

// This file is the phishing boundary. Everything else in the extension can be
// merely wrong; this being wrong types a password into someone else's form.

test('public suffixes are read from the list, not guessed', () => {
  assert.equal(publicSuffix('example.com'), 'com');
  assert.equal(publicSuffix('example.co.uk'), 'co.uk');
  assert.equal(publicSuffix('a.b.example.co.uk'), 'co.uk');
  assert.equal(publicSuffix('foo.github.io'), 'github.io'); // a private-section rule
});

test('exception rules are honoured', () => {
  // !city.kawasaki.jp means city.kawasaki.jp is registrable, unlike its
  // wildcard siblings under *.kawasaki.jp.
  assert.equal(publicSuffix('city.kawasaki.jp'), 'kawasaki.jp');
  assert.equal(registrableDomain('city.kawasaki.jp'), 'city.kawasaki.jp');
});

test('wildcard rules are honoured', () => {
  // *.ck means anything.ck is a suffix, so a.b.ck registers at b.ck.
  assert.equal(publicSuffix('a.b.ck'), 'b.ck');
  assert.equal(registrableDomain('a.b.ck'), 'a.b.ck');
});

test('registrable domains stop at the right label', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.c.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('a bare public suffix has no registrable domain', () => {
  // Nothing can be registered at this level, so no credential may match it.
  assert.equal(registrableDomain('co.uk'), null);
  assert.equal(registrableDomain('com'), null);
});

test('IP addresses and localhost are their own identity', () => {
  assert.equal(registrableDomain('192.168.1.1'), '192.168.1.1');
  assert.equal(registrableDomain('localhost'), null);
  assert.equal(sameSite('localhost', 'localhost'), true);
  assert.equal(sameSite('192.168.1.1', '192.168.1.2'), false);
});

test('a trailing dot is the same host', () => {
  assert.equal(sameSite('example.com.', 'example.com'), true);
});

// ---- the attacks --------------------------------------------------------

test('a suffix-confusion lookalike does not match', () => {
  // What `host.endsWith('google.com')` would have allowed.
  assert.equal(sameSite('evil-google.com', 'google.com'), false);
  assert.equal(scoreUrl('https://google.com', 'evil-google.com'), NO_MATCH);
});

test('a lookalike that merely contains the domain does not match', () => {
  assert.equal(sameSite('google.com.evil.example', 'google.com'), false);
  assert.equal(scoreUrl('https://google.com/', 'google.com.evil.example'), NO_MATCH);
});

test('two sites under one public suffix are not the same site', () => {
  // What "take the last two labels" would have allowed.
  assert.equal(sameSite('mine.co.uk', 'yours.co.uk'), false);
  assert.equal(sameSite('a.github.io', 'b.github.io'), false);
});

test('a subdomain of the real site does match', () => {
  assert.equal(scoreUrl('https://example.com', 'login.example.com'), SUBDOMAIN);
  assert.equal(scoreUrl('https://login.example.com', 'example.com'), SUBDOMAIN);
  assert.equal(scoreUrl('https://example.com/in', 'example.com'), EXACT);
});

test('unrelated hosts under one site score as site-level, not exact', () => {
  assert.equal(scoreUrl('https://mail.example.com', 'shop.example.com'), SITE);
});

// ---- offering and filling -----------------------------------------------

const login = (title, urls, extra = {}) => ({ type: 'login', title, urls, ...extra });

test('only matching logins are offered, best first', () => {
  const records = [
    login('Exact', ['https://login.example.com']),
    login('Site', ['https://example.com']),
    login('Other', ['https://elsewhere.example']),
    { type: 'address', title: 'Home', urls: [] },
  ];
  const out = matchesFor(records, 'login.example.com');
  assert.deepEqual(out.map((r) => r.title), ['Exact', 'Site']);
});

test('a record with no URL is never offered automatically', () => {
  // It can still be filled by picking it by name in the popup, which is an
  // explicit act naming one entry.
  assert.deepEqual(matchesFor([login('No URL', [])], 'example.com'), []);
});

test('more-used entries come first among equal matches', () => {
  const out = matchesFor(
    [
      login('Rare', ['https://example.com'], { timesUsed: 1 }),
      login('Common', ['https://example.com'], { timesUsed: 90 }),
    ],
    'example.com',
  );
  assert.deepEqual(out.map((r) => r.title), ['Common', 'Rare']);
});

test('filling is refused when the origin does not match', () => {
  const r = login('Bank', ['https://bank.example']);
  assert.deepEqual(canFill(r, 'bank.example'), { ok: true });
  assert.equal(canFill(r, 'bank-example.evil').reason, 'origin-mismatch');
});

test('filling is refused into a cross-origin frame', () => {
  // A login form in a third-party iframe is either a real identity provider or
  // an injected harvester, and from inside the page they are indistinguishable.
  const r = login('Bank', ['https://bank.example']);
  const verdict = canFill(r, 'bank.example', { pageHost: 'news.example' });
  assert.equal(verdict.reason, 'cross-origin-frame');
});

test('filling is refused on an http page unless explicitly allowed', () => {
  const r = login('Bank', ['https://bank.example']);
  assert.equal(canFill(r, 'bank.example', { frameProtocol: 'http:' }).reason, 'insecure-page');
  assert.deepEqual(
    canFill(r, 'bank.example', { frameProtocol: 'http:', allowInsecure: true }),
    { ok: true },
  );
});

test('http on a host that never leaves the network is allowed', () => {
  // Refusing these means refusing to fill a router, a NAS or a printer, none of
  // which will ever have a publicly trusted certificate — which trains someone
  // to disable the warning permanently.
  for (const h of ['127.0.0.1', 'localhost', '192.168.1.1', '10.0.0.5', '172.16.4.2', 'nas.local']) {
    const r = login('Local thing', ['http://' + h]);
    assert.deepEqual(canFill(r, h, { frameProtocol: 'http:' }), { ok: true }, h);
  }
});

test('http on a public host is still refused', () => {
  // The line is "does not leave your network", not "looks internal".
  const r = login('Bank', ['http://bank.example']);
  assert.equal(canFill(r, 'bank.example', { frameProtocol: 'http:' }).reason, 'insecure-page');
  // 172.32 is outside the RFC1918 block, a classic off-by-one in this check.
  const s = login('Not private', ['http://172.32.0.1']);
  assert.equal(canFill(s, '172.32.0.1', { frameProtocol: 'http:' }).reason, 'insecure-page');
});

test('an address is never filled as a login', () => {
  const a = { type: 'address', title: 'Home', urls: [] };
  assert.equal(canFill(a, 'example.com').reason, 'not-a-login');
});

test('hostOf tolerates the bare hostnames importers produce', () => {
  assert.equal(hostOf('https://example.com/login?x=1'), 'example.com');
  assert.equal(hostOf('example.com'), 'example.com');
  assert.equal(hostOf('example.com/login'), 'example.com');
  assert.equal(hostOf('localhost'), 'localhost');
  assert.equal(hostOf(''), '');
  assert.equal(hostOf('not a url'), '');
});

// ---- addresses ------------------------------------------------------------

test('an address is refused to a third-party frame', () => {
  // ARCHITECTURE.md says addresses follow the same rule as passwords. They are
  // not origin-bound — any address may go in any checkout — but handing one to
  // an unrelated frame is the same mistake, only quieter.
  assert.deepEqual(canFillAddress('shop.example'), { ok: true });
  assert.equal(
    canFillAddress('harvester.example', { pageHost: 'shop.example' }).reason,
    'cross-origin-frame',
  );
});

test('an address is refused over plain http on a public host', () => {
  assert.equal(
    canFillAddress('shop.example', { frameProtocol: 'http:' }).reason,
    'insecure-page',
  );
  assert.deepEqual(canFillAddress('192.168.1.50', { frameProtocol: 'http:' }), { ok: true });
});
