// Ordering a list, and finding the passwords that are on more than one entry.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ORDER, reuseCounts, reuseGroups } from '../src/core/listing.js';

const login = (title, extra = {}) => ({
  id: title,
  type: 'login',
  title,
  password: 'pw-' + title,
  ...extra,
});

const day = (s) => Date.parse(s);

test('A–Z is the default and sorts by title', () => {
  const rows = [login('Zebra'), login('apple'), login('Mouser')];
  assert.deepEqual(rows.sort(ORDER.title).map((r) => r.title), ['apple', 'Mouser', 'Zebra']);
});

test('newest added puts the most recent first, oldest added reverses it', () => {
  const rows = [
    login('old', { created: day('2019-01-01') }),
    login('new', { created: day('2026-09-01') }),
    login('middle', { created: day('2022-06-01') }),
  ];
  assert.deepEqual(rows.slice().sort(ORDER.added).map((r) => r.title), ['new', 'middle', 'old']);
  assert.deepEqual(rows.slice().sort(ORDER.oldest).map((r) => r.title), ['old', 'middle', 'new']);
});

test('oldest password first is what a rotation is worked through in', () => {
  const rows = [
    login('recent', { passwordChanged: day('2026-08-01') }),
    login('ancient', { passwordChanged: day('2014-02-02') }),
  ];
  assert.deepEqual(rows.sort(ORDER.stale).map((r) => r.title), ['ancient', 'recent']);
});

test('entries sharing a date come back in a stable order, not the map’s', () => {
  // After an import every entry has the same created date, and without the
  // tiebreak the list reshuffles between redraws while somebody reads it.
  const same = day('2026-08-20');
  const rows = [login('c', { created: same }), login('a', { created: same }), login('b', { created: same })];
  const once = rows.slice().sort(ORDER.added).map((r) => r.title);
  const twice = rows.slice().reverse().sort(ORDER.added).map((r) => r.title);
  assert.deepEqual(once, ['a', 'b', 'c']);
  assert.deepEqual(twice, once, 'the same records sorted to a different order');
});

test('a record with no date still appears', () => {
  const rows = [login('dated', { created: day('2020-01-01') }), login('undated')];
  assert.equal(rows.slice().sort(ORDER.added).length, 2);
  assert.equal(rows.slice().sort(ORDER.stale).length, 2);
});

test('reuse counts every entry that shares a password, and nothing else', () => {
  const shared = 'hunter2';
  const rows = [
    login('bank', { password: shared }),
    login('forum', { password: shared }),
    login('mail', { password: shared }),
    login('unique', { password: 'only-here' }),
  ];

  const counts = reuseCounts(rows);
  assert.equal(counts.get('bank'), 3);
  assert.equal(counts.get('forum'), 3);
  assert.equal(counts.get('mail'), 3);
  assert.equal(counts.has('unique'), false, 'an unshared password was flagged');
});

test('an empty password is not reuse, however many entries have one', () => {
  // Half an imported vault can have no password at all. Calling those a
  // reuse group would bury the real ones under it.
  const rows = [login('a', { password: '' }), login('b', { password: '' }), login('c', { password: undefined })];
  assert.equal(reuseCounts(rows).size, 0);
});

test('an address is never part of a reuse group', () => {
  const rows = [
    login('login', { password: 'x' }),
    { id: 'addr', type: 'address', title: 'Home', password: 'x' },
  ];
  assert.equal(reuseCounts(rows).size, 0, 'an address was counted as sharing a password');
});

test('the group names the other entries, which is what the detail pane shows', () => {
  const rows = [
    login('bank', { password: 'same' }),
    login('forum', { password: 'same' }),
    login('alone', { password: 'other' }),
  ];
  const groups = reuseGroups(rows);
  assert.deepEqual(groups.get('bank').map((r) => r.title), ['forum']);
  assert.deepEqual(groups.get('forum').map((r) => r.title), ['bank']);
  assert.equal(groups.has('alone'), false);

  // An entry is never listed as sharing with itself.
  for (const [id, others] of groups) {
    assert.ok(!others.some((o) => o.id === id), `${id} was shared with itself`);
  }
});
