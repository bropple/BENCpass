import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyLoginFields,
  classifyGroups,
  classifyAddressFields,
  isUsernameOnlyStep,
  autocompleteToken,
  autocompleteSection,
} from '../src/core/fields.js';

// Descriptors, not elements — the classifier is pure so the awkward cases can
// be written down as data. `index` is DOM order and the username heuristic
// depends on it.
let n = 0;
const f = (props) => ({ tag: 'input', type: 'text', visible: true, index: n++, ...props });
const form = (...fields) => {
  n = 0;
  return fields.map((p, i) => f({ ...p, index: i }));
};

// ---- autocomplete parsing ------------------------------------------------

test('autocomplete tokens are pulled out of their modifiers', () => {
  assert.equal(autocompleteToken('username'), 'username');
  assert.equal(autocompleteToken('shipping address-line1'), 'address-line1');
  assert.equal(autocompleteToken('section-blue billing tel'), 'tel');
  assert.equal(autocompleteSection('shipping address-line1'), 'shipping');
  assert.equal(autocompleteSection('billing postal-code'), 'billing');
});

test('autocomplete="off" is not a description of a field', () => {
  // It is a request not to autofill, routinely set on fields that still need
  // identifying — treating it as a field name would classify nothing.
  assert.equal(autocompleteToken('off'), null);
  assert.equal(autocompleteToken('on'), null);
  assert.equal(autocompleteToken(''), null);
  assert.equal(autocompleteToken(null), null);
});

// ---- the easy half: pages that set autocomplete ---------------------------

test('a well-marked login form is read straight off the attributes', () => {
  const fields = form(
    { name: 'u', autocomplete: 'username' },
    { name: 'p', type: 'password', autocomplete: 'current-password' },
  );
  const r = classifyLoginFields(fields);
  assert.equal(r.username.name, 'u');
  assert.equal(r.password.name, 'p');
  assert.equal(r.newPassword, null);
});

test('a change-password form separates the current and new boxes', () => {
  const fields = form(
    { name: 'old', type: 'password', autocomplete: 'current-password' },
    { name: 'new', type: 'password', autocomplete: 'new-password' },
    { name: 'again', type: 'password', autocomplete: 'new-password' },
  );
  const r = classifyLoginFields(fields);
  assert.equal(r.password.name, 'old');
  assert.equal(r.newPassword.name, 'new');
});

// ---- the hard half: pages that set nothing --------------------------------

test('position beats keywords for the username', () => {
  // "email" appears on a newsletter box further down; the field immediately
  // before the password is the real one.
  const fields = form(
    { name: 'account_id' },
    { name: 'pass', type: 'password' },
    { name: 'newsletter_email', type: 'email' },
  );
  assert.equal(classifyLoginFields(fields).username.name, 'account_id');
});

test('a search box is not mistaken for a username', () => {
  const fields = form(
    { name: 'q', placeholder: 'Search' },
    { name: 'login_email', type: 'email' },
    { name: 'pw', type: 'password' },
  );
  assert.equal(classifyLoginFields(fields).username.name, 'login_email');
});

test('two unmarked password boxes are read as a sign-up', () => {
  // Offering to generate into a sign-up form is harmless. Filling an existing
  // password into a "choose a password" box is not, so this is the safe reading.
  const fields = form(
    { name: 'email', type: 'email' },
    { name: 'password', type: 'password' },
    { name: 'password_confirm', type: 'password' },
  );
  const r = classifyLoginFields(fields);
  assert.equal(r.newPassword.name, 'password');
  assert.equal(r.password, null);
});

test('a single box named "new password" is not filled with the old one', () => {
  const fields = form({ name: 'new_password', type: 'password' });
  const r = classifyLoginFields(fields);
  assert.equal(r.newPassword.name, 'new_password');
  assert.equal(r.password, null);
});

test('a plain single password box is a login', () => {
  const fields = form({ name: 'user' }, { name: 'pass', type: 'password' });
  const r = classifyLoginFields(fields);
  assert.equal(r.password.name, 'pass');
  assert.equal(r.newPassword, null);
});

test('a label supplies the hint when the name is meaningless', () => {
  const fields = form(
    { name: 'ctl00$x1', label: 'Email address' },
    { name: 'ctl00$x2', type: 'password', label: 'Password' },
  );
  assert.equal(classifyLoginFields(fields).username.name, 'ctl00$x1');
});

test('hidden fields are ignored', () => {
  const fields = form(
    { name: 'honeypot', visible: false },
    { name: 'user' },
    { name: 'pw', type: 'password' },
  );
  assert.equal(classifyLoginFields(fields).username.name, 'user');
});

test('disabled and read-only fields are not fillable', () => {
  const fields = form(
    { name: 'user', disabled: true },
    { name: 'user2', readOnly: true },
    { name: 'user3' },
    { name: 'pw', type: 'password' },
  );
  assert.equal(classifyLoginFields(fields).username.name, 'user3');
});

// ---- one-time codes -------------------------------------------------------

test('a one-time code field is identified and kept out of the username slot', () => {
  const fields = form({ name: 'otp_code', placeholder: 'Authentication code' });
  const r = classifyLoginFields(fields);
  assert.equal(r.otp.name, 'otp_code');
  assert.equal(r.username, null);
});

test('autocomplete one-time-code is honoured', () => {
  const fields = form({ name: 'x', autocomplete: 'one-time-code' });
  assert.equal(classifyLoginFields(fields).otp.name, 'x');
});

// ---- two-step logins ------------------------------------------------------

test('a username-only step is recognised', () => {
  // The shape Microsoft and Google use. Missing it means doing nothing on the
  // first page of a great many sign-ins.
  assert.equal(isUsernameOnlyStep(form({ name: 'loginfmt', type: 'email' })), true);
  assert.equal(
    isUsernameOnlyStep(form({ name: 'user' }, { name: 'pw', type: 'password' })),
    false,
  );
});

test('a page of unrelated text boxes is not a username step', () => {
  assert.equal(isUsernameOnlyStep(form({ name: 'q', placeholder: 'Search' })), false);
});

// ---- addresses ------------------------------------------------------------

test('address fields marked with autocomplete map straight to record keys', () => {
  const fields = form(
    { name: 'a', autocomplete: 'shipping address-line1' },
    { name: 'b', autocomplete: 'shipping address-level2' },
    { name: 'c', autocomplete: 'shipping postal-code' },
    { name: 'd', autocomplete: 'shipping country' },
  );
  const out = classifyAddressFields(fields);
  assert.deepEqual(
    out.map((o) => o.token),
    ['address-line1', 'address-level2', 'postal-code', 'country'],
  );
  assert.equal(out[0].section, 'shipping');
});

test('unmarked address fields are guessed from their names', () => {
  const fields = form(
    { name: 'street_address' },
    { name: 'address2', placeholder: 'Apt, suite' },
    { name: 'city' },
    { name: 'state' },
    { name: 'zip' },
    { name: 'phone', type: 'tel' },
  );
  const out = classifyAddressFields(fields);
  assert.deepEqual(
    out.map((o) => o.token),
    ['address-line1', 'address-line2', 'address-level2', 'address-level1', 'postal-code', 'tel'],
  );
});

test('address-line2 is not swallowed by the address-line1 pattern', () => {
  // "address2" contains "address"; ordering the patterns wrongly puts both
  // lines of every address into the first box.
  const out = classifyAddressFields(form({ name: 'address2' }));
  assert.equal(out[0].token, 'address-line2');
});

test('a postcode field is matched even though it looks like a coupon box', () => {
  const out = classifyAddressFields(form({ name: 'zip_code' }));
  assert.equal(out[0].token, 'postal-code');
});

test('a discount code box is not treated as an address field', () => {
  assert.deepEqual(classifyAddressFields(form({ name: 'promo_code' })), []);
});

// ---- more than one form on a page -----------------------------------------

test('each form is classified on its own', () => {
  // The whole-document version of this saw four password boxes, read the count
  // as a sign-up, picked the first, and left every later form unrecognised.
  const fields = [
    { tag: 'input', type: 'text', name: 'user1', index: 0, group: 1, visible: true },
    { tag: 'input', type: 'password', name: 'pw1', index: 1, group: 1, visible: true },
    { tag: 'input', type: 'email', name: 'user2', index: 2, group: 2, visible: true },
    { tag: 'input', type: 'password', name: 'pw2', index: 3, group: 2, visible: true },
  ];

  const groups = classifyGroups(fields);
  assert.equal(groups.length, 2);

  assert.equal(groups[0].login.username.name, 'user1');
  assert.equal(groups[0].login.password.name, 'pw1');
  assert.equal(groups[0].login.newPassword, null);

  // The second form is a login too, not a sign-up — which is what the
  // single-group reading turned it into.
  assert.equal(groups[1].login.username.name, 'user2');
  assert.equal(groups[1].login.password.name, 'pw2');
  assert.equal(groups[1].login.newPassword, null);
});

test('a sign-up form beside a login form does not contaminate it', () => {
  const fields = [
    { tag: 'input', type: 'text', name: 'user', index: 0, group: 1, visible: true },
    { tag: 'input', type: 'password', name: 'pw', index: 1, group: 1, visible: true },
    { tag: 'input', type: 'email', name: 'signup_email', index: 2, group: 2, visible: true },
    { tag: 'input', type: 'password', name: 'choose', index: 3, group: 2, visible: true },
    { tag: 'input', type: 'password', name: 'confirm', index: 4, group: 2, visible: true },
  ];
  const [login, signup] = classifyGroups(fields);

  assert.equal(login.login.password.name, 'pw');
  assert.equal(login.login.newPassword, null);

  assert.equal(signup.login.newPassword.name, 'choose');
  assert.equal(signup.login.password, null);
});

test('fields with no form share one group', () => {
  const fields = [
    { tag: 'input', type: 'text', name: 'user', index: 0, visible: true },
    { tag: 'input', type: 'password', name: 'pw', index: 1, visible: true },
  ];
  const groups = classifyGroups(fields);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].login.password.name, 'pw');
});
