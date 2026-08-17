// The address model: what is stored, what is derived, and what is refused.
//
// The rule the whole file is really testing is the second one in address.js —
// a form gets exactly what it asked for and nothing else. Most of the bugs
// this can catch are of the shape "we volunteered a field nobody wanted" or
// "we guessed a value we had no way to know".

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ADDRESS_SCHEMA,
  ADDRESS_TOKENS,
  STORED_TOKENS,
  countryCode,
  countryName,
  countryOptions,
  isAddressish,
  joinName,
  normalizeCaptured,
  splitName,
  telParts,
  valuesForTokens,
} from '../src/core/address.js';

const HOME = {
  'given-name': 'Ben',
  'family-name': 'Ropple',
  organization: 'BENCO Holdings',
  'address-line1': '1 Pentagon Way',
  'address-line2': 'Unit 4',
  'address-level2': 'Springfield',
  'address-level1': 'California',
  'postal-code': '90210',
  country: 'US',
  tel: '+1 (415) 555-0132',
  email: 'ben@ropple.net',
};

// ---- the schema ------------------------------------------------------------

test('no payment field is anywhere in the model', () => {
  for (const token of ADDRESS_TOKENS) {
    assert.ok(!token.startsWith('cc-'), `${token} is a payment field`);
  }
  // Nor the other things that share the WHATWG table but are not an address.
  for (const token of ['bday', 'sex', 'photo', 'impp', 'password', 'new-password']) {
    assert.ok(!ADDRESS_TOKENS.has(token), `${token} should not be an address field`);
  }
});

test('every schema entry is a stored token and every label is distinct', () => {
  const labels = new Set();
  for (const field of ADDRESS_SCHEMA) {
    assert.ok(STORED_TOKENS.has(field.token));
    assert.ok(field.label, `${field.token} has no label`);
    assert.ok(!labels.has(field.label), `duplicate label ${field.label}`);
    labels.add(field.label);
  }
});

// ---- countries -------------------------------------------------------------

test('country codes resolve from codes, names and the usual alternatives', () => {
  assert.equal(countryCode('US'), 'US');
  assert.equal(countryCode('us'), 'US');
  assert.equal(countryCode('United States'), 'US');
  assert.equal(countryCode('United States of America'), 'US');
  assert.equal(countryCode('USA'), 'US');
  assert.equal(countryCode('Great Britain'), 'GB');
  assert.equal(countryCode('Holland'), 'NL');
  assert.equal(countryName('GB'), 'United Kingdom');
});

test('spelling differences that are not really differences still match', () => {
  // Diacritics, curly apostrophes and ampersands, which is why the alias list
  // does not need an entry for every country that has one.
  assert.equal(countryCode('Côte d’Ivoire'), 'CI');
  assert.equal(countryCode("COTE D'IVOIRE"), 'CI');
  assert.equal(countryCode('Antigua and Barbuda'), 'AG');
  assert.equal(countryCode('Antigua & Barbuda'), 'AG');
});

test('a country that is not one resolves to nothing', () => {
  assert.equal(countryCode('Atlantis'), '');
  assert.equal(countryCode(''), '');
  assert.equal(countryCode(null), '');
  // Withdrawn from ISO 3166-1 in 2010, and so absent from every country list a
  // page will show.
  assert.equal(countryCode('AN'), '');
});

test('the country list is complete enough to be a country list', () => {
  const options = countryOptions();
  assert.ok(options.length > 240, `only ${options.length} countries`);
  assert.ok(options.every(([code, name]) => /^[A-Z]{2}$/.test(code) && name.length > 1));
  // Sorted by name, since that is the order it is shown in.
  const names = options.map(([, name]) => name);
  assert.deepEqual(names, [...names].sort((a, b) => a.localeCompare(b, 'en')));
});

// ---- names -----------------------------------------------------------------

test('a full name is joined from its parts', () => {
  assert.equal(joinName(HOME), 'Ben Ropple');
  assert.equal(joinName({ 'given-name': 'Ada', 'additional-name': 'K', 'family-name': 'L' }), 'Ada K L');
});

test('a record that only kept a whole name still answers for one', () => {
  assert.equal(joinName({ name: 'Ben Ropple' }), 'Ben Ropple');
});

test('a whole name splits, and admits how little it knows', () => {
  assert.deepEqual(splitName('Ben Ropple'), { 'given-name': 'Ben', 'additional-name': undefined, 'family-name': 'Ropple' });
  assert.deepEqual(splitName('Ben Q Ropple'), { 'given-name': 'Ben', 'additional-name': 'Q', 'family-name': 'Ropple' });
  assert.deepEqual(splitName('Prince'), { 'given-name': 'Prince' });
  assert.deepEqual(splitName('   '), {});
});

// ---- telephone -------------------------------------------------------------

test('a written-out country code is taken, and the rest kept whole', () => {
  const parts = telParts('+44 118 496 0000');
  assert.equal(parts['tel-country-code'], '+44');
  assert.equal(parts['tel-national'], '118 496 0000');
});

test('a North American number splits into area code and local number', () => {
  const parts = telParts('+1 (415) 555-0132');
  assert.equal(parts['tel-country-code'], '+1');
  assert.equal(parts['tel-area-code'], '415');
  assert.equal(parts['tel-local'], '5550132');
  assert.equal(parts['tel-local-prefix'], '555');
  assert.equal(parts['tel-local-suffix'], '0132');
});

test('a number with no country code and ten digits is assumed North American', () => {
  assert.equal(telParts('415-555-0132')['tel-area-code'], '415');
});

test('a number that cannot be split is not split', () => {
  // +44 or +441? Nothing in the string says, so nothing is claimed.
  const run = telParts('+441184960000');
  assert.equal(run['tel-country-code'], undefined);
  assert.equal(run['tel-national'], undefined);
  assert.equal(run.tel, '+441184960000');

  // A national number outside the North American plan has no findable area code.
  const uk = telParts('+44 118 496 0000');
  assert.equal(uk['tel-area-code'], undefined);
  assert.equal(uk['tel-local'], undefined);
});

// ---- answering a form ------------------------------------------------------

test('a form is given what it asked for and nothing else', () => {
  const { values } = valuesForTokens(HOME, ['postal-code', 'address-line1']);
  assert.deepEqual(Object.keys(values).sort(), ['address-line1', 'postal-code']);
  // The record has a phone number, an email and a name. None of them travelled.
  assert.equal(values.tel, undefined);
  assert.equal(values.email, undefined);
});

test('composite fields are built from the parts', () => {
  const { values } = valuesForTokens(HOME, ['name', 'street-address', 'country-name']);
  assert.equal(values.name, 'Ben Ropple');
  assert.equal(values['street-address'], '1 Pentagon Way\nUnit 4');
  assert.equal(values['country-name'], 'United States');
});

test('name parts are answered from a record that only kept the whole name', () => {
  const { values } = valuesForTokens({ name: 'Ben Ropple' }, ['given-name', 'family-name']);
  assert.equal(values['given-name'], 'Ben');
  assert.equal(values['family-name'], 'Ropple');
});

test('a token the record cannot supply is left out entirely', () => {
  const sparse = { 'postal-code': 'RG1 4QX' };
  const { values } = valuesForTokens(sparse, ['postal-code', 'tel', 'country', 'organization']);
  assert.deepEqual(values, { 'postal-code': 'RG1 4QX' });
});

test('a token that is not an address field is ignored, however it is asked for', () => {
  const { values } = valuesForTokens(HOME, ['cc-number', 'password', 'bday', '__proto__', 'email']);
  assert.deepEqual(Object.keys(values), ['email']);
});

test('a dropdown gets the alternatives it may be spelled with', () => {
  const { values, alts } = valuesForTokens(HOME, ['country', 'address-level1']);
  assert.equal(values.country, 'US');
  assert.ok(alts.country.includes('United States'));
  assert.ok(alts.country.includes('USA'));
  // A state stored by name can still match a dropdown of abbreviations.
  assert.deepEqual(alts['address-level1'], ['CA']);
});

test('a state outside the countries with a subdivision table has no alternatives', () => {
  const gb = { ...HOME, country: 'GB', 'address-level1': 'Berkshire' };
  const { alts } = valuesForTokens(gb, ['address-level1']);
  assert.equal(alts['address-level1'], undefined);
});

test('asking twice for the same token does not produce it twice', () => {
  const { values } = valuesForTokens(HOME, ['email', 'email']);
  assert.deepEqual(values, { email: 'ben@ropple.net' });
});

// ---- taking one in ---------------------------------------------------------

test('a single name box is split on the way in', () => {
  const out = normalizeCaptured({ name: 'Ben Ropple', 'postal-code': '90210', 'address-line1': 'x' });
  assert.equal(out['given-name'], 'Ben');
  assert.equal(out['family-name'], 'Ropple');
});

test('explicit name parts are preferred over a whole name box', () => {
  const out = normalizeCaptured({
    name: 'Wrong Person',
    'given-name': 'Ben',
    'family-name': 'Ropple',
    'address-line1': '1 Pentagon Way',
    'postal-code': '90210',
  });
  assert.equal(out['given-name'], 'Ben');
  assert.equal(out['family-name'], 'Ropple');
});

test('one street box becomes numbered lines', () => {
  const out = normalizeCaptured({
    'street-address': '1 Pentagon Way\nUnit 4\nSpringfield',
    'postal-code': '90210',
  });
  assert.equal(out['address-line1'], '1 Pentagon Way');
  assert.equal(out['address-line2'], 'Unit 4');
  assert.equal(out['address-line3'], 'Springfield');
});

test('a country name becomes a country code', () => {
  assert.equal(normalizeCaptured({ country: 'United Kingdom', 'postal-code': 'x' }).country, 'GB');
  assert.equal(normalizeCaptured({ 'country-name': 'Germany', 'postal-code': 'x' }).country, 'DE');
});

test('a country that resolves to nothing is dropped rather than stored wrong', () => {
  assert.equal(normalizeCaptured({ country: 'Select a country…', 'postal-code': 'x' }).country, undefined);
});

test('a phone number split across boxes is reassembled', () => {
  const out = normalizeCaptured({
    'tel-country-code': '+1',
    'tel-area-code': '415',
    'tel-local': '5550132',
    'postal-code': '90210',
  });
  assert.equal(out.tel, '+1 415 5550132');
});

test('nothing outside the stored schema survives capture', () => {
  const out = normalizeCaptured({
    'address-line1': '1 Pentagon Way',
    'postal-code': '90210',
    'cc-number': '4111111111111111',
    notes: 'not an address field',
  });
  assert.equal(out['cc-number'], undefined);
  assert.equal(out.notes, undefined);
});

test('captured values are bounded', () => {
  const out = normalizeCaptured(
    { 'address-line1': 'x'.repeat(9000), 'postal-code': '90210' },
    64,
  );
  assert.equal(out['address-line1'].length, 64);
});

// ---- is it an address at all ----------------------------------------------

test('two structural fields make an address; contact details alone do not', () => {
  assert.ok(isAddressish({ 'address-line1': 'x', 'postal-code': 'y' }));
  assert.ok(!isAddressish({ 'given-name': 'Ben', email: 'ben@ropple.net', tel: '123' }));
  assert.ok(!isAddressish({ 'postal-code': 'y' }));
  assert.ok(!isAddressish({}));
  assert.ok(!isAddressish(null));
});
