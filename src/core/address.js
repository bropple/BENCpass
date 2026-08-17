// What an address is, and how to answer a form that asks for part of one.
//
// The record stores the *granular* pieces — first name and last name, not a
// full name; three street lines, not one block; a country code, not a country
// name. Composite fields are then derived on demand. That direction is the only
// one that works: joining is exact, splitting is a guess, so anything a form
// asks for can be built from granular storage, while the reverse loses
// information the moment a site wants "First name" and all we kept was "Ben
// Ropple".
//
// The other half of the job is restraint. A form is answered with exactly the
// tokens it asked for, and only those it asked for that we can actually supply.
// Nothing is volunteered: a checkout wanting a postcode gets a postcode, not a
// phone number it never requested, and a token we cannot derive honestly — an
// area code for a number whose country we cannot parse — is left alone rather
// than filled with a plausible guess.
//
// Deliberately absent: every `cc-*` token. BENCpass does not store payment
// details, so it has nothing to put in them and no reason to recognise them.
// Also absent: `bday`, `sex`, `photo`, `impp`. They are in the same WHATWG
// table but they are not an address, and a delivery form has no business
// receiving them.
//
// Pure and DOM-free, so the whole of it is testable under Node.

// ---- the stored schema ----------------------------------------------------
//
// `token` is the WHATWG autofill field name, used verbatim as the record key,
// so the model, the fill code and the editor cannot drift apart. `rare` fields
// are real but seldom asked for; the manager keeps them behind a disclosure so
// the editor stays short.

export const ADDRESS_SCHEMA = [
  // "Salutation", not "Title" — the record has a title of its own, and two
  // fields under one word in the same editor is a small cruelty.
  { token: 'honorific-prefix', label: 'Salutation', rare: true, placeholder: 'Mr, Ms, Dr' },
  { token: 'given-name', label: 'First name' },
  { token: 'additional-name', label: 'Middle name', rare: true },
  { token: 'family-name', label: 'Last name' },
  { token: 'honorific-suffix', label: 'Suffix', rare: true, placeholder: 'Jr, PhD' },
  { token: 'organization', label: 'Company' },
  { token: 'organization-title', label: 'Job title', rare: true },
  { token: 'address-line1', label: 'Address' },
  { token: 'address-line2', label: 'Address line 2' },
  { token: 'address-line3', label: 'Address line 3', rare: true },
  { token: 'address-level4', label: 'Sublocality', rare: true },
  { token: 'address-level3', label: 'District / Suburb', rare: true },
  { token: 'address-level2', label: 'City / Town' },
  { token: 'address-level1', label: 'State / Province / County' },
  { token: 'postal-code', label: 'Postcode / ZIP' },
  { token: 'country', label: 'Country', kind: 'country' },
  { token: 'tel', label: 'Phone' },
  { token: 'tel-extension', label: 'Extension', rare: true },
  { token: 'email', label: 'Email' },
];

/** The record keys an address may hold. */
export const STORED_TOKENS = new Set(ADDRESS_SCHEMA.map((f) => f.token));

/**
 * Tokens that may be *derived* from stored ones, and so can be recognised in a
 * page and filled even though nothing stores them directly.
 */
export const DERIVED_TOKENS = new Set([
  'name',
  'street-address',
  'country-name',
  'tel-country-code',
  'tel-national',
  'tel-area-code',
  'tel-local',
  'tel-local-prefix',
  'tel-local-suffix',
]);

/** Everything BENCpass will recognise on a page as part of an address. */
export const ADDRESS_TOKENS = new Set([...STORED_TOKENS, ...DERIVED_TOKENS]);

/**
 * Tokens that say "this really is an address form" rather than "this might be
 * anything". A name, an email and a phone number appear on sign-in pages,
 * newsletter boxes and support forms; a postcode does not.
 */
export const STRUCTURAL_TOKENS = new Set([
  'street-address',
  'address-line1',
  'address-line2',
  'address-line3',
  'address-level1',
  'address-level2',
  'address-level3',
  'address-level4',
  'postal-code',
  'country',
  'country-name',
  'organization',
]);

// ---- countries ------------------------------------------------------------
//
// ISO 3166-1 alpha-2 against the English (CLDR) name, generated rather than
// typed — see tools/gen-countries.mjs. The record stores the code, because a
// code is stable and unambiguous and most country <select> elements use it as
// the option value. The name is derived when a form asks for `country-name`,
// or when an option list turns out to be spelled out.

const COUNTRY_TABLE =
  'AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua & Barbuda|AI:Anguilla' +
  '|AL:Albania|AM:Armenia|AO:Angola|AQ:Antarctica|AR:Argentina|AS:American Samoa|AT:Austria' +
  '|AU:Australia|AW:Aruba|AX:Åland Islands|AZ:Azerbaijan|BA:Bosnia & Herzegovina|BB:Barbados' +
  '|BD:Bangladesh|BE:Belgium|BF:Burkina Faso|BG:Bulgaria|BH:Bahrain|BI:Burundi|BJ:Benin' +
  '|BL:St. Barthélemy|BM:Bermuda|BN:Brunei|BO:Bolivia|BQ:Caribbean Netherlands|BR:Brazil' +
  '|BS:Bahamas|BT:Bhutan|BV:Bouvet Island|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada' +
  '|CC:Cocos (Keeling) Islands|CD:Congo - Kinshasa|CF:Central African Republic' +
  '|CG:Congo - Brazzaville|CH:Switzerland|CI:Côte d’Ivoire|CK:Cook Islands|CL:Chile' +
  '|CM:Cameroon|CN:China|CO:Colombia|CQ:Sark|CR:Costa Rica|CU:Cuba|CV:Cape Verde|CW:Curaçao' +
  '|CX:Christmas Island|CY:Cyprus|CZ:Czechia|DE:Germany|DJ:Djibouti|DK:Denmark|DM:Dominica' +
  '|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|EE:Estonia|EG:Egypt|EH:Western Sahara' +
  '|ER:Eritrea|ES:Spain|ET:Ethiopia|FI:Finland|FJ:Fiji|FK:Falkland Islands|FM:Micronesia' +
  '|FO:Faroe Islands|FR:France|GA:Gabon|GB:United Kingdom|GD:Grenada|GE:Georgia' +
  '|GF:French Guiana|GG:Guernsey|GH:Ghana|GI:Gibraltar|GL:Greenland|GM:Gambia|GN:Guinea' +
  '|GP:Guadeloupe|GQ:Equatorial Guinea|GR:Greece|GS:South Georgia & South Sandwich Islands' +
  '|GT:Guatemala|GU:Guam|GW:Guinea-Bissau|GY:Guyana|HK:Hong Kong SAR China' +
  '|HM:Heard & McDonald Islands|HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|ID:Indonesia' +
  '|IE:Ireland|IL:Israel|IM:Isle of Man|IN:India|IO:British Indian Ocean Territory|IQ:Iraq' +
  '|IR:Iran|IS:Iceland|IT:Italy|JE:Jersey|JM:Jamaica|JO:Jordan|JP:Japan|KE:Kenya' +
  '|KG:Kyrgyzstan|KH:Cambodia|KI:Kiribati|KM:Comoros|KN:St. Kitts & Nevis|KP:North Korea' +
  '|KR:South Korea|KW:Kuwait|KY:Cayman Islands|KZ:Kazakhstan|LA:Laos|LB:Lebanon|LC:St. Lucia' +
  '|LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Lithuania|LU:Luxembourg|LV:Latvia' +
  '|LY:Libya|MA:Morocco|MC:Monaco|MD:Moldova|ME:Montenegro|MF:St. Martin|MG:Madagascar' +
  '|MH:Marshall Islands|MK:North Macedonia|ML:Mali|MM:Myanmar (Burma)|MN:Mongolia' +
  '|MO:Macao SAR China|MP:Northern Mariana Islands|MQ:Martinique|MR:Mauritania|MS:Montserrat' +
  '|MT:Malta|MU:Mauritius|MV:Maldives|MW:Malawi|MX:Mexico|MY:Malaysia|MZ:Mozambique' +
  '|NA:Namibia|NC:New Caledonia|NE:Niger|NF:Norfolk Island|NG:Nigeria|NI:Nicaragua' +
  '|NL:Netherlands|NO:Norway|NP:Nepal|NR:Nauru|NU:Niue|NZ:New Zealand|OM:Oman|PA:Panama' +
  '|PE:Peru|PF:French Polynesia|PG:Papua New Guinea|PH:Philippines|PK:Pakistan|PL:Poland' +
  '|PM:St. Pierre & Miquelon|PN:Pitcairn Islands|PR:Puerto Rico|PS:Palestinian Territories' +
  '|PT:Portugal|PW:Palau|PY:Paraguay|QA:Qatar|RE:Réunion|RO:Romania|RS:Serbia|RU:Russia' +
  '|RW:Rwanda|SA:Saudi Arabia|SB:Solomon Islands|SC:Seychelles|SD:Sudan|SE:Sweden' +
  '|SG:Singapore|SH:St. Helena|SI:Slovenia|SJ:Svalbard & Jan Mayen|SK:Slovakia' +
  '|SL:Sierra Leone|SM:San Marino|SN:Senegal|SO:Somalia|SR:Suriname|SS:South Sudan' +
  '|ST:São Tomé & Príncipe|SV:El Salvador|SX:Sint Maarten|SY:Syria|SZ:Eswatini' +
  '|TC:Turks & Caicos Islands|TD:Chad|TF:French Southern Territories|TG:Togo|TH:Thailand' +
  '|TJ:Tajikistan|TK:Tokelau|TL:Timor-Leste|TM:Turkmenistan|TN:Tunisia|TO:Tonga|TR:Türkiye' +
  '|TT:Trinidad & Tobago|TV:Tuvalu|TW:Taiwan|TZ:Tanzania|UA:Ukraine|UG:Uganda' +
  '|UM:U.S. Outlying Islands|US:United States|UY:Uruguay|UZ:Uzbekistan|VA:Vatican City' +
  '|VC:St. Vincent & Grenadines|VE:Venezuela|VG:British Virgin Islands' +
  '|VI:U.S. Virgin Islands|VN:Vietnam|VU:Vanuatu|WF:Wallis & Futuna|WS:Samoa|YE:Yemen' +
  '|YT:Mayotte|ZA:South Africa|ZM:Zambia|ZW:Zimbabwe|ZZ:Unknown Region';

const CODE_TO_NAME = new Map();
for (const entry of COUNTRY_TABLE.split('|')) {
  const at = entry.indexOf(':');
  CODE_TO_NAME.set(entry.slice(0, at), entry.slice(at + 1));
}

/**
 * Spellings a page might use that are not the CLDR name.
 *
 * Only the ones that actually differ. Diacritics, ampersands and curly
 * apostrophes are handled by normalisation instead, which covers far more
 * ground than any list could.
 */
const COUNTRY_ALIASES = {
  US: ['United States of America', 'USA', 'U.S.A.', 'U.S.', 'America'],
  GB: ['United Kingdom of Great Britain and Northern Ireland', 'UK', 'Great Britain', 'England'],
  KR: ['Korea, Republic of', 'Republic of Korea', 'Korea (South)'],
  KP: ["Korea, Democratic People's Republic of", 'Korea (North)'],
  RU: ['Russian Federation'],
  IR: ['Iran, Islamic Republic of'],
  SY: ['Syrian Arab Republic'],
  VN: ['Viet Nam'],
  LA: ["Lao People's Democratic Republic"],
  TW: ['Taiwan, Province of China'],
  MD: ['Moldova, Republic of'],
  TZ: ['Tanzania, United Republic of'],
  BO: ['Bolivia, Plurinational State of'],
  VE: ['Venezuela, Bolivarian Republic of'],
  CD: ['Congo, The Democratic Republic of the', 'DR Congo'],
  CG: ['Congo, Republic of the'],
  CI: ["Cote d'Ivoire", 'Ivory Coast'],
  CV: ['Cape Verde'],
  CZ: ['Czech Republic'],
  SZ: ['Swaziland'],
  MK: ['Macedonia', 'Republic of North Macedonia'],
  MM: ['Burma'],
  TL: ['East Timor'],
  NL: ['Holland', 'The Netherlands'],
  AE: ['UAE'],
  VA: ['Vatican City', 'Holy See'],
  PS: ['Palestine, State of'],
  BN: ['Brunei Darussalam'],
  MO: ['Macau'],
  HK: ['Hong Kong SAR China'],
};

// ---- subdivisions ---------------------------------------------------------
//
// A state <select> is as common as a country one, and its options are the
// abbreviation about as often as the name. There is no universal code for a
// subdivision the way there is for a country, so this covers the three places
// where a dropdown is the norm rather than the exception, and everywhere else
// falls back to matching what the user typed against the option text.

const SUBDIVISIONS = {
  US: 'AL:Alabama|AK:Alaska|AZ:Arizona|AR:Arkansas|CA:California|CO:Colorado|CT:Connecticut|DE:Delaware|DC:District of Columbia|FL:Florida|GA:Georgia|HI:Hawaii|ID:Idaho|IL:Illinois|IN:Indiana|IA:Iowa|KS:Kansas|KY:Kentucky|LA:Louisiana|ME:Maine|MD:Maryland|MA:Massachusetts|MI:Michigan|MN:Minnesota|MS:Mississippi|MO:Missouri|MT:Montana|NE:Nebraska|NV:Nevada|NH:New Hampshire|NJ:New Jersey|NM:New Mexico|NY:New York|NC:North Carolina|ND:North Dakota|OH:Ohio|OK:Oklahoma|OR:Oregon|PA:Pennsylvania|RI:Rhode Island|SC:South Carolina|SD:South Dakota|TN:Tennessee|TX:Texas|UT:Utah|VT:Vermont|VA:Virginia|WA:Washington|WV:West Virginia|WI:Wisconsin|WY:Wyoming|AS:American Samoa|GU:Guam|MP:Northern Mariana Islands|PR:Puerto Rico|VI:U.S. Virgin Islands',
  CA: 'AB:Alberta|BC:British Columbia|MB:Manitoba|NB:New Brunswick|NL:Newfoundland and Labrador|NS:Nova Scotia|NT:Northwest Territories|NU:Nunavut|ON:Ontario|PE:Prince Edward Island|QC:Quebec|SK:Saskatchewan|YT:Yukon',
  AU: 'ACT:Australian Capital Territory|NSW:New South Wales|NT:Northern Territory|QLD:Queensland|SA:South Australia|TAS:Tasmania|VIC:Victoria|WA:Western Australia',
};

const SUBDIVISION_PAIRS = new Map(
  Object.entries(SUBDIVISIONS).map(([country, table]) => [
    country,
    table.split('|').map((entry) => {
      const at = entry.indexOf(':');
      return [entry.slice(0, at), entry.slice(at + 1)];
    }),
  ]),
);

// ---- text ------------------------------------------------------------------

/**
 * Fold a country or region name to something two spellings of it agree on.
 *
 * "Côte d’Ivoire", "Cote d'Ivoire" and "COTE D IVOIRE" all become the same
 * string, as do "Antigua & Barbuda" and "Antigua and Barbuda". This is why the
 * alias list above can stay short.
 */
export function foldName(value) {
  return String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // the diacritics NFD just separated out
    .replace(/[\u2018\u2019]/g, "'")
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

const NAME_TO_CODE = new Map();
for (const [code, name] of CODE_TO_NAME) {
  NAME_TO_CODE.set(foldName(name), code);
}
for (const [code, names] of Object.entries(COUNTRY_ALIASES)) {
  for (const name of names) NAME_TO_CODE.set(foldName(name), code);
}

/** The English name for an ISO code, or '' if it is not one. */
export const countryName = (code) => CODE_TO_NAME.get(String(code ?? '').toUpperCase()) ?? '';

/** An ISO code from a code or a name, or '' if it resolves to neither. */
export function countryCode(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  const upper = raw.toUpperCase();
  if (CODE_TO_NAME.has(upper)) return upper;
  return NAME_TO_CODE.get(foldName(raw)) ?? '';
}

/** Every country, name-sorted, for the manager's dropdown. */
export const countryOptions = () =>
  [...CODE_TO_NAME].sort((a, b) => a[1].localeCompare(b[1], 'en'));

// ---- names ----------------------------------------------------------------

/** Full name from the parts, falling back to a `name` an older record kept. */
export function joinName(record) {
  const joined = ['given-name', 'additional-name', 'family-name']
    .map((k) => String(record?.[k] ?? '').trim())
    .filter(Boolean)
    .join(' ');
  return joined || String(record?.name ?? '').trim();
}

/**
 * Guess the parts of a written-out name.
 *
 * Used only when converting a captured or older record that kept a single
 * `name`. Last word is the family name, first is the given name, anything
 * between is additional — wrong for plenty of the world's naming customs, which
 * is exactly why it is a fallback and not the storage model.
 */
export function splitName(full) {
  const parts = String(full ?? '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return {};
  if (parts.length === 1) return { 'given-name': parts[0] };
  return {
    'given-name': parts[0],
    'additional-name': parts.slice(1, -1).join(' ') || undefined,
    'family-name': parts[parts.length - 1],
  };
}

// ---- telephone ------------------------------------------------------------

/**
 * Pull apart a stored phone number, as far as it can honestly be pulled.
 *
 * A country code is unambiguous only when it is written with a leading `+` and
 * something after it to say where it ends: `+441184960000` could be Great
 * Britain on 44 or Bermuda on 441, and nothing in the string settles it. So a
 * separator is required, and a run-together number is simply reported whole.
 *
 * An area code is harder still: the split differs by country and cannot be
 * found in a bare string of digits at all. So only the North American plan —
 * where a national number is always three digits of area code followed by
 * seven — is split any further, and every other number has no area code to
 * offer. A form asking for one gets nothing, which is the correct answer.
 */
export function telParts(tel) {
  const raw = String(tel ?? '').trim();
  if (!raw) return {};

  const out = { tel: raw };
  let national = raw;

  // The lookahead is what demands the separator. Brackets are not consumed:
  // `+1 (415) 555-0132` should keep its `(415)` intact as the national number.
  const withCountry = raw.match(/^\+\s*(\d{1,3})(?=[\s.\-(])[\s.\-]*(.*)$/);
  if (withCountry) {
    out['tel-country-code'] = `+${withCountry[1]}`;
    national = withCountry[2];
  } else if (raw.startsWith('+')) {
    // International, but written with nothing to mark where the country code
    // ends. The number as a whole is still good; every part of it is a guess.
    return out;
  }

  national = national.trim();
  if (!national) return out;
  out['tel-national'] = national;

  const digits = national.replace(/\D/g, '');
  const nanp = !withCountry || withCountry[1] === '1';
  if (nanp && digits.length === 10) {
    out['tel-area-code'] = digits.slice(0, 3);
    out['tel-local'] = digits.slice(3);
    out['tel-local-prefix'] = digits.slice(3, 6);
    out['tel-local-suffix'] = digits.slice(6);
  }
  return out;
}

// ---- answering a form -----------------------------------------------------

const streetLines = (r) =>
  ['address-line1', 'address-line2', 'address-line3']
    .map((k) => String(r?.[k] ?? '').trim())
    .filter(Boolean);

/**
 * Build the value for one token from a record, or '' if the record cannot
 * honestly supply it.
 */
function valueFor(record, token) {
  switch (token) {
    case 'name':
      return joinName(record);
    case 'given-name':
    case 'additional-name':
    case 'family-name': {
      const stored = String(record?.[token] ?? '').trim();
      if (stored) return stored;
      // An older record, or one captured from a single "Full name" box.
      return record?.name ? String(splitName(record.name)[token] ?? '') : '';
    }
    case 'street-address':
      return streetLines(record).join('\n');
    case 'country':
      return countryCode(record?.country);
    case 'country-name':
      return countryName(countryCode(record?.country));
    case 'tel':
    case 'tel-country-code':
    case 'tel-national':
    case 'tel-area-code':
    case 'tel-local':
    case 'tel-local-prefix':
    case 'tel-local-suffix':
      return telParts(record?.tel)[token] ?? '';
    default:
      return String(record?.[token] ?? '').trim();
  }
}

/**
 * Other strings that would be a correct answer for this token.
 *
 * Only ever used to pick an option out of a <select>. A text box gets the
 * primary value and nothing else — the alternatives exist because an option
 * list may be spelled `US`, `United States` or `United States of America` and
 * all three mean the same thing.
 */
function altsFor(record, token) {
  if (token === 'country' || token === 'country-name') {
    const code = countryCode(record?.country);
    if (!code) return [];
    return [code, countryName(code), ...(COUNTRY_ALIASES[code] ?? [])];
  }
  if (token === 'address-level1') {
    const value = String(record?.['address-level1'] ?? '').trim();
    if (!value) return [];
    const pairs = SUBDIVISION_PAIRS.get(countryCode(record?.country));
    if (!pairs) return [];
    const folded = foldName(value);
    const hit = pairs.find(([code, name]) => foldName(code) === folded || foldName(name) === folded);
    return hit ? [hit[0], hit[1]] : [];
  }
  return [];
}

/**
 * Answer exactly what a form asked for.
 *
 * `tokens` is what the page actually has fields for. Anything outside it is not
 * returned at all — not because it would be rejected downstream, but because it
 * should never leave the vault in the first place. A form with a postcode box
 * and nothing else has no business learning a phone number.
 */
export function valuesForTokens(record, tokens) {
  const values = {};
  const alts = {};
  const seen = new Set();

  for (const raw of tokens ?? []) {
    const token = String(raw ?? '');
    if (!ADDRESS_TOKENS.has(token) || seen.has(token)) continue;
    seen.add(token);

    const value = valueFor(record, token);
    if (!value) continue;
    values[token] = value;

    const extra = altsFor(record, token).filter((a) => a && a !== value);
    if (extra.length) alts[token] = extra;
  }
  return { values, alts };
}

// ---- taking one in --------------------------------------------------------

/**
 * Turn what a page had in it into what a record stores.
 *
 * The inverse of the derivation above, and lossy in the places derivation is
 * exact: a single `name` box has to be split, a `street-address` block has to
 * be cut into lines, a country name has to be resolved back to its code.
 */
export function normalizeCaptured(raw, limit = 256) {
  const trim = (v) => String(v ?? '').trim().slice(0, limit);
  const input = raw ?? {};
  const out = {};

  for (const token of STORED_TOKENS) {
    const value = trim(input[token]);
    if (value) out[token] = value;
  }

  // A single full-name box, when the form had no separate parts.
  if (!out['given-name'] && !out['family-name'] && input.name) {
    for (const [k, v] of Object.entries(splitName(trim(input.name)))) {
      if (v) out[k] = v;
    }
  }

  // One street box in place of the numbered lines.
  if (!out['address-line1'] && input['street-address']) {
    const lines = trim(input['street-address']).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines[0]) out['address-line1'] = lines[0];
    if (lines[1]) out['address-line2'] = lines[1];
    if (lines[2]) out['address-line3'] = lines.slice(2).join(', ').slice(0, limit);
  }

  // A country field holding a name, or a separate country-name box.
  const code = countryCode(out.country || trim(input['country-name']));
  if (code) out.country = code;
  else delete out.country;

  // A number split across boxes, when there was no whole one.
  if (!out.tel) {
    const joined = [
      trim(input['tel-country-code']),
      trim(input['tel-national']) ||
        [trim(input['tel-area-code']), trim(input['tel-local']) ||
          trim(input['tel-local-prefix']) + trim(input['tel-local-suffix'])]
          .filter(Boolean)
          .join(' '),
    ]
      .filter(Boolean)
      .join(' ')
      .trim();
    if (joined) out.tel = joined.slice(0, limit);
  }

  return out;
}

/**
 * Is this enough to be worth calling an address?
 *
 * Two structural fields. A lone email box on a newsletter form is not an
 * address, and neither is a name and a phone number on a contact form.
 */
export const isAddressish = (record) =>
  Object.keys(record ?? {}).filter((k) => STRUCTURAL_TOKENS.has(k)).length >= 2;

/** A one-line description, for the menu and the list. */
export const addressSummary = (r) =>
  [r?.['address-line1'], r?.['address-level2'], r?.['postal-code']].filter(Boolean).join(', ');
