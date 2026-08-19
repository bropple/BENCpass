// Behaviour for the awkward cases on the form-shapes page. Not part of the
// extension — this is the thing being tested against.

// Section 6: an input that fights a naive fill, the way a framework-controlled
// one does. React keeps its own record of the value on the node and reverts
// anything it did not set itself; assigning `.value` directly is silently undone.
// Going through the prototype's own setter is what makes a fill stick, so this
// reproduces the failure without pulling in React.
for (const id of ['f1', 'f2']) {
  const el = document.getElementById(id);
  let framework = '';
  const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

  Object.defineProperty(el, 'value', {
    get: () => framework,
    set(v) {
      // A direct assignment is ignored, exactly as a controlled input ignores one.
      framework = framework;
      native.set.call(el, framework);
    },
    configurable: true,
  });

  // Only a real input event, which is what the native setter path produces,
  // moves the framework's own state along.
  el.addEventListener('input', () => {
    framework = native.get.call(el);
  });
}

// Section 10: the two dropdowns, filled in properly rather than with a token
// three options each — you cannot tell whether an address fills a state field
// if the only states offered are the three you tested with.
//
// Both are deliberately awkward, because a convenient list proves nothing:
//
//   states     value is the postal abbreviation, text is the full name. An
//              address stored as "California" has to match an option worth
//              "CA", and one stored as "CA" has to match its text.
//   countries  value is the NAME, not the ISO code, which is the case a naive
//              implementation gets wrong — and the names are spelled the way
//              real option lists spell them, including the ones CLDR disagrees
//              with (Turkey, Hong Kong, Czech Republic) and the ones with
//              punctuation that never survives a copy and paste.
const US_STATES =
  'AL:Alabama,AK:Alaska,AZ:Arizona,AR:Arkansas,CA:California,CO:Colorado,CT:Connecticut,' +
  'DE:Delaware,DC:District of Columbia,FL:Florida,GA:Georgia,HI:Hawaii,ID:Idaho,IL:Illinois,' +
  'IN:Indiana,IA:Iowa,KS:Kansas,KY:Kentucky,LA:Louisiana,ME:Maine,MD:Maryland,' +
  'MA:Massachusetts,MI:Michigan,MN:Minnesota,MS:Mississippi,MO:Missouri,MT:Montana,' +
  'NE:Nebraska,NV:Nevada,NH:New Hampshire,NJ:New Jersey,NM:New Mexico,NY:New York,' +
  'NC:North Carolina,ND:North Dakota,OH:Ohio,OK:Oklahoma,OR:Oregon,PA:Pennsylvania,' +
  'RI:Rhode Island,SC:South Carolina,SD:South Dakota,TN:Tennessee,TX:Texas,UT:Utah,' +
  'VT:Vermont,VA:Virginia,WA:Washington,WV:West Virginia,WI:Wisconsin,WY:Wyoming';

const COUNTRIES = [
  'Australia', 'Austria', 'Belgium', 'Brazil', 'Canada', 'China', 'Czech Republic', 'Denmark',
  'Finland', 'France', 'Germany', 'Greece', 'Hong Kong', 'Hungary', 'India', 'Ireland', 'Israel',
  'Italy', 'Japan', 'Korea, Republic of', 'Mexico', 'Netherlands', 'New Zealand', 'Norway',
  'Poland', 'Portugal', 'Singapore', 'South Africa', 'Spain', 'Sweden', 'Switzerland', 'Turkey',
  'United Arab Emirates', 'United Kingdom', 'United States', 'Viet Nam',
  // The ones with punctuation. A page rarely reproduces CLDR's curly
  // apostrophe or its ampersand, and an address stored from one of these has
  // to come back out matching the other.
  "Cote d'Ivoire", 'Antigua and Barbuda', 'Aland Islands', 'Sao Tome and Principe',
];

function fillSelect(id, entries) {
  const select = document.getElementById(id);
  if (!select) return;
  for (const [value, text] of entries) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = text;
    select.append(option);
  }
}

fillSelect(
  'c8',
  US_STATES.split(',').map((entry) => {
    const at = entry.indexOf(':');
    return [entry.slice(0, at), entry.slice(at + 1)];
  }),
);
fillSelect(
  'c10',
  COUNTRIES.sort((a, b) => a.localeCompare(b, 'en')).map((name) => [name, name]),
);

// Section 5: the second half of a two-step login. The first page collects the
// username and the password box only exists after it, which is the shape that
// defeats a manager expecting both at once.
document.getElementById('e-next').addEventListener('click', () => {
  const slot = document.getElementById('step-two');
  if (slot.querySelector('form')) return;
  document.getElementById('step-one').hidden = true;

  // Built node by node rather than with innerHTML. This is a test page and the
  // only thing it can attack is itself — but a password manager's repository is
  // a poor place to keep a worked example of interpolating a form field into
  // markup, and the extension itself is held to exactly this rule.
  const form = document.createElement('form');

  const p = document.createElement('p');
  p.append(document.createTextNode('Enter password for '));
  const who = document.createElement('strong');
  who.textContent = document.getElementById('e1').value || 'that account';
  p.append(who);
  form.append(p);

  const label = document.createElement('label');
  label.htmlFor = 'e2';
  label.textContent = 'Password';
  form.append(label);

  const input = document.createElement('input');
  input.id = 'e2';
  input.name = 'passwd';
  input.type = 'password';
  input.autocomplete = 'current-password';
  form.append(input);

  const button = document.createElement('button');
  button.textContent = 'Sign in';
  form.append(button);
  slot.append(form);
});

// Section 7: a login form that appears long after load.
document.getElementById('late').addEventListener('click', () => {
  const slot = document.getElementById('late-slot');
  if (slot.querySelector('form')) return;

  const form = document.createElement('form');
  form.innerHTML = `
    <label for="h1">Username</label>
    <input id="h1" name="username" autocomplete="username">
    <label for="h2">Password</label>
    <input id="h2" name="password" type="password" autocomplete="current-password">
    <button>Sign in</button>`;
  slot.append(form);
});

// Nothing here submits anywhere. Capture is exercised by the submit event, and
// a real navigation would just lose the page.
document.addEventListener('submit', (e) => {
  e.preventDefault();
  const note = document.createElement('p');
  note.className = 'expect';
  note.textContent = 'Submitted — BENCpass should now offer to save (badge on the toolbar icon).';
  e.target.append(note);
});

// Self-test mode, for driving the extension without a person. tools/selftest.sh
if (location.search.includes('selftest')) {
  const s = document.createElement('script');
  s.src = 'selftest.js';
  s.type = 'module';
  document.body.append(s);
}
