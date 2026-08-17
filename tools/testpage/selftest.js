// Drives the extension from inside the page and reports what happened.
//
// A browser started by web-ext cannot be screenshotted from outside and cannot
// be clicked by anything external — but page script and the content script
// share a DOM, so an event dispatched here reaches the content script's own
// listeners. That is enough to open menus and count anchors without a human.
//
// Loaded only with ?selftest. Never part of the extension.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const anchors = () => [...document.querySelectorAll('[data-bencpass="anchor"]')];
const overlay = () => document.getElementById('bencpass-overlay-frame');

/** Which section a marked field sits in, by its heading number. */
function sectionOf(el) {
  const section = el.closest('section');
  return section ? section.querySelector('h2').textContent.trim().split('.')[0] : '?';
}

/**
 * Anchors are absolutely positioned siblings of body, not children of the
 * fields, so they are matched back to a field by position.
 */
function fieldUnder(anchor) {
  const a = anchor.getBoundingClientRect();
  const mid = { x: a.left + a.width / 2, y: a.top + a.height / 2 };
  // Selects included: country and state are dropdowns on a real checkout.
  for (const input of document.querySelectorAll('input, select')) {
    const r = input.getBoundingClientRect();
    if (mid.x >= r.left && mid.x <= r.right && mid.y >= r.top && mid.y <= r.bottom) return input;
  }
  return null;
}

/** Which sections currently have an anchor, recomputed from the live DOM. */
const anchoredSections = () =>
  anchors().map((a) => sectionOf(fieldUnder(a) ?? document.body));

async function run() {
  const report = { checks: [], anchors: [], errors: [] };
  const check = (name, pass, detail = '') => report.checks.push({ name, pass, detail });

  // Give the content script time to scan, classify and place anchors.
  await sleep(3000);

  for (const a of anchors()) {
    const field = fieldUnder(a);
    report.anchors.push({
      section: field ? sectionOf(field) : '?',
      field: field ? field.name || field.id : '(unmatched)',
      title: a.title,
      fill: a.querySelector('path')?.getAttribute('style') ?? '',
    });
  }

  const sections = new Set(report.anchors.map((a) => a.section));
  check('anchors on more than one form', sections.size > 1, [...sections].join(','));
  check('form 1 anchored', sections.has('1'));
  check('form 4 anchored', sections.has('4'));
  check('form 8 anchored (addresses)', sections.has('8'));
  // The username half of a two-step sign-in. Filling the username alone is the
  // whole point there, and a rule aimed at sign-up forms had excluded it.
  check('form 5 anchored (two-step username step)', sections.has('5'));

  // The search box and the honeypot must never be marked.
  check(
    'search box not anchored',
    !report.anchors.some((a) => a.field === 'q'),
    report.anchors.map((a) => a.field).join(' '),
  );
  check(
    'honeypot not anchored',
    !report.anchors.some((a) => String(a.field).endsWith('_hp')),
  );

  // A sign-up must not offer to fill the username from stored logins.
  check(
    'sign-up username not anchored',
    !report.anchors.some((a) => a.section === '4' && a.field === 'email'),
  );

  // Address anchors are drawn in the darker of P. Gon's two colours.
  const address = report.anchors.filter((a) => a.section === '8');
  check(
    'address anchors are visually distinct',
    address.length > 0 && address.every((a) => a.fill.includes('#254d75')),
    address.map((a) => a.fill).join(' | '),
  );

  // Locked, so every visor should be red.
  check(
    'visor red while locked',
    anchors().every((a) => a.querySelector('rect:last-of-type')?.getAttribute('style')?.includes('#d84a3a')),
  );

  // Clicking an anchor must open the menu, and it must stay open.
  const first = anchors()[0];
  if (first) {
    first.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    await sleep(1200);
    check('menu opens on click', Boolean(overlay()));
    await sleep(2000);
    check('menu still open two seconds later', Boolean(overlay()));
  } else {
    check('menu opens on click', false, 'no anchors to click');
  }

  // Late-rendered forms have to be noticed.
  document.getElementById('late').click();
  await sleep(2000);
  check('late form gets an anchor', anchoredSections().includes('7'));

  // The checkout with dropdowns. Country is a <select> on nearly every real
  // one, so an address that cannot mark one cannot fill one.
  const checkout = report.anchors.filter((a) => a.section === '10');
  check('form 10 anchored (checkout)', checkout.length > 0);
  check(
    'the country dropdown is anchored',
    checkout.some((a) => a.field === 'country'),
    checkout.map((a) => a.field).join(' '),
  );
  check(
    'the state dropdown is anchored',
    checkout.some((a) => a.field === 'c8'),
  );
  check(
    'the quantity dropdown is not anchored',
    !report.anchors.some((a) => a.field === 'qty'),
  );

  // The same two fields as plain text boxes, on the form that sets no
  // autocomplete attributes. A country dropdown and a country text box take
  // different values — the code and the name — so both paths need covering.
  const plain = report.anchors.filter((a) => a.section === '8');
  check(
    'the text-only form anchors country and phone',
    ['country', 'phone'].every((n) => plain.some((a) => a.field === n)),
    plain.map((a) => a.field).join(' '),
  );

  // Scrolling must not change what the extension thinks a form is.
  //
  // It used to. Visibility was measured against the viewport, and visibility
  // feeds classification: scroll a checkout until its street, city and postcode
  // boxes are above the fold, and the group has too few structural address
  // fields left to still count as an address — so the next rescan dropped every
  // anchor on it, while the click handlers already bound to the fields carried
  // on opening the menu. Anchors gone, dropdown still working.
  const before = anchoredSections().filter((s) => s === '10').length;
  window.scrollTo(0, document.documentElement.scrollHeight);
  document.body.appendChild(document.createElement('div')); // provoke a rescan
  await sleep(2500);
  const after = anchoredSections().filter((s) => s === '10').length;
  check(
    'anchors survive scrolling the form out of view',
    after > 0 && after >= before,
    `${before} before, ${after} after`,
  );
  window.scrollTo(0, 0);
  await sleep(1000);

  // Nothing may have been written into any field without a person choosing it.
  const filled = [...document.querySelectorAll('input')].filter((i) => i.value);
  check('nothing filled without a choice', filled.length === 0, filled.map((i) => i.name).join(' '));
  const chosen = [...document.querySelectorAll('select')].filter(
    (s) => s.name !== 'qty' && s.value,
  );
  check('no dropdown chosen without a choice', chosen.length === 0, chosen.map((s) => s.id).join(' '));

  await fetch('/__result', { method: 'POST', body: JSON.stringify(report, null, 2) });
  document.title = 'selftest done';
}

window.addEventListener('error', (e) => {
  fetch('/__result', { method: 'POST', body: JSON.stringify({ fatal: String(e.message) }) });
});

run();
