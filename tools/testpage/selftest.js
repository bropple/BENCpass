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
  for (const input of document.querySelectorAll('input')) {
    const r = input.getBoundingClientRect();
    if (mid.x >= r.left && mid.x <= r.right && mid.y >= r.top && mid.y <= r.bottom) return input;
  }
  return null;
}

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
  check(
    'late form gets an anchor',
    anchors().some((a) => sectionOf(fieldUnder(a) ?? document.body) === '7'),
  );

  // Nothing may have been written into any field without a person choosing it.
  const filled = [...document.querySelectorAll('input')].filter((i) => i.value);
  check('nothing filled without a choice', filled.length === 0, filled.map((i) => i.name).join(' '));

  await fetch('/__result', { method: 'POST', body: JSON.stringify(report, null, 2) });
  document.title = 'selftest done';
}

window.addEventListener('error', (e) => {
  fetch('/__result', { method: 'POST', body: JSON.stringify({ fatal: String(e.message) }) });
});

run();
