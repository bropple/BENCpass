// The background half of the probe. It keeps two objects a page hands over —
// one by reference, one rebuilt here from a primitive — and reads them both
// after the page is gone, from the same place BENCpass first crashed:
// tabs.onRemoved, which is where paintBadge reads vault.locked.
let byReference = null;
let builtHere = null;

window.probe = {
  keepReference(obj) {
    byReference = obj; // the shape background.js's setVault had — the bug
  },
  buildFromString(json) {
    builtHere = JSON.parse(json); // the shape handleSetup has — the fix
  },
};

const read = (o) => {
  try {
    return { ok: true, locked: o.locked };
  } catch (err) {
    return { ok: false, error: err.message };
  }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

browser.tabs.onRemoved.addListener(async () => {
  // The nuke is not synchronous with the close: Firefox tears the page's
  // compartment down on its own schedule, sometimes before this listener runs
  // and sometimes seconds after. Deadness never reverses, so poll until the
  // reference dies or patience runs out — a single read here reported the
  // page's object still alive on one run and dead on the next.
  let waited = 0;
  while (read(byReference).ok && waited < 15000) {
    await sleep(500);
    waited += 500;
  }
  const report = {
    waitedMs: waited,
    byReference: read(byReference),
    builtHere: read(builtHere),
  };
  await fetch('http://127.0.0.1:8736/__result', {
    method: 'POST',
    body: JSON.stringify(report),
  }).catch(() => {});
});

browser.tabs.create({ url: browser.runtime.getURL('page.html') });
