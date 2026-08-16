// The content script. Runs inside every page, and is the least trusted part of
// this extension — it shares a process and a DOM with whatever the page is.
//
// It is therefore kept deliberately stupid. It reports what fields exist, it
// draws an anchor, and it writes a value it is handed. Every judgement — which
// field is the username, whether this origin may receive a credential at all —
// happens in the background page, which can check the frame's real identity
// with the browser instead of asking the frame.
//
// A classic script, not a module: MV2 content scripts cannot be modules. That
// is convenient here, because it makes importing the crypto core impossible by
// construction.

(() => {
  'use strict';

  const MSG = {
    DESCRIBE: 'describe',
    CANDIDATES: 'candidates',
    CAPTURE: 'capture',
    FILL: 'fill',
    DISMISS: 'dismiss',
  };

  const MARK = 'data-bencpass';
  const OVERLAY_ID = 'bencpass-overlay-frame';

  let fields = []; // live elements, index-aligned with the descriptors sent
  let roles = null; // what the background said they are
  let anchorEl = null;
  let rescanTimer = null;

  // ---- finding fields ------------------------------------------------------

  /** Collect inputs, descending into open shadow roots. */
  function collect(root, out) {
    const nodes = root.querySelectorAll('input, textarea');
    for (const el of nodes) out.push(el);
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) collect(el.shadowRoot, out);
    }
    return out;
  }

  function isVisible(el) {
    if (!el.getClientRects().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (Number(style.opacity) === 0) return false;
    // A 1x1 input parked off-screen is a honeypot, not a field a person fills.
    const r = el.getBoundingClientRect();
    return r.width > 8 && r.height > 8;
  }

  function labelFor(el) {
    if (el.labels && el.labels.length) return el.labels[0].textContent ?? '';
    const wrapper = el.closest('label');
    if (wrapper) return wrapper.textContent ?? '';
    const id = el.getAttribute('id');
    if (id) {
      const lab = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (lab) return lab.textContent ?? '';
    }
    return '';
  }

  function describe(el, index) {
    return {
      index,
      tag: el.tagName.toLowerCase(),
      type: (el.getAttribute('type') ?? (el.tagName === 'TEXTAREA' ? 'textarea' : 'text')).toLowerCase(),
      name: el.getAttribute('name') ?? '',
      id: el.getAttribute('id') ?? '',
      autocomplete: el.getAttribute('autocomplete') ?? '',
      placeholder: el.getAttribute('placeholder') ?? '',
      ariaLabel: el.getAttribute('aria-label') ?? '',
      label: labelFor(el).trim().slice(0, 120),
      disabled: el.disabled === true,
      readOnly: el.readOnly === true,
      visible: isVisible(el),
    };
  }

  async function scan() {
    fields = collect(document, []);
    if (!fields.length) {
      roles = null;
      return;
    }
    const descriptors = fields.slice(0, 300).map(describe);
    try {
      roles = await browser.runtime.sendMessage({ type: MSG.DESCRIBE, fields: descriptors });
    } catch {
      roles = null; // background asleep or extension reloading
    }
    placeAnchors();
  }

  const rescan = () => {
    clearTimeout(rescanTimer);
    rescanTimer = setTimeout(scan, 300);
  };

  // ---- the anchor ----------------------------------------------------------
  //
  // A small mark on the fields BENCpass can help with. Clicking it is the
  // explicit action that opens the menu. Nothing is offered, and certainly
  // nothing is filled, without one — a page that renders a hidden login form
  // and waits would otherwise harvest a credential on load.

  function placeAnchors() {
    document.querySelectorAll(`[${MARK}]`).forEach((el) => el.remove());
    if (!roles) return;

    const targets = new Set(
      [roles.login?.username, roles.login?.password, roles.login?.newPassword]
        .filter((i) => i !== null && i !== undefined)
        .map((i) => fields[i])
        .filter(Boolean),
    );
    for (const el of targets) attachAnchor(el);
  }

  function attachAnchor(el) {
    const dot = document.createElement('div');
    dot.setAttribute(MARK, 'anchor');
    // `all: initial` first, so the page's own stylesheet cannot restyle this
    // into something invisible or enormous.
    dot.style.cssText =
      'all: initial; position: absolute; width: 16px; height: 16px; cursor: pointer;' +
      'z-index: 2147483646; background: #3d7dbf; border: 1px solid #254d75;' +
      'border-radius: 3px;';
    dot.title = 'BENCpass';
    dot.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(el);
    });

    document.body.appendChild(dot);
    position(dot, el);
  }

  function position(node, el) {
    const r = el.getBoundingClientRect();
    node.style.top = `${window.scrollY + r.top + (r.height - 16) / 2}px`;
    node.style.left = `${window.scrollX + r.right - 22}px`;
  }

  // ---- the menu ------------------------------------------------------------
  //
  // An iframe pointing at an extension page. It has to be an iframe: anything
  // rendered into the page's own DOM can be read and rewritten by the page,
  // which would hand the list of usernames to whatever is running there and let
  // it fake a click on an entry.

  async function openMenu(el, kind = 'login') {
    closeMenu();
    let reply;
    try {
      reply = await browser.runtime.sendMessage({ type: MSG.CANDIDATES, kind });
    } catch {
      return;
    }
    if (!reply || reply.locked || !reply.sessionId || !reply.candidates.length) return;

    anchorEl = el;
    const frame = document.createElement('iframe');
    frame.id = OVERLAY_ID;
    frame.setAttribute(MARK, 'overlay');
    // The session id does NOT go in the URL. This element lives in the page's
    // own DOM, so page script can read `frame.src` — which would hand it both
    // the extension's UUID and a live session id, and overlay.html is
    // web-accessible, so it could then run its own privileged copy against that
    // session and clickjack a fill out of it. The id is posted to the frame
    // after load instead, where the page cannot reach it: a cross-origin
    // contentWindow cannot be listened to, and the targetOrigin below means a
    // swapped document receives nothing.
    frame.src = browser.runtime.getURL('ext/overlay.html');
    frame.style.cssText =
      'all: initial; position: absolute; width: 280px; height: ' +
      `${Math.min(260, 44 + reply.candidates.length * 46)}px;` +
      'z-index: 2147483647; border: 1px solid #1e2c3d; border-radius: 3px;' +
      'box-shadow: 0 4px 16px rgba(0,0,0,0.5); background: #0c1420; color-scheme: dark;';

    const extensionOrigin = new URL(browser.runtime.getURL('')).origin;
    frame.addEventListener(
      'load',
      () => {
        frame.contentWindow?.postMessage(
          { bencpass: 'session', sessionId: reply.sessionId },
          extensionOrigin,
        );
      },
      { once: true },
    );

    document.body.appendChild(frame);
    const r = el.getBoundingClientRect();
    frame.style.top = `${window.scrollY + r.bottom + 4}px`;
    frame.style.left = `${window.scrollX + Math.max(4, r.left)}px`;

    setTimeout(() => document.addEventListener('mousedown', onOutside, true), 0);
  }

  function onOutside(e) {
    if (e.target?.getAttribute?.(MARK)) return;
    closeMenu();
  }

  function closeMenu() {
    document.getElementById(OVERLAY_ID)?.remove();
    document.removeEventListener('mousedown', onOutside, true);
  }

  // ---- filling -------------------------------------------------------------

  /**
   * Set a value in a way frameworks notice.
   *
   * React tracks the previous value on the DOM node and ignores an `input`
   * event whose value it believes it already knows, so assigning `el.value`
   * directly leaves the field looking filled and the framework's state empty —
   * the form then submits nothing. Going through the prototype's own setter
   * bypasses React's override and updates its tracker.
   */
  function setValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(proto.prototype, 'value')?.set;
    el.focus();
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  const at = (i) => (i === null || i === undefined ? null : fields[i] ?? null);

  function fill(kind, values) {
    if (kind === 'address') return fillAddress(values);

    const login = roles?.login ?? {};
    if (kind === 'generated') {
      const target = at(login.newPassword) ?? at(login.password);
      if (target) setValue(target, values.password);
      return;
    }

    const user = at(login.username);
    const pass = at(login.password) ?? at(login.newPassword);
    if (user && values.username) setValue(user, values.username);
    if (pass && values.password) setValue(pass, values.password);
    // A username-only step has nowhere to put the password, and must not be
    // given one to hold until the next page.
    if (!pass && user) lastSubmitted.username = values.username ?? '';
  }

  function fillAddress(values) {
    for (const { index, token } of roles?.address ?? []) {
      const el = at(index);
      if (!el) continue;
      let value = values[token];
      // Some forms take one box where the record has two lines.
      if (token === 'street-address') {
        value = [values['address-line1'], values['address-line2']].filter(Boolean).join('\n');
      }
      if (value) setValue(el, value);
    }
  }

  // ---- capture -------------------------------------------------------------

  const lastSubmitted = { username: '', password: '' };

  function remember() {
    const login = roles?.login ?? {};
    const user = at(login.username);
    const pass = at(login.password) ?? at(login.newPassword);
    if (user?.value) lastSubmitted.username = user.value;
    if (pass?.value) lastSubmitted.password = pass.value;
  }

  function offerCapture() {
    if (!lastSubmitted.password) return;
    browser.runtime
      .sendMessage({
        type: MSG.CAPTURE,
        username: lastSubmitted.username,
        password: lastSubmitted.password,
      })
      .catch(() => {});
    lastSubmitted.username = '';
    lastSubmitted.password = '';
  }

  // A submit event is the clean signal and is often never fired: a great many
  // sign-in forms are a div and a click handler that calls fetch(). So the
  // values are remembered on every input, and the offer is made on whichever of
  // these happens first.
  document.addEventListener('input', remember, true);
  document.addEventListener('submit', () => { remember(); offerCapture(); }, true);
  window.addEventListener('pagehide', offerCapture, { capture: true });

  // A single-page app navigating without unloading, which is the case both of
  // the above miss.
  let lastUrl = location.href;
  setInterval(() => {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    offerCapture();
    rescan();
  }, 1000);

  // ---- messages from the background ---------------------------------------

  browser.runtime.onMessage.addListener((msg) => {
    if (msg?.type === MSG.FILL) {
      fill(msg.kind, msg.values ?? {});
      closeMenu();
      return Promise.resolve({ ok: true });
    }
    if (msg?.type === MSG.DISMISS) {
      closeMenu();
      if (msg.open) {
        const login = roles?.login ?? {};
        const target = at(login.password) ?? at(login.username) ?? at(login.newPassword);
        if (target) openMenu(target);
      }
      return Promise.resolve({ ok: true });
    }
  });

  // ---- start ---------------------------------------------------------------

  if (window.top !== window.self && !document.querySelector('input[type=password]')) {
    // Most third-party frames on a page are advertising. Scanning them all is
    // wasted work; a frame that grows a password field later is caught by the
    // observer below.
  }

  new MutationObserver(rescan).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
  window.addEventListener('scroll', () => placeAnchors(), { passive: true });
  window.addEventListener('resize', () => placeAnchors(), { passive: true });

  scan();
})();
