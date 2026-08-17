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
    FILL_TARGET: 'fill-target',
    DISMISS: 'dismiss',
    LOCKSTATE: 'lockstate',
  };

  const MARK = 'data-bencpass';
  const BOUND = 'data-bencpass-bound';

  // Anchors are swept and rebuilt constantly; the overlay and the page's own
  // fields must never be caught by that sweep. So the selector names the value
  // rather than the attribute — a bare [data-bencpass] also matched the overlay
  // iframe, which is why the menu deleted itself about a third of a second
  // after opening, and would have matched the page's inputs too and removed
  // them from the document.
  const ANCHOR_SEL = `[${MARK}="anchor"]`;
  const OVERLAY_ID = 'bencpass-overlay-frame';

  /** Anything this extension put in the page. */
  const isOurs = (node) =>
    Boolean(node && node.nodeType === 1 && node.closest(`[${MARK}], [${BOUND}]`));

  let fields = []; // live elements, index-aligned with the descriptors sent
  let groups = []; // per-form roles, as the background classified them
  let formIds = new WeakMap();
  let formSeq = 0; // WeakMap has no .size — see groupOf
  let locked = true;
  let activeGroup = null; // the form the open menu belongs to
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

  /**
   * Which form an input belongs to; one shared bucket for those with none.
   *
   * The counter is explicit because WeakMap has no `.size` — it cannot have
   * one, since it cannot enumerate its own keys. Reading it gave `undefined`,
   * so every form was numbered `undefined + 1` = NaN, and Map treats NaN as
   * equal to NaN, so all of them landed in one group. The result was
   * indistinguishable from the whole-document classification this replaced,
   * which is why nothing appeared to change.
   */
  function groupOf(el) {
    const form = el.form ?? el.closest('form');
    if (!form) return 0;
    if (!formIds.has(form)) formIds.set(form, ++formSeq);
    return formIds.get(form);
  }

  function describe(el, index) {
    return {
      index,
      group: groupOf(el),
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
      groups = [];
      return;
    }
    formIds = new WeakMap();
    formSeq = 0;
    const descriptors = fields.slice(0, 300).map(describe);
    try {
      const reply = await browser.runtime.sendMessage({
        type: MSG.DESCRIBE,
        fields: descriptors,
      });
      groups = reply?.groups ?? [];
      locked = reply?.locked !== false;
    } catch {
      groups = []; // background asleep or extension reloading
    }
    placeAnchors();
  }

  /** The roles for whichever form an element sits in. */
  function groupFor(el) {
    const index = fields.indexOf(el);
    if (index < 0) return null;
    return (
      groups.find(
        (g) =>
          [g.login.username, g.login.password, g.login.newPassword, g.login.otp].includes(index) ||
          (g.address ?? []).some((a) => a.index === index),
      ) ?? null
    );
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
    document.querySelectorAll(ANCHOR_SEL).forEach((el) => el.remove());

    // Every form on the page, not just the first. Treating the document as one
    // form left every login below the first one unmarked.
    const targets = new Map(); // element -> which menu it opens
    for (const g of groups) {
      // Only when there is a current-password box to fill. In a sign-up group
      // the username anchor offered the stored pool, and picking an entry wrote
      // its password into the "choose a password" field — the exact thing the
      // sign-up menu exists to prevent.
      if (g.login.password !== null && g.login.password !== undefined) {
        for (const i of [g.login.username, g.login.password]) {
          if (i === null || i === undefined) continue;
          const el = fields[i];
          if (el) targets.set(el, 'login');
        }
      }
      // A box asking the user to choose a new password gets its own menu, which
      // offers to generate one and nothing else. Offering the existing pool
      // there invites reuse at the exact moment a fresh password is free.
      const fresh = fields[g.login.newPassword];
      if (fresh) targets.set(fresh, 'signup');
      // Address fields get an anchor too. Without one there was no way to ask
      // for an address at all — the menu existed and nothing ever opened it.
      for (const { index } of g.address ?? []) {
        const el = fields[index];
        if (el && !targets.has(el)) targets.set(el, 'address');
      }
    }
    for (const [el, kind] of targets) attachAnchor(el, kind);
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';

  /**
   * P. Gon, drawn rather than loaded.
   *
   * An <img> would need the icon in web_accessible_resources, which widens what
   * a page can fingerprint the extension by. The shapes carry inline styles
   * because the wrapper's `all: initial` resets `fill`, and fill inherits.
   */
  /**
   * P. Gon, drawn rather than loaded.
   *
   * Addresses get the darker of his two canonical colours — his own edge tone
   * rather than his fill — so a login anchor and an address anchor are not the
   * same mark. Same character, quieter role, no new colour introduced.
   */
  function gonMark(isLocked, kind) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 200 200');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');

    const body = document.createElementNS(SVG_NS, 'path');
    body.setAttribute('d', 'M 100,16 L 179.89,74.04 L 149.37,167.96 L 50.63,167.96 L 20.11,74.04 Z');
    body.setAttribute(
      'style',
      kind === 'address'
        ? 'fill:#254d75;stroke:#3d7dbf;stroke-width:8'
        : 'fill:#3d7dbf;stroke:#254d75;stroke-width:8',
    );

    const visor = document.createElementNS(SVG_NS, 'rect');
    visor.setAttribute('x', '53.8');
    visor.setAttribute('y', '95.8');
    visor.setAttribute('width', '92.4');
    visor.setAttribute('height', '28.56');
    visor.setAttribute('style', 'fill:#9a9d94');

    const stripe = document.createElementNS(SVG_NS, 'rect');
    stripe.setAttribute('x', '70.6');
    stripe.setAttribute('y', '103.36');
    stripe.setAttribute('width', '58.8');
    stripe.setAttribute('height', '13.44');
    // The visor is the lock indicator, the same as on the gate: red locked,
    // green open.
    stripe.setAttribute('style', `fill:${isLocked ? '#d84a3a' : '#78b946'}`);

    svg.append(body, visor, stripe);
    return svg;
  }

  function attachAnchor(el, kind = 'login') {
    const dot = document.createElement('div');
    dot.setAttribute(MARK, 'anchor');
    // `all: initial` first, so the page's own stylesheet cannot restyle this
    // into something invisible or enormous.
    dot.style.cssText =
      'all: initial; position: absolute; width: 18px; height: 18px; cursor: pointer;' +
      'z-index: 2147483646; line-height: 0;';
    dot.title =
      kind === 'address'
        ? 'BENCpass — addresses'
        : kind === 'signup'
          ? 'BENCpass — generate a password'
          : 'BENCpass';
    dot.append(gonMark(locked, kind));

    dot.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(el, kind);
    });

    // Clicking the field opens the menu too, the way Firefox's own login
    // autocomplete does — the anchor alone is a small target and not an obvious
    // one. Still an explicit act by the user; nothing opens or fills on its own.
    if (!el.hasAttribute(BOUND)) {
      el.setAttribute(BOUND, '1');
      el.addEventListener('click', () => {
        if (!document.getElementById(OVERLAY_ID)) openMenu(el, kind);
      });
    }

    document.body.appendChild(dot);
    position(dot, el);
  }

  function position(node, el) {
    const r = el.getBoundingClientRect();
    node.style.top = `${window.scrollY + r.top + (r.height - 18) / 2}px`;
    node.style.left = `${window.scrollX + r.right - 24}px`;
  }

  // ---- the menu ------------------------------------------------------------
  //
  // An iframe pointing at an extension page. It has to be an iframe: anything
  // rendered into the page's own DOM can be read and rewritten by the page,
  // which would hand the list of usernames to whatever is running there and let
  // it fake a click on an entry.

  async function openMenu(el, kind = 'login') {
    closeMenu();
    activeGroup = groupFor(el);
    let reply;
    try {
      reply = await browser.runtime.sendMessage({ type: MSG.CANDIDATES, kind });
    } catch {
      return;
    }
    // A locked vault returns a session with a single placeholder candidate, so
    // the menu can offer to unlock. Bailing on reply.locked meant clicking a
    // field while locked did nothing at all, which is the state most in need of
    // an explanation.
    if (!reply || !reply.sessionId || !reply.candidates.length) return;

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
    // Match the field's width the way a native autocomplete panel does, with a
    // floor so a narrow box does not produce an unreadable menu.
    const box = el.getBoundingClientRect();
    frame.style.cssText =
      `all: initial; position: absolute; width: ${Math.max(240, Math.round(box.width))}px;` +
      `height: ${Math.min(260, 40 + reply.candidates.length * 46)}px;` +
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
    frame.style.top = `${window.scrollY + box.bottom + 2}px`;
    frame.style.left = `${window.scrollX + Math.max(4, box.left)}px`;

    setTimeout(() => document.addEventListener('mousedown', onOutside, true), 0);
  }

  function onOutside(e) {
    // A mousedown inside the iframe never reaches this document, so this only
    // sees clicks on the page — but the anchor and the field the menu belongs
    // to are ours, and clicking either must not dismiss it.
    if (isOurs(e.target)) return;
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

    // The form the menu was opened from, not whichever one happens to be first.
    const login = activeGroup?.login ?? groups[0]?.login ?? {};
    if (kind === 'generated') {
      const target = at(login.newPassword) ?? at(login.password);
      if (target) setValue(target, values.password);
      // And the confirmation box, or the form rejects it and the generator has
      // saved nobody anything.
      const confirm = at(login.confirmPassword);
      if (confirm && confirm !== target) setValue(confirm, values.password);
      return;
    }

    const user = at(login.username);
    // Never newPassword. A stored password belongs in a box asking for the
    // current one, never in one asking the user to choose a new one.
    const pass = at(login.password);
    if (user && values.username) setValue(user, values.username);
    if (pass && values.password) setValue(pass, values.password);
    // A username-only step has nowhere to put the password, and must not be
    // given one to hold until the next page.
    if (!pass && user) lastSubmitted.username = values.username ?? '';
  }

  function fillAddress(values) {
    const address = activeGroup?.address ?? groups.flatMap((g) => g.address);
    for (const { index, token } of address) {
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

  const lastSubmitted = { username: '', password: '', address: null };

  function remember() {
    const login = activeGroup?.login ?? groups[0]?.login ?? {};
    const user = at(login.username);
    const pass = at(login.password) ?? at(login.newPassword);
    if (user?.value) lastSubmitted.username = user.value;
    if (pass?.value) lastSubmitted.password = pass.value;

    // Addresses are worth keeping too. Typed once into a checkout, they are
    // otherwise typed again at the next one.
    const address = {};
    for (const g of groups) {
      for (const { index, token } of g.address ?? []) {
        const el = at(index);
        if (el?.value?.trim()) address[token] = el.value.trim();
      }
    }
    // Two fields is the floor for calling it an address; a lone email box on a
    // newsletter form is not one.
    if (Object.keys(address).length >= 2) lastSubmitted.address = address;
  }

  function offerCapture() {
    if (lastSubmitted.password) {
      browser.runtime
        .sendMessage({
          type: MSG.CAPTURE,
          username: lastSubmitted.username,
          password: lastSubmitted.password,
        })
        .catch(() => {});
    }

    if (lastSubmitted.address) {
      browser.runtime
        .sendMessage({ type: MSG.CAPTURE, kind: 'address', address: lastSubmitted.address })
        .catch(() => {});
    }

    lastSubmitted.username = '';
    lastSubmitted.password = '';
    lastSubmitted.address = null;
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
    if (msg?.type === MSG.FILL_TARGET) {
      // getTargetElement resolves the element the context menu was opened on,
      // which is not necessarily the focused one — right-clicking does not
      // always move focus, and guessing from document.activeElement fills the
      // wrong box on a form with several.
      const el = browser.menus?.getTargetElement?.(msg.targetElementId);
      if (el) setValue(el, msg.values?.password ?? '');
      return Promise.resolve({ ok: Boolean(el) });
    }
    if (msg?.type === MSG.LOCKSTATE) {
      locked = Boolean(msg.locked);
      closeMenu();
      placeAnchors();
      return Promise.resolve({ ok: true });
    }
    if (msg?.type === MSG.DISMISS) {
      closeMenu();
      if (msg.open) {
        const login = groups[0]?.login ?? {};
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

  // Ignore the extension's own additions and removals. Without this, appending
  // an anchor triggers a rescan, which removes and re-adds every anchor, which
  // triggers another — a loop that also took the open menu with it each time.
  new MutationObserver((records) => {
    for (const record of records) {
      const touched = [...record.addedNodes, ...record.removedNodes];
      if (touched.length && touched.every(isOurs)) continue;
      rescan();
      return;
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('scroll', () => placeAnchors(), { passive: true });
  window.addEventListener('resize', () => placeAnchors(), { passive: true });

  scan();
})();
