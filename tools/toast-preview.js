// Design harness for the save prompt. Never shipped — it lives in tools/ so no
// stub can end up inside the extension by accident.
//
// The toast is normally framed into a page by the content script and talks to
// the background page. Here it is the whole document and there is no background
// page, so `browser.runtime` is stubbed with the one reply it asks for. The
// markup and the stylesheet are the real ones: tools/preview.sh generates the
// page from src/ext/toast.html with only this script swapped in, so what is on
// screen cannot drift from what ships.

const q = new URLSearchParams(location.search);
const kind = q.get('kind') === 'address' ? 'address' : 'login';

const NOTICE = {
  login: {
    kind: 'login',
    host: 'benco.example',
    username: 'ben@ropple.net',
    update: q.has('update'),
    summary: '',
    suggestedName: '',
  },
  address: {
    kind: 'address',
    host: 'shop.example',
    username: '',
    update: false,
    summary: '1 Pentagon Way, Springfield, 90210',
    suggestedName: 'Springfield',
  },
};

globalThis.browser = {
  runtime: {
    // The toast asks for exactly one thing before it draws, and sends exactly
    // two afterwards. Anything else here would be a stub of something the real
    // toast does not do.
    sendMessage: async (msg) => {
      if (msg.type === 'notice-state') return NOTICE[kind];
      if (msg.type === 'save') return { ok: true, merged: q.has('merged') };
      return { ok: true };
    },
  },
};

await import('../src/ext/toast.js');

// The real notice id arrives by postMessage from the content script that framed
// the toast. At top level `window.parent` is `window`, so posting to ourselves
// satisfies the same check.
window.postMessage({ bencpass: 'notice', noticeId: 'preview' }, '*');
