// The page half: hand the background one object it made itself and one string,
// then close — closing is what nukes this document's compartment.
(async () => {
  const bg = await browser.runtime.getBackgroundPage();
  bg.probe.keepReference({ locked: false });
  bg.probe.buildFromString(JSON.stringify({ locked: false }));
  const me = await browser.tabs.getCurrent();
  setTimeout(() => browser.tabs.remove(me.id), 300);
})();
