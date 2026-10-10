/** The toolbar badge. The Firefox build is Manifest V2, where `action` is `browserAction`. */
export async function setToolbarBadge(tabId: number, text: string, color: string): Promise<void> {
  const action =
    (browser.action as typeof browser.action | undefined) ??
    (browser.browserAction as typeof browser.action | undefined);
  try {
    await action?.setBadgeText({ tabId, text });
    await action?.setBadgeBackgroundColor({ tabId, color });
  } catch {
    // The badge is a hint; failing to draw it must never hide a finished check.
  }
}
