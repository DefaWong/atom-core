// Pure helpers for the factory reset (components/ResetCard.vue). No imports, so `npm test` runs them directly.

/** What the confirmation asks the user to type. */
export const RESET_WORD = '重置'

interface Place {
  hostname: string
}

/** The hostname is an address (or localhost), which the wizard accepts as a Host. */
function isAddress(hostname: string): boolean {
  return hostname === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')
}

/**
 * Where the browser goes for the reset: the wizard on the host the panel was opened on, or on one of the
 * wizard's LAN addresses when the panel was opened by a name the wizard may refuse. The one-time code rides in
 * the fragment, which the browser never sends; the wizard takes it out of the address at once.
 */
export function wizardURL(here: Place, port: number, code: string, urls: readonly string[]): string {
  let target: URL
  if (isAddress(here.hostname) || !urls.length) {
    target = new URL('http://localhost/')
    target.hostname = here.hostname
  } else {
    target = new URL(urls[0])
  }
  target.protocol = 'http:'
  target.port = String(port)
  target.pathname = '/'
  target.search = ''
  target.hash = `code=${encodeURIComponent(code)}`
  return target.href
}
