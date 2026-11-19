/**
 * Copies text. `navigator.clipboard` exists only on secure pages (https or localhost), so on a
 * plain http panel it falls back to a hidden textarea and `execCommand('copy')`.
 */
export async function copyText(text: string): Promise<void> {
  if (globalThis.navigator?.clipboard && globalThis.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      // Refused (no permission): try the fallback.
    }
  }
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  const focused = document.activeElement instanceof HTMLElement ? document.activeElement : null
  area.select()
  try {
    if (!document.execCommand('copy')) throw new Error('复制失败')
  } finally {
    area.remove()
    focused?.focus()
  }
}
