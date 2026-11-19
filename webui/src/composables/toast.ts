import { reactive } from 'vue'

export type ToastKind = 'ok' | 'warn' | 'bad' | 'acc'
export interface Toast {
  id: number
  kind: ToastKind
  text: string
}

export const toasts = reactive<Toast[]>([])
let next = 0

export function dismiss(id: number) {
  const index = toasts.findIndex((toast) => toast.id === id)
  if (index >= 0) toasts.splice(index, 1)
}

/** A message in the corner; it goes after a few seconds (errors after 8), or when closed
 * (`ms` sets the delay). */
export function toast(kind: ToastKind, text: string, ms?: number) {
  const id = ++next
  toasts.push({ id, kind, text })
  setTimeout(() => dismiss(id), ms ?? (kind === 'bad' ? 8000 : 4000))
}
