// Request helpers for state that several pollers read (composables/maintenance.ts). No imports, so `npm test` runs them directly.

export type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown }

/**
 * One request at a time for a shared piece of state. A caller that comes while a request is in flight
 * waits for that request instead of starting another, so a slow server is never asked again before it answers,
 * and no answer is thrown away for a newer one. `invalidate()` marks the request in flight as stale (the state
 * changed under it): its answer is dropped and the next caller starts a fresh request.
 */
export function singleFlight<T>(load: () => Promise<T>, apply: (outcome: Outcome<T>) => void) {
  let ticket = 0
  let running: { ticket: number; done: Promise<void> } | undefined
  return {
    run(): Promise<void> {
      if (running && running.ticket === ticket) return running.done
      const mine = ++ticket
      const done = (async () => {
        let outcome: Outcome<T>
        try {
          outcome = { ok: true, value: await load() }
        } catch (error) {
          outcome = { ok: false, error }
        }
        if (running?.ticket === mine) running = undefined
        if (mine === ticket) apply(outcome)
      })()
      running = { ticket: mine, done }
      return done
    },
    invalidate() {
      ticket++
    },
  }
}

/**
 * Runs `task` every `ms` until the returned stop is called; the next run is scheduled only after the
 * previous one finished, so runs never overlap however slow the task is.
 */
export function pollSequentially(task: () => Promise<unknown>, ms: number): () => void {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  const run = async () => {
    if (stopped) return
    try {
      await task()
    } catch {
      // the task shows its own failures
    }
    if (!stopped) timer = setTimeout(run, ms)
  }
  timer = setTimeout(run, ms)
  return () => {
    stopped = true
    clearTimeout(timer)
  }
}
