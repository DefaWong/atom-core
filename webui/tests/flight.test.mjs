// Shared requests and sequential polling (src/flight.ts), used for the maintenance state.
import test from 'node:test'
import assert from 'node:assert/strict'

import { pollSequentially, singleFlight } from '../src/flight.ts'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

test('callers during a request share it, and its answer is applied', async () => {
  const pending = []
  const applied = []
  const flight = singleFlight(() => { const d = deferred(); pending.push(d); return d.promise }, (o) => applied.push(o))
  const a = flight.run()
  const b = flight.run()
  assert.equal(a, b)
  assert.equal(pending.length, 1)
  pending[0].resolve('slow')
  await a
  assert.deepEqual(applied, [{ ok: true, value: 'slow' }])
  // the next caller starts a new request
  const c = flight.run()
  assert.equal(pending.length, 2)
  pending[1].reject(new Error('down'))
  await c
  assert.equal(applied[1].ok, false)
})

test('a slow server still answers: no request is dropped for a newer one', async () => {
  const applied = []
  let calls = 0
  const flight = singleFlight(async () => { calls++; await sleep(30); return calls }, (o) => applied.push(o.value))
  // a fast poller and a slow one hitting it repeatedly while every answer takes longer than the interval
  const runs = []
  for (let i = 0; i < 5; i++) { runs.push(flight.run()); await sleep(10) }
  await Promise.all(runs)
  assert.ok(applied.length >= 1)
  assert.equal(applied.length, calls)
  assert.deepEqual(applied, applied.map((_, i) => i + 1))
})

test('invalidate drops the answer in flight and the next caller asks again', async () => {
  const pending = []
  const applied = []
  const flight = singleFlight(() => { const d = deferred(); pending.push(d); return d.promise }, (o) => applied.push(o.value))
  const stale = flight.run()
  flight.invalidate()
  const fresh = flight.run()
  assert.notEqual(stale, fresh)
  assert.equal(pending.length, 2)
  pending[0].resolve('before')
  await stale
  assert.deepEqual(applied, [])
  pending[1].resolve('after')
  await fresh
  assert.deepEqual(applied, ['after'])
})

test('polling waits for each run before scheduling the next and stops cleanly', async () => {
  let active = 0
  let most = 0
  let runs = 0
  const stop = pollSequentially(async () => {
    active++; most = Math.max(most, active); runs++
    await sleep(25)
    active--
    if (runs === 2) throw new Error('shown elsewhere')
  }, 5)
  await sleep(150)
  stop()
  const seen = runs
  assert.equal(most, 1)
  assert.ok(seen >= 3, `ran ${seen} times`)
  await sleep(60)
  assert.ok(runs <= seen + 1)
})
