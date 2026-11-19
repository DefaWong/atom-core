// Which groups a batch node deletion leaves empty (src/emptied.ts), as the host's empty_groups judges it.
import test from 'node:test'
import assert from 'node:assert/strict'

import { emptiedBy, FINAL_ID, usesProviders } from '../src/emptied.ts'

const base = { groups: [], final: null, inactive: new Set(), providers: [], mihomo: true }
const del = (...ids) => new Set(ids)

test('a group losing its last node is named; one keeping a node is not', () => {
  const groups = [
    { id: 'g1', members: ['n1'], empty: false },
    { id: 'g2', members: ['n1', 'n2'], empty: false },
    { id: 'g3', members: ['n2'], empty: false },
  ]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups }), ['g1'])
  assert.deepEqual(emptiedBy(del('n1', 'n2'), { ...base, groups }), ['g1', 'g2', 'g3'])
  assert.deepEqual(emptiedBy(del(), { ...base, groups }), [])
})

test('all_providers with no subscription saved draws nothing, so the group empties', () => {
  const groups = [{ id: 'g', members: ['n1'], all_providers: true, providers: [], empty: false }]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups }), ['g'])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups, providers: ['p-1'] }), [])
})

test('listed subscriptions keep the group under mihomo, not under sing-box', () => {
  const groups = [{ id: 'g', members: ['n1'], providers: ['p-1'], empty: false }]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups, providers: ['p-1'] }), [])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups, providers: ['p-1'], mihomo: false }), ['g'])
  assert.equal(usesProviders(groups[0], []), true)
  assert.equal(usesProviders({ id: 'h', members: [], all_providers: true }, []), false)
})

test('nodes the kernel cannot run are no member', () => {
  const groups = [{ id: 'g', members: ['n1', 'bad'], empty: false }]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups, inactive: new Set(['bad']) }), ['g'])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups }), [])
})

test('filtered nodes, member groups and subscription nodes count as direct members', () => {
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups: [{ id: 'g', members: [], matched: ['n1', 'n2'], empty: false }] }), [])
  assert.deepEqual(emptiedBy(del('n1', 'n2'), { ...base, groups: [{ id: 'g', members: [], matched: ['n1', 'n2'], empty: false }] }), ['g'])
  // nested: the outer group keeps the inner one as a direct member even when the inner one empties
  const nested = [{ id: 'inner', members: ['n1'], empty: false }, { id: 'outer', members: ['inner'], empty: false }]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups: nested }), ['inner'])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups: [{ id: 'g', members: ['n1', 'p-1/hk'], empty: false }] }), [])
})

test('a group already empty is not named again, nor one the deletion does not touch', () => {
  const groups = [{ id: 'g', members: ['bad'], empty: true }, { id: 'h', members: ['bad'], empty: false }]
  assert.deepEqual(emptiedBy(del('n1'), { ...base, groups, inactive: new Set(['bad']) }), [])
})

test('Final empties like a group', () => {
  assert.deepEqual(emptiedBy(del('n1'), { ...base, final: { members: ['n1'], empty: false } }), [FINAL_ID])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, final: { members: ['n1', 'g'], empty: false } }), [])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, final: { members: ['n1', 'bad'], empty: false }, inactive: new Set(['bad']) }), [FINAL_ID])
  assert.deepEqual(emptiedBy(del('n1'), { ...base, final: { members: ['n1'], empty: true } }), [])
})
