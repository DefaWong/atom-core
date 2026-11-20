import test from 'node:test'
import assert from 'node:assert/strict'
import { availableMembers, orderedMembers, reorderVisibleMembers } from '../src/group-members.ts'

test('group and Final hide inactive members and show them again on the original kernel', () => {
  const group = {
    members: ['naive', 'ss', 'g-other'],
    matched: ['ss', 'naive-match', 'tuic'],
    order: ['naive-match', 'ss', 'naive', 'tuic', 'g-other']
  }
  const final = { members: ['naive', 'g-other'] }
  const mihomo = new Set(['naive', 'naive-match'])
  assert.deepEqual(availableMembers(group, mihomo), ['ss', 'tuic', 'g-other'])
  assert.deepEqual(availableMembers(final, mihomo), ['g-other'])
  assert.deepEqual(availableMembers(group, new Set()), group.order)
  assert.deepEqual(availableMembers(final, new Set()), final.members)
})

test('dragging active rows preserves hidden members and their slots for saving', () => {
  const group = { members: ['ss', 'naive', 'tuic'], matched: ['naive-match'], order: ['ss', 'naive', 'naive-match', 'tuic'] }
  const inactive = new Set(['naive', 'naive-match'])
  const order = reorderVisibleMembers(orderedMembers(group), ['tuic', 'ss'], inactive)
  const saved = { ...group, members: order.filter((id) => group.members.includes(id)), order }
  assert.deepEqual(availableMembers(saved, inactive), ['tuic', 'ss'])
  assert.deepEqual(saved.members, ['tuic', 'naive', 'ss'])
  assert.deepEqual(availableMembers(saved, new Set()), ['tuic', 'naive', 'naive-match', 'ss'])
})
