// The deployment the maintenance overview reports (src/deployment.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { isContainer } from '../src/deployment.ts'

test('only an overview that says container is the container version', () => {
  assert.equal(isContainer({ deployment: 'container' }), true)
  assert.equal(isContainer({}), false)
  assert.equal(isContainer({ deployment: 'linux' }), false)
  assert.equal(isContainer(null), false)
  assert.equal(isContainer(undefined), false)
})
