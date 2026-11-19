// The factory reset's hand-over to the install wizard (src/reset.ts).
import test from 'node:test'
import assert from 'node:assert/strict'

import { wizardURL } from '../src/reset.ts'

test('the wizard on the address the panel was opened on, with the code in the fragment', () => {
  assert.equal(wizardURL({ hostname: '10.0.0.5' }, 9996, '012345', ['http://10.0.2.1:9996/']), 'http://10.0.0.5:9996/#code=012345')
  assert.equal(wizardURL({ hostname: '[fd00::5]' }, 9996, '012345', []), 'http://[fd00::5]:9996/#code=012345')
  assert.equal(wizardURL({ hostname: 'localhost' }, 80, '000001', []), 'http://localhost/#code=000001')
})

test('a panel opened by name goes to a LAN address of the wizard', () => {
  assert.equal(wizardURL({ hostname: 'atom.home.arpa' }, 41234, '123456', ['http://192.168.1.2:41234/', 'http://10.0.0.2:41234/']), 'http://192.168.1.2:41234/#code=123456')
  assert.equal(wizardURL({ hostname: 'atom' }, 9996, '123456', []), 'http://atom:9996/#code=123456')
})
