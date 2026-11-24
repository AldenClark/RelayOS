#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname,
  '../packages/luci-theme-relay/htdocs/luci-static/resources/relay/agent-state.js'), 'utf8');
let services = {};
const agent = new Function('baseclass', 'rpc', '_', source)(
  { extend: value => value }, { declare: () => async () => services }, value => value);

async function run() {
  assert.deepEqual(agent.classify({}), { installed: false, enabled: false, managed: false });
  for (const service of [ { enabled: true }, { running: true }, { enabled: false, running: true } ])
    assert.equal(agent.classify({ 'airroute-agent': service }).managed, true);
  assert.deepEqual(agent.classify({ 'airroute-agent': { enabled: false, running: false } }),
    { installed: true, enabled: false, managed: false });
  // A truncated/unsupported rc reply must never grant manual ownership. In
  // particular rc omits running for a non-procd init script, so it is unknown.
  for (const service of [ null, false, [], {}, { enabled: false }, { running: false },
      { enabled: 'false', running: false }, { enabled: false, running: 0 } ]) {
    services = { 'airroute-agent': service };
    assert.throws(() => agent.classify(services), /Unable to detect/);
    await assert.rejects(agent.assertManual(), /Unable to detect/);
  }
  console.log('RelayOS Agent ownership: malformed and incomplete service replies fail closed');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
