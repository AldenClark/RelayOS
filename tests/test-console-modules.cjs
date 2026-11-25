#!/usr/bin/env node
// Verify LuCI class-factory contracts, which `node --check` alone cannot catch.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const resources = path.resolve(__dirname,
  '../packages/luci-theme-relay/htdocs/luci-static/resources');

function BaseClass() {}
BaseClass.extend = function(properties) {
  function Subclass() {}
  Subclass.prototype = Object.create(this.prototype);
  Object.assign(Subclass.prototype, properties);
  return Subclass;
};
BaseClass.isSubclass = function(value) {
  return typeof value === 'function' && value.prototype instanceof this;
};

let now = 1000;
const dependencies = {
  _: value => value,
  baseclass: BaseClass,
  view: BaseClass,
  rpc: { declare: () => () => Promise.resolve({}) },
  form: {}, uci: {}, poll: {}, fs: {}, ui: {}, request: {},
  Date: { now: () => now }
};

function loadModule(file) {
  const source = fs.readFileSync(path.join(resources, file), 'utf8');
  const names = Object.keys(dependencies);
  const constructor = new Function(...names, source)(...names.map(n => dependencies[n]));
  assert.ok(BaseClass.isSubclass(constructor),
    `${file}: LuCI factory must return a baseclass subclass constructor`);
  return new constructor();
}

dependencies.traffic = loadModule('relay/traffic.js');
dependencies.wireguard = loadModule('relay/wireguard.js');
dependencies.systemManager = loadModule('relay/system.js');
dependencies.agentState = loadModule('relay/agent-state.js');
dependencies.wgConfig = loadModule('relay/wg-config.js');

const traffic = dependencies.traffic;
assert.equal(traffic.bytes(1024), '1.0 KB');
assert.equal(traffic.bytes(-1), '—');

const sample = traffic.tracker();
assert.deepEqual(sample('wg0', { statistics: { rx_bytes: 1000, tx_bytes: 2000 } }),
  { rx: 1000, tx: 2000, rxRate: null, txRate: null });
now += 5000;
assert.deepEqual(sample('wg0', { statistics: { rx_bytes: 1500, tx_bytes: 2300 } }),
  { rx: 1500, tx: 2300, rxRate: 100, txRate: 60 });
assert.equal(sample('wg1', {}), null);

// Historical counters survive navigation because they come from the device.
const rows = Array.from({ length: 241 }, (_, i) => `${i * 15} ${i * 1500} ${i * 3000}`).join('\n');
const history = traffic.history(rows, 3600);
assert.equal(history.length, 241);
assert.equal(history[1].rxRate, 100);
assert.equal(history[240].txRate, 200);
assert.equal(traffic.history(rows, 7201).length, 0);
assert.deepEqual(traffic.history('malformed', 3600), []);
assert.deepEqual(traffic.history(rows, undefined), []);
assert.equal(traffic.history('0 100 100\n15 50 50', 15)[1].rxRate, null);
assert.equal(traffic.history('0 100 100\n60 200 200', 60)[1].rxRate, null);
assert.equal(traffic.history('0 100 100\nbad\n15 200 200', 15)[1].rxRate, null);
assert.equal(traffic.history('30 100 100', 15).length, 0);
assert.match(traffic.linePath(history, 'rx', 3600), /^ M1\.3,13\.0 L/);
const gap = traffic.history('0 0 0\n15 150 150\n75 300 300\n90 450 450', 90);
assert.equal((traffic.linePath(gap, 'rx', 90).match(/M/g) || []).length, 2);

for (const file of fs.readdirSync(path.join(resources, 'view/relay')))
  if (file.endsWith('.js')) loadModule(`view/relay/${file}`);

async function overviewPolling() {
  const polls = new Map();
  let mountFrame, historyReads = 0, elapsed = 0;
  Object.assign(dependencies, {
    E: () => ({ isConnected: false }),
    L: { url: () => '', resolveDefault: (promise, fallback) => promise.catch(() => fallback) },
    document: { createElementNS: () => ({ setAttribute() {}, classList: { add() {} }, appendChild() {} }) },
    performance: { now: () => elapsed },
    requestAnimationFrame: callback => { mountFrame = callback; },
    poll: { add: (callback, interval) => polls.set(interval, callback), remove: callback => {
      for (const [interval, registered] of polls)
        if (registered === callback) polls.delete(interval);
    } },
    fs: { read: async () => { historyReads++; return ''; } },
    wireguard: { snapshot: async () => [], render() {} }
  });
  const view = loadModule('view/relay/overview.js');
  view.updateSnapshot = () => {};
  const page = view.render(await view.load());
  assert.equal(historyReads, 1);
  assert.equal(polls.size, 0, 'A synchronous poll must not run against an unmounted page');
  page.isConnected = true;
  mountFrame();
  assert.deepEqual([...polls.keys()], [5, 15]);
  await polls.get(15)();
  assert.equal(historyReads, 1, 'Skip a duplicate read just after the initial load');
  elapsed = 15000;
  await polls.get(5)();
  assert.equal(historyReads, 1);
  await polls.get(15)();
  assert.equal(historyReads, 2);
  page.isConnected = false;
  await polls.get(5)();
  await polls.get(15)();
  assert.equal(polls.size, 0);
}

overviewPolling().then(() => {
  console.log('RelayOS LuCI modules: factory contracts, traffic sampling and overview polling OK');
}).catch(error => { console.error(error); process.exitCode = 1; });
