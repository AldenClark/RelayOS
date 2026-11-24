#!/usr/bin/env node
'use strict';
// Native pinned LuCI form/UI/validation regression with disposable UCI data.
// Not a router or a browser/layout test; run explicitly with the same extra
// JSDOM_MODULE and LUCI_DIR dependencies as test-ipsec-dom.cjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
assert.ok(process.env.JSDOM_MODULE, 'Set JSDOM_MODULE to the installed jsdom module');
assert.ok(process.env.LUCI_DIR, 'Set LUCI_DIR to the exact product-pinned LuCI checkout');
const { JSDOM, VirtualConsole } = require(process.env.JSDOM_MODULE);
const luciRoot = process.env.LUCI_DIR;
const pinned = /^src-git luci .*\^([0-9a-f]{40})$/m.exec(fs.readFileSync(path.join(root, 'feeds.conf'), 'utf8'))[1];
assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: luciRoot, encoding: 'utf8' }).trim(), pinned);
const upstream = ['luci', 'cbi', 'form', 'ui', 'validation'].map(name => 'modules/luci-base/htdocs/luci-static/resources/' + name + '.js');
assert.equal(execFileSync('git', ['diff', 'HEAD', '--', ...upstream], { cwd: luciRoot, encoding: 'utf8' }), '');
const luci = path.join(luciRoot, 'modules/luci-base/htdocs/luci-static/resources');
const errors = [], keyCalls = [], applies = [];
const dom = new JSDOM('<!doctype html><html><head><title>RelayOS WireGuard form regression</title></head><body><main id="mount"></main></body></html>', {
  url: 'http://relayos.test/cgi-bin/luci/admin/relay/settings', runScripts: 'outside-only',
  virtualConsole: new VirtualConsole().on('jsdomError', error => errors.push(error.message))
});
const { window } = dom, { document } = window;
window.eval(fs.readFileSync(path.join(luci, 'luci.js'), 'utf8'));
window.eval(fs.readFileSync(path.join(luci, 'cbi.js'), 'utf8'));
window._ = text => text;
window.L = Object.create(window.LuCI.prototype);
window.L.hasViewPermission = () => true;
window.E = (...args) => window.L.dom.create(...args);
let writeAllowed = true, managed = false, busy = false, serial = 0, saves = 0;
const db = { network: {}, firewall: { up: { '.name': 'up', '.type': 'zone', name: 'uplink', network: ['lan'], input: 'REJECT' } }, luci: {} };
const modules = {
  baseclass: window.LuCI.extend({ __init__() {} }), dom: window.L.dom,
  uci: {
    load: async () => {}, loadPackage: async () => {},
    sections: (config, type) => Object.values(db[config] || {}).filter(section => !type || section['.type'] === type),
    get: (config, id, key) => key == null ? db[config]?.[id] : db[config]?.[id]?.[key],
    set: (config, id, key, value) => { db[config][id][key] = value; },
    unset: (config, id, key) => { if (db[config]?.[id]) delete db[config][id][key]; },
    add: (config, type, id = 'test' + (++serial)) => { db[config][id] = { '.type': type, '.name': id }; return id; },
    remove: (config, id) => { delete db[config][id]; },
    save: async () => { saves++; }, changes: async () => ({})
  },
  rpc: { declare: spec => async (...args) => {
    if (spec.object === 'session') return writeAllowed;
    if (spec.object === 'network.interface') return [];
    if (spec.object === 'luci.wireguard') { keyCalls.push(args[0]); return { pub: 'PUBLIC:' + args[0] }; }
    return {};
  } },
  request: {}, session: { getLocalData: () => null, setLocalData() {} },
  poll: { add() {}, remove() {} }, fs: {},
  agentState: { assertManual: async () => { if (managed) throw new Error('Agent managed'); } }
};
function load(name, dir = luci) {
  const names = Object.keys(modules);
  const Class = new window.Function(...names, fs.readFileSync(path.join(dir, name + '.js'), 'utf8'))(...names.map(name => modules[name]));
  return new Class();
}
modules.validation = load('validation');
modules.ui = load('ui');
window.L.ui = modules.ui;
modules.form = load('form');
modules.ui.changes.apply = async confirmed => { applies.push(confirmed); };
const wg = load('wg-config', path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/relay'));
const tick = () => new Promise(resolve => setImmediate(resolve));
async function flush() { for (let i = 0; i < 8; i++) await tick(); }
function button(title) {
  const matches = [...document.querySelectorAll('button')].filter(node => node.textContent === title);
  assert.equal(matches.length, 1, title);
  return matches[0];
}
function input(id, option) { return document.getElementById('widget.cbid.network.' + id + '.' + option); }
function fill(id, option, value) {
  const node = input(id, option);
  assert.ok(node, id + '.' + option);
  node.value = value;
  node.dispatchEvent(new window.Event('change', { bubbles: true }));
  node.dispatchEvent(new window.Event('blur', { bubbles: true }));
}
let map;
async function mount() {
  const node = await wg.render({ onMap: value => { map = value; }, coordination: {
    run: async operation => { if (busy) throw new Error('Another operation is busy'); return operation(); }
  } });
  document.querySelector('#mount').replaceChildren(node);
}
async function run() {
  try {
    await mount();
    assert.equal(document.title, 'RelayOS WireGuard form regression');
    assert.equal(document.location.pathname, '/cgi-bin/luci/admin/relay/settings');
    assert.equal(button('Create tunnel').disabled, false);
    button('Create tunnel').click();
    await flush();
    assert.equal(saves, 1);
    assert.equal(db.network.wg0.listen_port, '51820', 'Native parse must not erase creation defaults');
    assert.equal(input('wg0', 'listen_port').value, '51820');
    assert.equal(document.querySelectorAll('.cbi-section-remove').length, 0, 'Created tunnel cannot expose unguarded Delete');
    assert.equal(input('wg0', 'private_key').type, 'password');
    const section = map.children[0], peers = section.getOption('_peers').subsection;
    await assert.rejects(peers.handleAdd(), /invalid input value/);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 0, 'Failed form validation must not leave an invisible peer');
    const privateKey = Buffer.alloc(32, 1).toString('base64');
    fill('wg0', 'private_key', privateKey);
    await flush();
    assert.equal(keyCalls.at(-1), privateKey, 'Native onchange argument order must send the actual key');
    assert.equal(input('wg0', '_public_key').value, 'PUBLIC:' + privateKey);
    fill('wg0', 'private_key', '');
    await flush();
    assert.equal(input('wg0', '_public_key').value, '');
    fill('wg0', 'private_key', privateKey);
    fill('wg0', 'addresses', '10.77.0.2/32');
    await peers.handleAdd();
    const first = modules.uci.sections('network', 'wireguard_wg0')[0]['.name'];
    assert.equal(db.network[first].route_allowed_ips, '1');
    assert.equal(db.network[first].persistent_keepalive, '25');
    assert.equal(document.querySelectorAll('.cbi-section-remove').length, 0);
    await assert.rejects(peers.handleAdd(), /invalid input value/);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
    fill(first, 'public_key', Buffer.alloc(32, 2).toString('base64'));
    fill(first, 'allowed_ips', '10.77.0.1/32');
    busy = true;
    const before = JSON.stringify(db);
    await assert.rejects(peers.handleAdd(), /busy/);
    assert.equal(JSON.stringify(db), before);
    busy = false;
    await peers.handleAdd();
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 2);
    const second = modules.uci.sections('network', 'wireguard_wg0').find(peer => peer['.name'] !== first)['.name'];
    fill('wg0', 'private_key', 'invalid-key');
    const beforeRejectedRemoval = JSON.stringify(db);
    await assert.rejects(peers.handleRemove(second), /invalid input value/);
    assert.equal(JSON.stringify(db), beforeRejectedRemoval, 'Rejected removal must leave the target peer in the draft');
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 2);
    fill('wg0', 'private_key', privateKey);
    // The removed peer itself is incomplete and must not block deletion.
    await peers.handleRemove(second);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
    await assert.rejects(peers.handleRemove(first), /at least one peer/);
    assert.deepEqual(applies, [], 'Editing the draft must not apply it');
    managed = true;
    await assert.rejects(peers.handleAdd(), /Agent managed/);
    managed = false;
    writeAllowed = false;
    await mount();
    assert.equal(input('wg0', 'private_key').disabled, true);
    assert.equal(button('Add peer').disabled, true);
    assert.equal(button('Save & Apply').disabled, true);
    assert.deepEqual(errors, []);
    console.log('RelayOS native WireGuard form: creation, validation, key derivation, peer controls, gate and ACL passed');
  } finally { window.close(); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
