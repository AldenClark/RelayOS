#!/usr/bin/env node
'use strict';
// Actual pinned LuCI form/UI/UCI with deterministic, disposable RPC replies.
// This exercises browser DOM events, not browser layout or router networking.
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
const upstream = ['luci', 'cbi', 'form', 'ui', 'validation', 'uci'].map(name => 'modules/luci-base/htdocs/luci-static/resources/' + name + '.js');
assert.equal(execFileSync('git', ['diff', 'HEAD', '--', ...upstream], { cwd: luciRoot, encoding: 'utf8' }), '');
const luci = path.join(luciRoot, 'modules/luci-base/htdocs/luci-static/resources');
const errors = [], mutations = [], unhandled = [];
const onUnhandled = error => unhandled.push(error);
process.on('unhandledRejection', onUnhandled);
const dom = new JSDOM('<!doctype html><html><head><title>RelayOS shared settings regression</title></head><body><main id="maincontent"></main></body></html>', {
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
const copy = value => JSON.parse(JSON.stringify(value));
let db, serial = 0, statusError = null, statusBarrier = null, statusCalls = 0;
let failMutation = null, applies = 0, coordination;
const modules = {
  baseclass: window.LuCI.extend({ __init__() {} }), dom: window.L.dom,
  view: { extend: value => value },
  request: {}, session: { getLocalData: () => null, setLocalData() {} },
  poll: { add() {}, remove() {} }, fs: {},
  agentState: { status: async () => ({ managed: false }), assertManual: async () => {} },
  systemManager: { render: () => window.E('div') },
  ipsec: {
    async status() {
      statusCalls++;
      if (statusBarrier) await statusBarrier;
      if (statusError) throw statusError;
      return { enabled: false, peers: [] };
    },
    render(_state, _agent, _readonly, gate) { coordination = gate; return window.E('div'); }
  },
  rpc: { declare: spec => async (...args) => {
    if (spec.object === 'session') return true;
    if (spec.object === 'network.interface') return [];
    if (spec.object === 'luci.wireguard') return { pub: 'PUBLIC:' + args[0] };
    assert.equal(spec.object, 'uci');
    const [config, section, values] = args;
    if (spec.method === 'get') return copy(db[config] || {});
    if (spec.method === 'changes') return {};
    mutations.push({ method: spec.method, args: copy(args) });
    if (failMutation?.(spec.method, args)) throw new window.Error('Synthetic UCI failure');
    if (spec.method === 'set') Object.assign(db[config][section], copy(values));
    else if (spec.method === 'delete') {
      if (values == null) delete db[config][section];
      else for (const key of values) delete db[config][section][key];
    }
    else if (spec.method === 'add') {
      const id = values || 'cfg' + String(++serial).padStart(6, '0');
      db[config][id] = { ...copy(args[3]), '.type': section, '.name': id, '.index': Object.keys(db[config]).length };
      return id;
    }
    else assert.equal(spec.method, 'order');
    return 0;
  } }
};
function load(name, dir = luci) {
  const names = Object.keys(modules);
  const Class = new window.Function(...names, fs.readFileSync(path.join(dir, name + '.js'), 'utf8'))(...names.map(name => modules[name]));
  return typeof Class === 'function' ? new Class() : Class;
}
modules.uci = load('uci');
modules.validation = load('validation');
modules.ui = load('ui'); window.L.ui = modules.ui;
modules.form = load('form');
modules.ui.changes.apply = confirmed => {
  assert.equal(confirmed, true); applies++;
  document.body.classList.add('modal-overlay-active');
};
modules.wgConfig = load('wg-config', path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/relay'));
const settings = load('settings', path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/view/relay'));
const tick = () => new Promise(resolve => setImmediate(resolve));
async function flush() { for (let i = 0; i < 16; i++) await tick(); }
function input(id, option) { return document.getElementById('widget.cbid.network.' + id + '.' + option); }
function fill(id, option, value) {
  const node = input(id, option); assert.ok(node, id + '.' + option);
  node.value = value;
  node.dispatchEvent(new window.Event('change', { bubbles: true }));
  node.dispatchEvent(new window.Event('blur', { bubbles: true }));
  return node;
}
const networkButton = () => settings._networkMap.root.querySelector('button.cbi-button-apply');
async function mount() {
  db = {
    network: {
      lan: { '.type': 'interface', '.name': 'lan', '.index': 0, proto: 'static', ipaddr: '192.168.1.20', netmask: '255.255.255.0' },
      wg0: { '.type': 'interface', '.name': 'wg0', '.index': 1, proto: 'wireguard', private_key: Buffer.alloc(32, 1).toString('base64'), addresses: ['10.77.0.2/32'], listen_port: '51820' },
      peer1: { '.type': 'wireguard_wg0', '.name': 'peer1', '.index': 2, public_key: Buffer.alloc(32, 2).toString('base64'), allowed_ips: ['10.77.0.1/32'], route_allowed_ips: '1', persistent_keepalive: '25' }
    },
    firewall: { uplink: { '.type': 'zone', '.name': 'uplink', '.index': 0, name: 'uplink', network: ['lan'], input: 'REJECT' } },
    luci: {}
  };
  mutations.length = 0; errors.length = 0; unhandled.length = 0;
  statusError = statusBarrier = failMutation = null; statusCalls = applies = 0;
  settings._networkBusy = false; settings._networkNeedsReload = false;
  modules.uci.unload(['network', 'firewall', 'luci']);
  document.body.classList.remove('modal-overlay-active');
  document.querySelector('#maincontent').replaceChildren(await settings.render(await settings.load()));
}
async function run() {
  try {
    await mount();
    const original = fill('lan', 'ipaddr', '192.168.1.21');
    statusError = new window.Error('Current IPsec status unavailable');
    networkButton().click(); await flush();
    assert.match(document.querySelector('.alert-message')?.textContent || '', /Current IPsec status unavailable/,
      'A failed shared apply must visibly explain why the draft was not applied');
    assert.equal(input('lan', 'ipaddr'), original);
    assert.equal(original.value, '192.168.1.21');
    assert.equal(original.disabled, false);
    assert.equal(mutations.length, 0); assert.equal(applies, 0);
    assert.deepEqual(unhandled, [], 'The DOM click handler must consume its reported rejection');

    // Freeze both native maps while the post-parse remote check is pending.
    // Otherwise later user edits are silently discarded by renderContents().
    statusError = null;
    let release;
    statusBarrier = new Promise(resolve => { release = resolve; });
    networkButton().click(); await flush();
    assert.equal(settings._networkBusy, true);
    for (const map of [settings._networkMap, settings._wireguardMap]) {
      assert.equal(map.root.hasAttribute('inert'), true, 'Custom LuCI widgets must also be non-interactive');
      assert.equal(map.root.getAttribute('aria-busy'), 'true');
      assert.ok([...map.root.querySelectorAll('input,select,textarea,button')].every(node => node.disabled));
    }
    release(); await flush(); statusBarrier = null;
    assert.equal(db.network.lan.ipaddr, '192.168.1.21');
    assert.equal(applies, 1);
    assert.equal(input('lan', 'ipaddr').disabled, false);
    assert.equal(settings._networkMap.root.hasAttribute('inert'), false);
    assert.equal(settings._wireguardMap.root.hasAttribute('inert'), false);
    assert.equal(input('wg0', '_public_key').disabled, true, 'Restore each widget\'s original readonly state');

    // netifd accepts bare gateway/DNS addresses only; LuCI ip4addr normally
    // accepts /CIDR too, so those fields must explicitly request nomask.
    for (const [option, masked, valid] of [
      ['gateway', '192.168.1.1/24', '192.168.1.1'],
      ['dns', '1.1.1.1/32', '1.1.1.1'],
      ['netmask', '255.255.255.0/24', '255.255.255.0']
    ]) {
      await mount();
      const field = fill('lan', option, masked);
      assert.equal(field.classList.contains('cbi-input-invalid'), true, option + ' must reject a prefix');
      if (option === 'dns') {
        // Native DynamicList keeps the invalid add buffer outside getValue().
        // It must not be accepted as a list item or silently discarded by a
        // successful apply. Keep the same input for the user to correct it.
        field.nextElementSibling.click();
        assert.equal(field.closest('.cbi-dynlist').querySelectorAll('.item').length, 0);
      }
      await assert.rejects(settings.handleApply(), /invalid input value/, option + ' must reject a prefix');
      assert.equal(input('lan', option), field); assert.equal(field.value, masked);
      assert.equal(mutations.length, 0); assert.equal(applies, 0);
      fill('lan', option, valid); await settings.handleApply();
      assert.equal(applies, 1);
    }

    // LuCI accepts decimal IPv4 octets with leading zeros, while netifd's
    // inet_pton() rejects them. Save canonical literals without changing the
    // user-facing draft until a successful apply rebuilds the form.
    for (const [entered, expected] of [
      ['192.168.001.020', '192.168.1.20'],
      ['192.168.001.020/24', '192.168.1.20/24'],
      ['192.168.001.020/08', '192.168.1.20/8'],
      ['192.168.001.020/255.255.255.000', '192.168.1.20/24']
    ]) {
      await mount();
      fill('lan', 'ipaddr', entered);
      fill('lan', 'gateway', '192.168.001.001');
      fill('lan', 'netmask', '255.255.255.000');
      fill('lan', 'dns', '008.008.004.004');
      await settings.handleApply();
      assert.equal(db.network.lan.ipaddr, expected);
      assert.equal(db.network.lan.gateway, '192.168.1.1');
      assert.equal(db.network.lan.netmask, '255.255.255.0');
      assert.deepEqual(db.network.lan.dns, ['8.8.4.4']);
      assert.equal(applies, 1);
    }
    // Unchanged loaded values must also be normalized; normal form equality
    // checks would otherwise skip write() and leave invalid native literals.
    await mount();
    Object.assign(db.network.lan, { ipaddr: '192.168.001.020/08', gateway: '192.168.001.001',
      netmask: '255.255.255.000', dns: ['008.008.004.004'] });
    modules.uci.unload('network');
    document.querySelector('#maincontent').replaceChildren(await settings.render(await settings.load()));
    const loadedInput = input('lan', 'ipaddr');
    statusError = new window.Error('Keep the draft after preflight fails');
    await assert.rejects(settings.handleApply(), /Keep the draft/);
    assert.equal(input('lan', 'ipaddr'), loadedInput);
    assert.equal(loadedInput.value, '192.168.001.020/08');
    assert.equal(mutations.length, 0);
    statusError = null; await settings.handleApply();
    assert.equal(db.network.lan.ipaddr, '192.168.1.20/8');
    assert.equal(db.network.lan.gateway, '192.168.1.1');
    assert.equal(db.network.lan.netmask, '255.255.255.0');
    assert.deepEqual(db.network.lan.dns, ['8.8.4.4']);

    // Simulate uci.add succeeding while an independent uci.set fails. The
    // actual pinned client retains creates after Promise.all rejects. A retry
    // would create a second anonymous section, so require an explicit reload.
    await mount();
    const id = modules.uci.add('network', 'wireguard_wg0');
    modules.uci.set('network', id, 'public_key', Buffer.alloc(32, 3).toString('base64'));
    modules.uci.set('network', id, 'allowed_ips', ['10.77.1.1/32']);
    modules.uci.set('network', id, 'route_allowed_ips', '1');
    modules.uci.set('network', id, 'persistent_keepalive', '25');
    await settings._wireguardMap.load(); await settings._wireguardMap.renderContents();
    const unsavedInput = fill('lan', 'ipaddr', '192.168.1.99');
    failMutation = (method, args) => method === 'set' && args[0] === 'network' && args[1] === 'lan';
    networkButton().click(); await flush();
    assert.equal(Object.values(db.network).filter(section => section['.type'] === 'wireguard_wg0').length, 2);
    assert.ok(modules.uci.state.creates.network[id], 'Pinned native UCI retains the acknowledged anonymous creation');
    assert.equal(input('lan', 'ipaddr'), unsavedInput); assert.equal(unsavedInput.value, '192.168.1.99');
    assert.equal(applies, 0);
    assert.match(document.querySelector('.alert-message').textContent, /Reload this page and review pending changes/);
    assert.ok([...document.querySelectorAll('.alert-message button')].some(button => button.textContent === 'Reload page'));
    const count = mutations.length;
    failMutation = null;
    networkButton().click(); await flush();
    assert.equal(mutations.length, count, 'A retry must not duplicate an acknowledged anonymous add');
    await assert.rejects(coordination.run(async () => { throw new Error('must not enter'); }), /Reload this page/);
    assert.equal(mutations.length, count);
    assert.deepEqual(unhandled, []);
    assert.deepEqual(errors, []);
    // Negative control: bypass only the product gate in this disposable test.
    // This is the exact duplicate that the guarded user action prevented.
    await modules.uci.save();
    assert.equal(Object.values(db.network).filter(section => section['.type'] === 'wireguard_wg0').length, 3,
      'An unguarded native UCI retry really would duplicate the acknowledged creation');
    console.log('RelayOS native Settings DOM/UCI: failure feedback, input locks, native IPv4 normalization, DNS/mask validation and partial-save recovery gate passed');
  } finally {
    window.close(); process.removeListener('unhandledRejection', onUnhandled);
  }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
