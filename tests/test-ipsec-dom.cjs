#!/usr/bin/env node
'use strict';
// Extra DOM integration regression, deliberately outside test-console-*.cjs.
// Run with JSDOM_MODULE=/absolute/path/to/node_modules/jsdom and LUCI_DIR
// pointing at the exact LuCI checkout in feeds.conf (or set OPENWRT_DIR).
// Uses the real pinned LuCI DOM and RPC classes, but simulated device replies.
// This is NOT a browser, visual-layout, or hardware integration test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
assert.ok(process.env.JSDOM_MODULE, 'Set JSDOM_MODULE to the installed jsdom module; this extra test is not silently skipped');
const { JSDOM, VirtualConsole } = require(process.env.JSDOM_MODULE);
const luciRoot = process.env.LUCI_DIR || (process.env.OPENWRT_DIR && path.join(process.env.OPENWRT_DIR, 'feeds/luci'));
assert.ok(luciRoot, 'Set LUCI_DIR or OPENWRT_DIR to a prepared pinned LuCI checkout');
const luciCommit = /^src-git luci .*\^([0-9a-f]{40})$/m.exec(fs.readFileSync(path.join(root, 'feeds.conf'), 'utf8'))?.[1];
assert.ok(luciCommit, 'feeds.conf must pin LuCI');
assert.equal(execFileSync('git', [ 'rev-parse', 'HEAD' ], { cwd: luciRoot, encoding: 'utf8' }).trim(), luciCommit,
  'Use the exact product-pinned LuCI revision');
const upstreamFiles = [ 'modules/luci-base/htdocs/luci-static/resources/luci.js', 'modules/luci-base/htdocs/luci-static/resources/rpc.js' ];
assert.equal(execFileSync('git', [ 'diff', 'HEAD', '--', ...upstreamFiles ], { cwd: luciRoot, encoding: 'utf8' }), '',
  'Do not patch the upstream DOM/RPC implementation to make this test pass');
const moduleFile = path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/relay/ipsec.js');
const errors = [], transports = [], applies = [];
let current = { ok: true, revision: 'dom-r1', enabled: false, ready: false, eip93: true, manual: true, peers: [] };
let failureCode = '', managed = false, readonly = false, applyBarrier = null, failStatus = false;
let applyAllowed = true, failAccess = false, revokeAfterApply = false;
const dom = new JSDOM('<!doctype html><html lang="en"><head><title>RelayOS IPsec DOM regression</title></head><body><main id="mount"></main></body></html>', {
  url: 'http://relayos.test/cgi-bin/luci/admin/relay/settings', runScripts: 'outside-only',
  virtualConsole: new VirtualConsole().on('jsdomError', error => errors.push(error.message))
});
const { window } = dom;
const { document } = window;
const plain = value => JSON.parse(JSON.stringify(value));
window.addEventListener('error', event => errors.push(event.message));
window.addEventListener('unhandledrejection', event => errors.push(String(event.reason)));
window.TextEncoder = TextEncoder;
window.eval(fs.readFileSync(path.join(luciRoot, upstreamFiles[0]), 'utf8'));
window._ = text => text;
window.L = Object.create(window.LuCI.prototype);
window.L.hasViewPermission = () => !readonly;
window.L.env.rpctimeout = 20;
window.E = (...args) => window.L.dom.create(...args);
// Use LuCI's actual base class and RPC framing, not a reimplementation of E().
const baseclass = window.LuCI.extend({ __init__() {} });
const request = {
  post: async (url, message, options) => {
    const [ _session, object, method, params ] = message.params;
    assert.equal(url, '/ubus');
    assert.ok([ 'relay.ipsec', 'session' ].includes(object));
    assert.ok((object === 'relay.ipsec' ? [ 'get', 'apply' ] : [ 'access' ]).includes(method));
    transports.push({ object, method, options: plain(options) });
    if (method === 'get' && failStatus) throw new window.Error('simulated transport failure');
    let result = current;
    if (method === 'access') {
      assert.deepEqual(plain(params), { scope: 'ubus', object: 'relay.ipsec', function: 'apply' });
      if (failAccess) throw new window.Error('simulated private ACL transport error');
      result = { access: applyAllowed };
    }
    if (method === 'apply') {
      applies.push(plain(params.config));
      if (applyBarrier) await applyBarrier;
      if (failureCode) result = { ok: false, error: failureCode };
      else {
        current = { ...current, enabled: params.config.enabled, ready: params.config.enabled,
          revision: 'dom-r' + (applies.length + 1),
          peers: params.config.peers.map(peer => {
            const { psk, ...redacted } = plain(peer);
            return { ...redacted, psk_set: true,
              state: params.config.enabled && peer.enabled ? 'connecting' : 'disabled' };
          }) };
        result = current;
        if (revokeAfterApply) applyAllowed = false;
      }
    }
    // Decode through the real rpc.js parseCallReply/handleCallReply path.
    const body = window.JSON.parse(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: [ 0, result ] }));
    return { ok: true, status: 200, json: () => body };
  }
};
const Rpc = new window.Function('baseclass', 'request', 'L', fs.readFileSync(path.join(luciRoot, upstreamFiles[1]), 'utf8'))(baseclass, request, window.L);
const rpc = new Rpc();
rpc.setBaseURL('/ubus');
const agentState = { status: async () => ({ managed }) };
const Module = new window.Function('baseclass', 'rpc', 'request', 'agentState', 'E', 'L', '_', fs.readFileSync(moduleFile, 'utf8'))(
  baseclass, rpc, request, agentState, window.E, window.L, window._);
const ipsec = new Module();

function button(name, scope = document) {
  const matches = [ ...scope.querySelectorAll('button') ].filter(element => element.textContent === name);
  assert.equal(matches.length, 1, 'Expected one button: ' + name);
  return matches[0];
}
function field(name, scope = document) {
  const labels = [ ...scope.querySelectorAll('label') ].filter(label => label.textContent === name);
  assert.equal(labels.length, 1, 'Expected one label: ' + name);
  assert.ok(labels[0].control, 'Label must be associated with a real form control: ' + name);
  return labels[0].control;
}
function fill(name, value, scope = document) {
  const input = field(name, scope);
  input.focus(); input.value = value;
  input.dispatchEvent(new window.Event(input.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
  return input;
}
const peers = () => [ ...document.querySelectorAll('.ar-ipsec-peer') ];
const form = () => document.querySelector('#cbi-relay-ipsec');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function idle() {
  for (let i = 0; i < 100 && form()?.getAttribute('aria-busy') === 'true'; i++) await tick();
  assert.equal(form().getAttribute('aria-busy'), 'false', 'DOM operation did not complete');
}
async function load() {
  const state = await ipsec.status();
  document.querySelector('#mount').replaceChildren(ipsec.render(state, await agentState.status(), readonly));
  assert.equal(document.title, 'RelayOS IPsec DOM regression');
  assert.equal(document.location.pathname, '/cgi-bin/luci/admin/relay/settings');
  assert.ok(document.querySelector('h2').textContent.includes('IPsec'));
}
function fillPeer(card, n, name) {
  fill('Name', name, card);
  fill('Endpoint host', 'cloud' + n + '.example.com', card);
  fill('Local IKE identity', 'relay-' + n, card);
  fill('Remote IKE identity', 'cloud-' + n, card);
  fill('Preshared key', 'synthetic-test-key-' + n, card);
  fill('Local tunnel IPv4 address', '10.78.' + n + '.2/32', card);
  fill('Remote IPv4 subnets', '10.78.' + n + '.1/32', card);
}
async function save() {
  assert.equal(button('Save & Apply').disabled, false);
  button('Save & Apply').click();
  await idle();
}

async function run() {
  try {
    await load();
    assert.ok(form().matches('.cbi-map'));
    assert.ok(form().querySelector('.cbi-section > .cbi-section-node #relay-ipsec-enabled'));
    assert.doesNotMatch(form().textContent, /Disabled|EIP-93|Changes are applied only|Editor resource limits|No IPsec peers configured/);
    assert.equal(document.querySelectorAll('input[type=checkbox]').length, 1);
    assert.ok(![ ...document.querySelectorAll('button') ].some(b => /^(Enable|Disable) IPsec$/.test(b.textContent)));
    assert.equal(button('Save & Apply').disabled, true);
    field('Enable IPsec').click();
    button('Add peer').click(); fillPeer(peers()[0], 1, 'Cloud A');
    button('Add peer').click(); fillPeer(peers()[1], 2, 'Cloud B');
    assert.equal(applies.length, 0, 'Adding peers and editing fields must only change drafts');
    assert.equal(peers().length, 2);
    assert.ok(peers().every(card => /^p[0-7][0-9a-f]{7}$/.test(card.dataset.peerId) && card.dataset.peerId !== 'p00000000'));
    assert.equal(document.querySelectorAll('input[type=checkbox]').length, 3);
    // Real E() must retain textarea contents when another peer is added.
    assert.equal(field('Remote IPv4 subnets', peers()[0]).value, '10.78.1.1/32');
    assert.equal(field('Name', peers()[0]).value, 'Cloud A');
    await save();
    assert.equal(applies.length, 1); assert.equal(current.peers.length, 2); assert.equal(current.enabled, true);
    assert.ok([ ...document.querySelectorAll('input[type=password]') ].every(input => input.value === ''));
    assert.ok(!document.body.innerHTML.includes('synthetic-test-key'));
    assert.equal(button('Save & Apply').disabled, true);
    assert.ok(transports.filter(call => call.method === 'apply').every(call => call.options.timeout === 30000 && call.options.nobatch === true));
    assert.ok(transports.filter(call => call.method === 'get').every(call => call.options.timeout === 20000));
    assert.equal(window.L.env.rpctimeout, 20);
    assert.equal(field('Enable IPsec').disabled, false, 'A successful apply keeps independently verified write access');

    // Disable only B. No stored key may be sent back as an empty replacement.
    field('Enable peer', peers()[1]).click();
    await save();
    assert.equal(applies[1].peers[0].enabled, true); assert.equal(applies[1].peers[1].enabled, false);
    assert.ok(applies[1].peers.every(peer => !Object.hasOwn(peer, 'psk') && !Object.hasOwn(peer, 'psk_set')));
    assert.equal(field('Enable peer', peers()[1]).checked, false);

    // Native number-input constraints must not swallow our custom validation
    // when invalid advanced fields are hidden inside a collapsed details node.
    for (const [ label, invalidValue, validValue, error ] of [
      [ 'DPD interval (seconds)', '30.5', '30', /DPD interval must be an integer/ ],
      [ 'Tunnel MTU', '1400.5', '1400', /MTU must be an integer/ ]
    ]) {
      const invalidInput = fill(label, invalidValue, peers()[0]);
      assert.equal(invalidInput.validity.stepMismatch, true);
      assert.equal(peers()[0].querySelector('details').open, false);
      await save(); assert.equal(applies.length, 2);
      assert.match(document.querySelector('[role=status]').textContent, error);
      assert.equal(field(label, peers()[0]), invalidInput);
      assert.equal(invalidInput.value, invalidValue);
      fill(label, validValue, peers()[0]);
    }

    // Validation happens before the apply RPC and keeps all entered values.
    fill('Local IKE identity', '192.0.2.1-192.0.2.10', peers()[0]);
    await save(); assert.equal(applies.length, 2);
    assert.match(document.querySelector('[role=status]').textContent, /IKE identities/);
    assert.equal(field('Local IKE identity', peers()[0]).value, '192.0.2.1-192.0.2.10');
    fill('Local IKE identity', '@CLOUD-2', peers()[0]);
    await save(); assert.equal(applies.length, 2);
    assert.match(document.querySelector('[role=status]').textContent, /IKE identities conflict/);
    assert.equal(field('Local IKE identity', peers()[0]).value, '@CLOUD-2');
    fill('Local IKE identity', 'relay-1', peers()[0]);
    fill('Remote IKE identity', '0.0.0.0', peers()[0]);
    await save(); assert.equal(applies.length, 2);
    assert.match(document.querySelector('[role=status]').textContent, /IKE identities/);
    assert.equal(field('Remote IKE identity', peers()[0]).value, '0.0.0.0');
    fill('Remote IKE identity', 'cloud-1', peers()[0]);
    fill('Remote IPv4 subnets', '0.0.0.0/0', peers()[0]);
    await save(); assert.equal(applies.length, 2);
    assert.match(document.querySelector('[role=status]').textContent, /default route/);
    fill('Remote IPv4 subnets', '10.78.1.1/32', peers()[0]);

    // Failed backend apply keeps the same input node, value and dirty state.
    failureCode = 'route_conflict';
    const nameInput = fill('Name', 'Preserved draft', peers()[0]);
    await save(); assert.equal(applies.length, 3);
    assert.equal(field('Name', peers()[0]), nameInput);
    assert.equal(nameInput.value, 'Preserved draft');
    assert.match(document.querySelector('[role=status]').textContent, /conflict/);
    assert.equal(button('Save & Apply').disabled, false);
    failureCode = 'unexpected backend output synthetic-key';
    await save(); assert.equal(applies.length, 4);
    assert.ok(!document.querySelector('[role=status]').textContent.includes('synthetic-key'));
    failureCode = '';

    // A read-only status refresh must preserve the dirty input and update state.
    current.peers[0].state = 'established';
    nameInput.focus();
    button('Refresh status').click(); await idle();
    assert.equal(field('Name', peers()[0]), nameInput); assert.equal(nameInput.value, 'Preserved draft');
    assert.equal(document.activeElement, nameInput);
    assert.equal(peers()[0].querySelector('[data-ipsec-status]').textContent, 'Connected');
    button('Discard changes').click(); await idle();
    assert.equal(field('Name', peers()[0]).value, 'Cloud A');
    assert.equal(button('Save & Apply').disabled, true);

    // Concurrent saves are blocked even if a second submit event is injected.
    fill('Name', 'One application', peers()[0]);
    let release;
    applyBarrier = new Promise(resolve => { release = resolve; });
    button('Save & Apply').click(); await tick();
    const count = applies.length;
    assert.equal(form().getAttribute('aria-busy'), 'true');
    assert.ok([ ...form().querySelectorAll('[data-ipsec-edit]') ].every(input => input.disabled));
    form().dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await tick(); assert.equal(applies.length, count);
    release(); await idle(); applyBarrier = null;

    // Delete is staged, then sent as a full desired peer list, not a side effect.
    button('Remove peer', peers()[1]).click();
    assert.equal(peers().length, 1); assert.equal(current.peers.length, 2);
    assert.equal(applies.length, count);
    await save(); assert.equal(current.peers.length, 1);
    assert.equal(current.peers[0].name, 'One application');

    // Stale writers cannot overwrite an external configuration change.
    fill('Name', 'Stale draft', peers()[0]);
    current = { ...current, revision: 'external-writer', peers: [ { ...current.peers[0], name: 'External name' } ] };
    const staleCount = applies.length;
    await save(); assert.equal(applies.length, staleCount);
    assert.equal(field('Name', peers()[0]).value, 'Stale draft');
    assert.match(document.querySelector('[role=status]').textContent, /changed elsewhere/);
    button('Discard changes').click(); await idle();
    assert.equal(field('Name', peers()[0]).value, 'External name');

    // An Agent takeover is rechecked immediately before apply.
    fill('Name', 'Agent race draft', peers()[0]); managed = true;
    await save(); assert.equal(applies.length, staleCount);
    assert.equal(button('Add peer').disabled, true);
    assert.equal(field('Name', peers()[0]).value, 'Agent race draft');
    managed = false; button('Refresh status').click(); await idle();
    assert.equal(button('Add peer').disabled, false);
    // A failed status read also locks writes until ownership can be read again.
    failStatus = true; button('Refresh status').click(); await idle();
    assert.equal(field('Enable IPsec').disabled, true);
    assert.equal(field('Name', peers()[0]).value, 'Agent race draft');
    failStatus = false; button('Discard changes').click(); await idle();

    // Real pinned LuCI E() treats scalar string children as HTML; ensure our
    // untrusted names and textarea values are text nodes, not parsed elements.
    const maliciousName = '<img src=x onerror=alert(1)>';
    current.peers[0].name = maliciousName;
    current.peers[0].remote_subnets = [ '</textarea><img id=qa-xss src=x>' ];
    await load();
    assert.equal(document.querySelectorAll('.ar-ipsec-peer img').length, 0);
    assert.equal(peers()[0].querySelector('h3').textContent, maliciousName);
    assert.equal(field('Remote IPv4 subnets', peers()[0]).value, '</textarea><img id=qa-xss src=x>');
    assert.ok(peers()[0].querySelector('h3').childNodes[0].nodeType === window.Node.TEXT_NODE);

    // Secrets returned in an invalid backend payload must fail schema decoding.
    current.peers[0].psk = 'never-return-keys';
    await assert.rejects(ipsec.status(), /status is unavailable/);
    delete current.peers[0].psk;
    const validId = current.peers[0].id;
    for (const invalidId of [ 'p00000000', 'p80000000', 'pffffffff' ]) {
      current.peers[0].id = invalidId;
      await assert.rejects(ipsec.status(), /status is unavailable/);
    }
    current.peers[0].id = validId;
    current.peers[0].name = 'Cloud A'; current.peers[0].remote_subnets = [ '10.78.1.1/32' ];
    readonly = true; await load();
    assert.ok([ ...form().querySelectorAll('[data-ipsec-edit]') ].every(input => input.disabled));
    const readonlyCount = applies.length;
    button('Add peer').click(); form().dispatchEvent(new window.Event('submit', { cancelable: true }));
    await idle(); assert.equal(applies.length, readonlyCount); assert.equal(peers().length, 1);
    readonly = false; await load();

    // The menu grants write when ANY required ACL group grants write. Simulate
    // network write + IPsec read only: L.hasViewPermission() remains true.
    applyAllowed = false; current.can_apply = true;
    await load();
    assert.equal(window.L.hasViewPermission(), true);
    assert.ok([ ...form().querySelectorAll('[data-ipsec-edit]') ].every(input => input.disabled));
    assert.ok(document.body.textContent.includes('IPsec settings are read-only for this session.'));
    const aclCount = applies.length;
    button('Add peer').click(); form().dispatchEvent(new window.Event('submit', { cancelable: true }));
    await idle(); assert.equal(applies.length, aclCount); assert.equal(peers().length, 1);
    assert.equal(field('Preshared key', peers()[0]).value, '');
    delete current.can_apply;

    // Refresh must reevaluate method access, and an unknown answer fails closed.
    applyAllowed = true; button('Refresh status').click(); await idle();
    assert.equal(field('Enable IPsec').disabled, false);
    const aclDraft = fill('Name', 'Retain ACL draft', peers()[0]);
    failAccess = true; button('Refresh status').click(); await idle();
    assert.equal(field('Enable IPsec').disabled, true);
    assert.equal(field('Name', peers()[0]), aclDraft); assert.equal(aclDraft.value, 'Retain ACL draft');
    assert.ok(!document.body.textContent.includes('private ACL transport error'));
    failAccess = false; button('Refresh status').click(); await idle();
    assert.equal(field('Enable IPsec').disabled, false);

    // A permission revoked between editing and apply must stop before apply RPC.
    applyAllowed = false;
    await save(); assert.equal(applies.length, aclCount);
    assert.equal(field('Name', peers()[0]), aclDraft); assert.equal(aclDraft.value, 'Retain ACL draft');
    assert.equal(field('Enable IPsec').disabled, true);
    assert.match(document.querySelector('[role=status]').textContent, /read-only/);
    applyAllowed = true; button('Refresh status').click(); await idle();

    // A successful transaction also refreshes access instead of inheriting a
    // stale page-wide grant or trusting a can_apply field from relay.ipsec.
    revokeAfterApply = true; await save(); revokeAfterApply = false;
    assert.equal(applies.length, aclCount + 1); assert.equal(current.peers[0].name, 'Retain ACL draft');
    assert.equal(field('Enable IPsec').disabled, true);
    assert.equal(field('Preshared key', peers()[0]).value, '');
    applyAllowed = true; button('Refresh status').click(); await idle();
    assert.equal(field('Enable IPsec').disabled, false);

    // Global toggle and peer toggle are separate, actual checkbox controls.
    assert.equal(field('Enable IPsec').type, 'checkbox');
    assert.equal(field('Enable peer', peers()[0]).type, 'checkbox');
    field('Enable IPsec').click(); await save();
    assert.equal(current.enabled, false); assert.equal(current.peers[0].enabled, true);
    assert.equal(peers()[0].querySelector('[data-ipsec-status]').textContent, 'Disabled');
    assert.deepEqual(errors, []);
    console.log('RelayOS IPsec DOM integration: PASS (jsdom + exact pinned LuCI DOM/RPC; no browser/layout/hardware claim)');
    console.log('Verified actual labels/checkboxes/buttons, two peers, draft-only add/remove, save success/failure, isolated timeout, key redaction, stale/Agent/mixed-ACL/concurrency guards and XSS text insertion');
  } finally { dom.window.close(); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
