'use strict';
'require baseclass';
'require rpc';
'require request';
'require relay.agent-state as agentState';

// Isolated RPC: saving IPsec must not apply pending WireGuard/LAN UCI edits.
const getConfig = rpc.declare({ object: 'relay.ipsec', method: 'get', expect: { '': {} } });
const checkApplyAccess = rpc.declare({ object: 'session', method: 'access',
  params: [ 'scope', 'object', 'function' ], expect: { access: false } });
// The bounded transaction includes rollback. Give this call its own 30s
// transport timeout without changing global LuCI RPC timeouts or other forms.
const applyRpc = Object.create(rpc);
applyRpc.call = function(req, callback) {
  return request.post(this.getBaseURL(), req, { timeout: 30000, nobatch: true, credentials: true }).then(callback, callback);
};
const applyConfig = applyRpc.declare({ object: 'relay.ipsec', method: 'apply', params: [ 'config' ], expect: { '': {} } });
const ikeProposals = [ 'aes128-sha256-modp2048', 'aes256-sha256-modp2048' ];
const espProposals = [ 'aes128-sha256-noesn', 'aes256-sha256-noesn', 'aes128gcm16-noesn' ];
const peerStates = [ 'established', 'connecting', 'down', 'disabled' ];
const peerFields = [ 'id', 'name', 'enabled', 'remote', 'local_id', 'remote_id',
  'local_address', 'remote_subnets', 'ike', 'esp', 'dpd_delay', 'mtu' ];

function failure(message) {
  const error = new Error(message);
  error.ipsecSafe = true;
  return error;
}

function operationError(code) {
  switch (code) {
    case 'stale_revision':
      return _('IPsec settings changed elsewhere. Discard this draft and review the current settings.');
    case 'busy':
      return _('Another IPsec operation is in progress. Try again shortly.');
    case 'managed':
      return _('IPsec is managed by AirRoute Agent or unavailable.');
    case 'route_conflict': case 'name_conflict':
      return _('IPsec settings conflict with an existing route, interface or configuration. Review the settings.');
    case 'identity_conflict':
      return _('IKE identities conflict with another peer. Check local and remote identities.');
    case 'port_conflict':
      return _('WireGuard and IPsec cannot use the same UDP listen ports (500 and 4500).');
    case 'key_required':
      return _('A new peer requires a preshared key.');
    case 'pending_changes':
      return _('Other network or firewall changes are pending. Apply or discard those changes first.');
    case 'unmanaged_config':
      return _('Existing unmanaged IPsec configuration must be reviewed before using this editor.');
    case 'unavailable':
      return _('IPsec components are unavailable. Check the installed firmware packages.');
    case 'invalid_config':
      return _('IPsec settings were rejected. Check the peer parameters and address ranges.');
    case 'rollback_failed':
      return _('IPsec application and rollback failed. Inspect the device through SSH before making further changes.');
    default:
      return _('IPsec settings could not be applied. Review the service status and system log; your draft has been kept.');
  }
}

function copyPeer(peer) {
  return Object.fromEntries(peerFields.map(k => [ k,
    Array.isArray(peer[k]) ? peer[k].slice() : peer[k] ]));
}

// These fields are ASCII-only. Explicitly reject controls and line separators:
// JavaScript's $ anchor alone also matches immediately before a final newline.
function invalidAsciiControl(value) { return /[\x00-\x1f\x7f\u2028\u2029]/.test(value); }
function peerIdValid(value) {
  return typeof value === 'string' && !invalidAsciiControl(value) &&
    /^p[0-7][0-9a-f]{7}$/.test(value) && value !== 'p00000000';
}
function normalizedIdentity(value) { return value.replace(/^@/, '').toLowerCase(); }

function decode(state) {
  if (!state || state.ok !== true) throw failure(operationError(state?.error));
  if (typeof state.revision !== 'string' || !state.revision ||
      [ 'enabled', 'ready', 'eip93', 'manual' ].some(k => typeof state[k] !== 'boolean') ||
      !Array.isArray(state.peers) || state.peers.some(p => !p ||
        !peerIdValid(p.id) || typeof p.enabled !== 'boolean' || typeof p.psk_set !== 'boolean' ||
        [ 'name', 'remote', 'local_id', 'remote_id', 'local_address', 'ike', 'esp' ].some(k => typeof p[k] !== 'string') ||
        !Array.isArray(p.remote_subnets) || p.remote_subnets.some(v => typeof v !== 'string') ||
        !Number.isInteger(p.dpd_delay) || !Number.isInteger(p.mtu) || !peerStates.includes(p.state) ||
        Object.prototype.hasOwnProperty.call(p, 'psk')) ||
      new Set(state.peers.map(p => p.id)).size !== state.peers.length)
    throw failure(_('IPsec service status is unavailable.'));
  // Whitelist the redacted schema: unexpected properties never enter form state.
  return { ok: true, revision: state.revision, enabled: state.enabled,
    ready: state.ready, eip93: state.eip93, manual: state.manual,
    peers: state.peers.map(p => ({ ...copyPeer(p), psk_set: p.psk_set, state: p.state })) };
}

async function applyAccess() {
  // Mixed-ACL pages are writable when any menu dependency grants write access.
  // Only this method's own session ACL may unlock the IPsec editor.
  try { return await checkApplyAccess('ubus', 'relay.ipsec', 'apply') === true; }
  catch (error) { return false; }
}
async function status() {
  const [ state, access ] = await Promise.all([ getConfig(), applyAccess() ]);
  return { ...decode(state), can_apply: access };
}
function canChange(state, agent, readonly) {
  return !!state && state.can_apply === true && state.manual === true &&
    !!agent && agent.managed === false && !readonly;
}

function ipv4(value) {
  if (typeof value !== 'string' || invalidAsciiControl(value) ||
      !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  if (parts.some(n => n > 255)) return null;
  return parts.reduce((n, part) => n * 256 + part, 0);
}
function subnet(value) {
  if (typeof value !== 'string' || invalidAsciiControl(value)) return null;
  const match = /^(.*)\/(0|[1-9][0-9]?)$/.exec(value);
  if (!match) return null;
  const address = ipv4(match[1]), prefix = Number(match[2]);
  if (address == null || prefix < 1 || prefix > 32) return null;
  const width = 2 ** (32 - prefix), first = Math.floor(address / width) * width;
  return { first, last: first + width - 1, prefix };
}
function overlap(a, b) { return a.first <= b.last && b.first <= a.last; }
function unicast(address) {
  return address != null && address >= 0x01000000 && address < 0xe0000000 &&
    Math.floor(address / 0x1000000) !== 127 && Math.floor(address / 0x10000) !== 0xa9fe;
}
function hostValid(value) {
  if (typeof value !== 'string' || invalidAsciiControl(value)) return false;
  if (ipv4(value) != null) return unicast(ipv4(value));
  return value.length <= 253 && !/^[0-9.]+$/.test(value) &&
    value.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part));
}

function validateConfig(config, previous = []) {
  if (!config || typeof config.enabled !== 'boolean' || !Array.isArray(config.peers) || config.peers.length > 64)
    return _('IPsec settings were rejected. Check the peer parameters and address ranges.');
  const ids = new Set(), identities = new Set(), addresses = new Set(), ranges = [];
  for (const peer of config.peers) {
    if (!peer || !peerIdValid(peer.id) || ids.has(peer.id))
      return _('Peer identifiers must be unique. Reload the editor.');
    ids.add(peer.id);
    if (typeof peer.name !== 'string' || !peer.name.length || new TextEncoder().encode(peer.name).length > 64 || /[\x00-\x1f\x7f]/.test(peer.name))
      return _('Give every peer a name of 1 to 64 UTF-8 bytes, without control characters.');
    if (typeof peer.enabled !== 'boolean' || !hostValid(peer.remote))
      return _('Enter a valid peer IPv4 address or DNS hostname, without a port.');
    if (![ peer.local_id, peer.remote_id ].every(v => typeof v === 'string' && !invalidAsciiControl(v) &&
        v !== '0.0.0.0' && v.length <= 128 && /^@?[A-Za-z0-9][A-Za-z0-9_.@-]*$/.test(v) &&
        !/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(v)))
      return _('IKE identities must start with a letter or digit (optionally after @) and contain only letters, digits, dots, @, underscores and hyphens.');
    const remoteIdentity = normalizedIdentity(peer.remote_id);
    if (identities.has(remoteIdentity)) return _('Each peer must have a different remote IKE identity.');
    identities.add(remoteIdentity);
    const local = subnet(ipv4(peer.local_address) != null ? peer.local_address + '/32' : peer.local_address);
    if (!local || local.prefix !== 32 || !unicast(local.first))
      return _('Enter a local tunnel IPv4 address with a /32 prefix.');
    if (addresses.has(local.first)) return _('Local tunnel IPv4 addresses must be different for each peer.');
    addresses.add(local.first);
    if (!Array.isArray(peer.remote_subnets) || !peer.remote_subnets.length || peer.remote_subnets.length > 32)
      return _('Enter from 1 to 32 remote IPv4 subnets.');
    if (ranges.length + peer.remote_subnets.length > 256)
      return _('At most 256 remote IPv4 subnets are allowed across all peers, including disabled peers.');
    for (const value of peer.remote_subnets) {
      const range = subnet(value);
      if (!range) return _('Enter valid IPv4 CIDRs; a default route (/0) is not allowed.');
      if (range.first < 0x01000000 || range.last >= 0xe0000000 ||
          overlap(range, subnet('127.0.0.0/8')) || overlap(range, subnet('169.254.0.0/16')))
        return _('Remote subnets must not contain unspecified, loopback, link-local or multicast addresses.');
      if (ranges.some(r => overlap(r, range)))
        return _('Remote IPv4 subnets must not overlap, including between peers.');
      ranges.push(range);
    }
    const old = previous.find(p => p.id === peer.id);
    if (peer.psk != null && typeof peer.psk !== 'string')
      return _('Enter a preshared key of 16 to 128 UTF-8 bytes.');
    if (peer.psk) {
      const size = new TextEncoder().encode(peer.psk).length;
      if (size < 16 || size > 128 || /[\x00-\x1f\x7f]/.test(peer.psk))
        return _('Enter a preshared key of 16 to 128 UTF-8 bytes without control characters.');
    } else if (!old?.psk_set) return _('A new peer requires a preshared key.');
    if (!ikeProposals.includes(peer.ike) || !espProposals.includes(peer.esp))
      return _('Select a supported IKE and ESP proposal.');
    if (!Number.isInteger(peer.dpd_delay) || peer.dpd_delay < 10 || peer.dpd_delay > 3600)
      return _('DPD interval must be an integer from 10 to 3600 seconds.');
    if (!Number.isInteger(peer.mtu) || peer.mtu < 576 || peer.mtu > 1500)
      return _('MTU must be an integer from 576 to 1500.');
  }
  // Remote-only PSK credentials must never also match another connection's
  // local ID. Shared local IDs are fine as long as they match no remote ID.
  if (config.peers.some(p => identities.has(normalizedIdentity(p.local_id))))
    return operationError('identity_conflict');
  if (config.peers.some(p => addresses.has(ipv4(p.remote))))
    return _('A local tunnel address must not equal an IKE endpoint address.');
  for (const range of ranges) {
    if ([ ...addresses ].some(ip => ip >= range.first && ip <= range.last))
      return _('A remote subnet must not include a local tunnel address.');
    if (config.peers.some(p => { const ip = ipv4(p.remote); return ip != null && ip >= range.first && ip <= range.last; }))
      return _('A remote subnet must not include an IKE endpoint address.');
  }
  return null;
}

function newPeer(peers) {
  let id;
  do {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    // The pinned jshn -> netifd XFRM path only accepts positive INT32 if_ids.
    bytes[0] &= 0x7f;
    id = 'p' + Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
  } while (id === 'p00000000' || peers.some(p => p.id === id));
  return { id, name: '', enabled: true, remote: '', local_id: '', remote_id: '', psk: '',
    local_address: '', remote_subnets: [], ike: ikeProposals[0], esp: espProposals[0], dpd_delay: 30, mtu: 1400 };
}

function createEditor(initial, initialAgent, readonly, coordination = {}) {
  const coordinate = operation => coordination.run ? coordination.run(operation) : operation();
  const editor = { state: initial, agent: initialAgent, readonly: !!readonly, busy: false,
    dirty: false, message: '', onchange: () => {} };
  editor.replace = function(next) {
    this.state = next;
    this.draft = { revision: next?.revision || '', enabled: next?.enabled || false,
      peers: (next?.peers || []).map(p => ({ ...copyPeer(p), psk: '' })) };
    this.dirty = false;
  };
  editor.replace(initial);
  editor.writable = function() { return L.hasViewPermission() && canChange(this.state, this.agent, this.readonly); };
  editor.change = function() { this.dirty = true; this.message = ''; this.onchange('controls'); };
  editor.add = function() {
    if (this.busy || !this.writable() || this.draft.peers.length >= 64) return;
    this.draft.peers.push(newPeer(this.draft.peers));
    this.dirty = true; this.message = ''; this.onchange('peers');
  };
  editor.remove = function(id) {
    if (this.busy || !this.writable()) return;
    this.draft.peers = this.draft.peers.filter(p => p.id !== id);
    this.dirty = true; this.message = ''; this.onchange('peers');
  };
  editor.run = async function(operation) {
    if (this.busy) return false;
    this.busy = true; this.message = ''; this.onchange('controls');
    try { return await operation(); }
    catch (error) {
      this.message = error?.ipsecSafe ? error.message : operationError();
      return false;
    } finally { this.busy = false; this.onchange('controls'); }
  };
  editor.read = async function() {
    try { return await Promise.all([ status(), agentState.status() ]); }
    catch (error) {
      // A failed ownership/status refresh locks mutation controls until the
      // next successful refresh, but never destroys the user's draft.
      this.agent = null;
      throw error;
    }
  };
  editor.refresh = async function(discard = false) {
    return this.run(async () => {
      const [ next, agent ] = await this.read();
      this.agent = agent;
      if (!this.dirty || discard) { this.replace(next); this.onchange('replace'); }
      else {
        this.state = next;
        if (next.revision !== this.draft.revision) this.message = operationError('stale_revision');
      }
      return true;
    });
  };
  editor.apply = async function() {
    if (this.busy || !this.writable() || !this.dirty) return false;
    const config = { revision: this.draft.revision, enabled: this.draft.enabled,
      peers: this.draft.peers.map(peer => ({ ...copyPeer(peer),
        local_address: ipv4(peer.local_address) != null ? peer.local_address + '/32' : peer.local_address,
        ...(peer.psk ? { psk: peer.psk } : {}) })) };
    const validation = validateConfig(config, this.state?.peers);
    if (validation) { this.message = validation; this.onchange('controls'); return false; }
    return this.run(() => coordinate(async () => {
      const [ current, agent ] = await this.read();
      this.agent = agent;
      if (!canChange(current, agent, this.readonly)) {
        this.state = current;
        throw failure(current.can_apply !== true || this.readonly ?
          _('IPsec settings are read-only for this session.') : operationError('managed'));
      }
      if (current.revision !== config.revision) {
        this.state = current;
        throw failure(operationError('stale_revision'));
      }
      const next = { ...decode(await applyConfig(config)), can_apply: await applyAccess() };
      this.replace(next); this.onchange('replace');
      this.message = _('IPsec settings applied. A ready IKE service does not by itself mean every tunnel is connected.');
      return true;
    }));
  };
  return editor;
}

function stateText(state) {
  return state === 'established' ? _('Connected') : state === 'connecting' ? _('Connecting') :
    state === 'disabled' ? _('Disabled') : state === 'down' ? _('Not connected') : _('Not yet applied');
}

function render(state, agent, readonly, coordination = {}) {
  const editor = createEditor(state, agent, readonly, coordination);
  const peerList = E('div', { class: 'ar-ipsec-peers' }, []);
  const serviceStatus = E('p', { class: 'ar-muted', 'aria-live': 'polite' });
  const permissionStatus = E('p', { class: 'ar-muted', 'aria-live': 'polite' });
  const hardwareStatus = E('p', { class: 'ar-muted' });
  const message = E('p', { class: 'ar-ipsec-message', role: 'status', 'aria-live': 'polite' });
  const pending = E('span', { class: 'ar-muted ar-ipsec-pending' });
  const control = (type, attrs = {}, children) => E(type, { 'data-ipsec-edit': '', ...attrs }, children);
  const field = (id, title, input, hint) => E('div', { class: 'cbi-value' }, [
    E('label', { class: 'cbi-value-title', for: id }, title),
    E('div', { class: 'cbi-value-field' }, [ input,
      hint ? E('div', { class: 'cbi-value-description' }, hint) : '' ])
  ]);
  const globalId = 'relay-ipsec-enabled';
  const globalToggle = control('input', { type: 'checkbox', id: globalId,
    change: ev => { editor.draft.enabled = ev.target.checked; editor.change(); } });
  const addButton = control('button', { type: 'button', class: 'btn cbi-button-add', click: () => editor.add() }, _('Add peer'));
  const saveButton = control('button', { type: 'submit', class: 'btn cbi-button-apply important' });
  const discardButton = E('button', { type: 'button', class: 'btn', click: () => editor.refresh(true) }, _('Discard changes'));
  const refreshButton = E('button', { type: 'button', class: 'btn', click: () => editor.refresh() }, _('Refresh status'));

  function peerCard(peer) {
    const fieldId = key => 'relay-ipsec-' + peer.id + '-' + key;
    function text(key, title, hint, type = 'text', placeholder = '') {
      const input = control('input', { type, id: fieldId(key), class: 'cbi-input-text',
        value: peer[key] ?? '', placeholder,
        autocomplete: type === 'password' ? 'new-password' : 'off', spellcheck: 'false',
        input: ev => { peer[key] = type === 'number' ? Number(ev.target.value) : ev.target.value; editor.change(); }
      });
      if (type === 'password') input.setAttribute('data-lpignore', 'true');
      return field(fieldId(key), title, input, hint);
    }
    function choice(key, title, values) {
      const select = control('select', { id: fieldId(key), class: 'cbi-input-select',
        change: ev => { peer[key] = ev.target.value; editor.change(); } });
      for (const value of values) select.appendChild(E('option', { value, selected: peer[key] === value ? '' : null }, value));
      return field(fieldId(key), title, select);
    }
    const savedPeer = editor.state?.peers.find(p => p.id === peer.id);
    return E('section', { class: 'ar-ipsec-peer cbi-section', 'data-peer-id': peer.id }, [
      E('div', { class: 'ar-ipsec-peer-head' }, [
        E('h3', { 'data-ipsec-name': peer.id }, [ peer.name || _('New peer') ]),
        E('span', { class: 'ar-muted', 'data-ipsec-status': peer.id }, stateText(savedPeer?.state)),
        control('button', { type: 'button', class: 'btn cbi-button-remove',
          'aria-label': _('Remove peer'), click: () => editor.remove(peer.id) }, _('Remove peer'))
      ]),
      field(fieldId('enabled'), _('Enable peer'), control('input', { type: 'checkbox', id: fieldId('enabled'),
        checked: peer.enabled ? '' : null,
        change: ev => { peer.enabled = ev.target.checked; editor.change(); } })),
      text('name', _('Name'), null),
      text('remote', _('Endpoint host'), _('IPv4 address or DNS hostname of the remote IKE peer.'), 'text', 'vpn.example.com'),
      text('local_id', _('Local IKE identity'), null, 'text', 'relay-node'),
      text('remote_id', _('Remote IKE identity'), null, 'text', 'cloud-node'),
      text('psk', _('Preshared key'), savedPeer?.psk_set ?
        _('A key is stored. Leave this field blank to keep it; enter a new key to replace it.') :
        _('Required for a new peer. Use a random key of 16 to 128 UTF-8 bytes.'), 'password'),
      text('local_address', _('Local tunnel IPv4 address'), _('Use a different /32 address for every peer.'), 'text', '10.78.0.2/32'),
      field(fieldId('remote_subnets'), _('Remote IPv4 subnets'), control('textarea', {
        id: fieldId('remote_subnets'), class: 'cbi-input-textarea', rows: 3,
        placeholder: '10.78.0.1/32',
        input: ev => { peer.remote_subnets = ev.target.value.split(/[\s,]+/).filter(Boolean); editor.change(); }
      }, [ peer.remote_subnets.join('\n') ]), _('One IPv4 CIDR per line. No default route, overlapping peer routes or WireGuard routes.')),
      E('details', { class: 'ar-ipsec-advanced' }, [
        E('summary', {}, _('Advanced parameters')),
        choice('ike', _('IKE proposal'), ikeProposals),
        choice('esp', _('ESP proposal'), espProposals),
        text('dpd_delay', _('DPD interval (seconds)'), null, 'number'),
        text('mtu', _('Tunnel MTU'), null, 'number'),
        E('p', { class: 'ar-muted' }, _('NAT traversal is automatic. AES-CBC/SHA-256 is the EIP-93 test profile; AES-GCM may use CPU crypto.'))
      ])
    ]);
  }

  // Keep validation in validateConfig(), which reports errors in the visible
  // status area. Native number-input step validation can otherwise suppress
  // submit entirely when an invalid advanced field is inside closed details.
  const form = E('form', { id: 'cbi-relay-ipsec', class: 'ar-ipsec-config ar-wg-config', novalidate: '',
    submit: ev => { ev.preventDefault(); editor.apply(); } }, [
    field(globalId, _('Enable IPsec'), globalToggle), serviceStatus, permissionStatus, hardwareStatus,
    E('p', { class: 'ar-muted' }, _('Changes are applied only when you save. Disabled peers keep protected routes; removing a peer removes its routes.')),
    E('p', { class: 'ar-muted' }, _('Editor resource limits: 64 peers, 32 subnets per peer, 256 subnets total including disabled peers; not protocol or hardware limits.')),
    peerList, addButton,
    E('div', { class: 'ar-modal-actions' }, [ pending, refreshButton, discardButton, saveButton ]), message
  ]);
  const panel = E('section', { class: 'ar-wg-editor ar-ipsec-editor' }, [ E('h2', {}, _('IPsec (IKEv2)')), form ]);

  function update(reason) {
    if (reason === 'replace' || reason === 'peers') {
      globalToggle.checked = editor.draft.enabled;
      L.dom.content(peerList, editor.draft.peers.length ? editor.draft.peers.map(peerCard) : [
        E('p', { class: 'ar-muted ar-ipsec-empty' }, _('No IPsec peers configured. Add a peer to create a tunnel.'))
      ]);
    }
    const writable = editor.writable();
    // Status refreshes must not rebuild inputs or lose drafts/focus.
    peerList.querySelectorAll('[data-ipsec-status]').forEach(node => {
      node.textContent = stateText(editor.state?.peers.find(p => p.id === node.getAttribute('data-ipsec-status'))?.state);
    });
    peerList.querySelectorAll('[data-ipsec-name]').forEach(node => {
      node.textContent = editor.draft.peers.find(p => p.id === node.getAttribute('data-ipsec-name'))?.name || _('New peer');
    });
    form.querySelectorAll('[data-ipsec-edit]').forEach(input => { input.disabled = editor.busy || !writable; });
    saveButton.disabled = editor.busy || !writable || !editor.dirty;
    addButton.disabled = editor.busy || !writable || editor.draft.peers.length >= 64;
    saveButton.textContent = editor.busy ? _('Applying…') : _('Save & Apply');
    discardButton.disabled = editor.busy || !editor.dirty;
    refreshButton.disabled = editor.busy;
    const current = editor.state;
    serviceStatus.textContent = !current ? _('IPsec service status is unavailable.') :
      current.ready ? _('IKE service ready') : current.enabled ? _('IKE service not responding') : _('Disabled');
    permissionStatus.textContent = !current ? '' :
      current.can_apply !== true || editor.readonly || !L.hasViewPermission() ?
        _('IPsec settings are read-only for this session.') :
      !canChange(current, editor.agent, editor.readonly) ? _('IPsec is managed by AirRoute Agent or unavailable.') : '';
    permissionStatus.hidden = !permissionStatus.textContent;
    hardwareStatus.textContent = current ? (current.eip93 ?
      _('EIP-93 driver registered; hardware use depends on the negotiated ESP algorithm.') : _('EIP-93 driver not registered.')) : '';
    pending.textContent = editor.dirty ? _('Unsaved changes') : '';
    message.textContent = editor.message;
    form.setAttribute('aria-busy', editor.busy ? 'true' : 'false');
  }
  editor.onchange = update;
  update('replace');
  return panel;
}

return baseclass.extend({ decode, status, canChange, validateConfig, createEditor, render });
