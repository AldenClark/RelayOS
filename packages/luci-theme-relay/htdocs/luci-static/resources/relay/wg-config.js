'use strict';
'require baseclass';
'require form';
'require uci';
'require ui';
'require rpc';
'require poll';
'require relay.agent-state as agentState';

const publicKey = rpc.declare({ object: 'luci.wireguard', method: 'getPublicAndPrivateKeyFromPrivate', params: [ 'privkey' ], expect: { keys: {} } });
const access = rpc.declare({ object: 'session', method: 'access', params: [ 'scope', 'object', 'function' ], expect: { access: false } });
const interfaces = rpc.declare({ object: 'network.interface', method: 'dump' });
const wgInstances = rpc.declare({ object: 'luci.wireguard', method: 'getWgInstances', reject: true });

function peerStatus(instances, name, key, disabled) {
  if (disabled) return _('Peer disabled');
  if (!instances || typeof instances !== 'object' || Array.isArray(instances)) return _('Status unavailable');
  const peers = instances[name]?.peers;
  const peer = Array.isArray(peers) && peers.find(entry => entry.public_key === key);
  if (!peer) return _('Peer not active');
  const timestamp = Number(peer.latest_handshake);
  if (timestamp === 0) return _('No handshake yet');
  const age = Date.now() / 1000 - timestamp;
  if (!Number.isFinite(age) || age < 0) return _('Status unavailable');
  return age < 180 ? _('Recent handshake') : _('No recent handshake');
}

function keyValid(_id, value) {
  return !value || (typeof value === 'string' && value.length === 44 &&
    /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(value) && !/^A{43}=$/.test(value))
    ? true : _('Enter a valid WireGuard key.');
}

function list(value) { return Array.isArray(value) ? value : value ? [ value ] : []; }
const peerDefaults = { route_allowed_ips: '1', persistent_keepalive: '25' };

function listenerRule(name) {
  const id = 'airrelay_wg_' + name;
  const rule = uci.get('firewall', id);
  return rule?.['.type'] === 'rule' && rule.name === 'AirRelay WireGuard ' + name ? id : null;
}

function concealed(option) {
  option.password = true;
  const render = option.renderWidget;
  option.renderWidget = function(...args) {
    const node = render.apply(this, args);
    node.querySelectorAll('.control-group > button').forEach(button => button.remove());
    return node;
  };
}

function ipv4(value) {
  if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  return parts.some(n => n > 255) ? null : parts.reduce((n, octet) => n * 256 + octet, 0);
}

// LuCI accepts both numeric and dotted masks, including zero-padded forms.
// Parse them numerically so /00 cannot bypass the default-route guard.
function subnet(value, mask) {
  if (typeof value !== 'string') return null;
  const parts = value.split('/'), address = ipv4(parts[0]);
  if (parts.length > 2 || address == null) return null;
  const suffix = parts.length === 2 ? parts[1] : mask == null ? '32' : String(mask);
  let prefix;
  if (/^\d{1,2}$/.test(suffix)) prefix = Number(suffix);
  else {
    const dotted = ipv4(suffix);
    if (dotted == null) return null;
    const bits = dotted.toString(2).padStart(32, '0');
    if (!/^1*0*$/.test(bits)) return null;
    prefix = bits.indexOf('0');
    if (prefix < 0) prefix = 32;
  }
  if (prefix > 32) return null;
  const size = 2 ** (32 - prefix), first = Math.floor(address / size) * size;
  return { address, first, last: first + size - 1, prefix };
}
function addressText(address) {
  return [24, 16, 8, 0].map(shift => (address >>> shift) & 255).join('.');
}
function prefixValid(_id, value) {
  return list(value).every(value => subnet(value)) ? true : _('Enter a valid IPv4 address or prefix.');
}
function ipv4List(option) {
  // The pinned ip4addr validator leaves its value set to the numeric mask
  // before invoking custom validation. Validate the original string here.
  option.datatype = 'string';
  option.validate = prefixValid;
  const isValid = option.isValid, getValidationError = option.getValidationError;
  option.isValid = function(id) {
    const input = this.getUIElement(id)?.node?.querySelector('.add-item > input[type="text"]');
    // Native DynamicList.getValue() omits an invalid pending item, so its
    // aggregate validator alone may accept the remaining old values.
    return isValid.call(this, id) && !(input?.value.trim() && input.classList.contains('cbi-input-invalid'));
  };
  option.getValidationError = function(id) {
    const input = this.getUIElement(id)?.node?.querySelector('.add-item > input[type="text"].cbi-input-invalid');
    return input?.value.trim() ? input.getAttribute('data-tooltip') : getValidationError.call(this, id);
  };
  // LuCI accepts dotted masks and zero-padded octets, while netifd and wg
  // consume numeric CIDR prefixes and canonical address literals.
  option.forcewrite = true;
  option.write = function(id, value) {
    uci.set('network', id, this.option, list(value).map(value => {
      const net = subnet(value);
      return addressText(net.address) + '/' + net.prefix;
    }));
  };
}
function overlap(a, b) { return a && b && a.first <= b.last && b.first <= a.last; }
function defaultRoute(value) { return subnet(value)?.prefix === 0; }
function unicast(net) {
  return net && net.first >= 16777216 && net.last < 3758096384 &&
    !overlap(net, subnet('127.0.0.0/8')) && !overlap(net, subnet('169.254.0.0/16'));
}
function routeError() { return new Error(_('WireGuard addresses or routes conflict with another tunnel or the management network.')); }
function tunnelDisabled(value) { return value === '1' || value === 'true'; }
function configuredSubnet(value, mask, wireguard) {
  if (typeof value !== 'string') throw routeError();
  const parts = value.split('/');
  if (parts[0].includes(':')) return null;
  if (parts.length > 2 || ipv4(parts[0]) == null) throw routeError();
  const suffix = parts.length === 2 ? parts[1] : mask == null ? '32' : String(mask);
  let prefix;
  // Native static netifd masks use strtoul(..., 0); the WireGuard ucode
  // protocol uses decimal int(). This is committed environment input, not
  // the stricter syntax accepted by our editable WireGuard fields.
  if (wireguard) prefix = /^\d+$/.test(suffix) ? Number(suffix) : NaN;
  else if (/^0[xX][0-9a-fA-F]+$/.test(suffix)) prefix = Number(suffix);
  else if (/^0[0-7]*$/.test(suffix)) prefix = parseInt(suffix, 8);
  else if (/^[1-9]\d*$/.test(suffix)) prefix = Number(suffix);
  else prefix = suffix.includes('.') ? subnet('0.0.0.0/' + suffix)?.prefix : NaN;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw routeError();
  return subnet(parts[0] + '/' + prefix);
}
function configuredList(value, wireguard) {
  // UCI list items are already separate; scalar array options are split by
  // libuci on spaces/tabs, or by wireguard.uc on whitespace.
  return typeof value === 'string' ? value.split(wireguard ? /\s+/ : /[ \t]+/).filter(Boolean) : list(value);
}
function firewallEnabled(section) {
  return section.enabled == null || ['1', 'on', 'true', 'yes'].includes(String(section.enabled));
}
function usableZone(zone) {
  if (!zone) return;
  if (!firewallEnabled(zone))
    throw new Error(_('The management and tunnel firewall zones must be enabled.'));
  const family = String(zone.family ?? 'any');
  if (!['any', 'all', '*', 'inet'].includes(family) && !family.includes('4'))
    throw new Error(_('The management and tunnel firewall zones must support IPv4.'));
}

function validate(names, environment = {}) {
  const selected = new Set(names.filter(name => uci.get('network', name, 'proto') === 'wireguard'));
  const reserved = [], locals = [], remotes = [], endpoints = [], ports = new Set();
  const reserve = (value, mask, route = false) => {
    const net = subnet(value, mask);
    if (net && (net.prefix || !route)) reserved.push(net);
  };
  const reserveConfigured = (value, mask, wireguard, route = false) => {
    const net = configuredSubnet(value, mask, wireguard);
    if (net && (net.prefix || !route)) reserved.push(net);
  };
  for (const section of uci.sections('network')) {
    if (section['.type'] === 'interface' && !selected.has(section['.name'])) {
      for (const address of configuredList(section.ipaddr)) reserveConfigured(address, section.netmask, false);
      for (const address of configuredList(section.addresses, section.proto === 'wireguard'))
        reserveConfigured(address, null, section.proto === 'wireguard');
    }
    if (section['.type'] === 'route' && !selected.has(section.interface) && section.target && section.target !== 'default')
      reserveConfigured(section.target, section.netmask, false, true);
  }
  for (const link of environment.interfaces || []) {
    if (selected.has(link.interface)) continue;
    // Static interfaces are validated from the intended draft above. A DHCP
    // lease has no UCI address, so also inspect current netifd addresses/routes.
    if (uci.get('network', link.interface, 'proto') === 'static') continue;
    for (const address of link['ipv4-address'] || []) reserve(address.address, address.mask);
    for (const route of link.route || []) reserve(route.target, route.mask, true);
  }
  for (const name of selected) {
    const section = uci.get('network', name);
    const addresses = list(section.addresses);
    if (!addresses.length) throw new Error(_('Enter a tunnel IPv4 address.'));
    for (const value of addresses) {
      const net = subnet(value);
      if (!net || !net.prefix || !unicast(net)) throw routeError();
      locals.push({ ...net, name });
    }
    const port = section.listen_port ? Number(section.listen_port) : 0;
    if (port && !tunnelDisabled(section.disabled)) {
      if (ports.has(port)) throw new Error(_('Enabled WireGuard tunnels must use different listen ports.'));
      ports.add(port);
    }
    const peers = uci.sections('network', 'wireguard_' + name);
    if (!peers.some(peer => peer.disabled !== '1') && !tunnelDisabled(section.disabled))
      throw new Error(_('Keep at least one enabled peer.'));
    const keys = new Set();
    for (const peer of peers) {
      if (peer.public_key && keys.has(peer.public_key))
        throw new Error(_('Each peer in a WireGuard tunnel must have a different public key.'));
      if (peer.public_key) keys.add(peer.public_key);
      const endpoint = ipv4(peer.endpoint_host);
      if (endpoint != null) endpoints.push({ first: endpoint, last: endpoint });
      for (const value of list(peer.allowed_ips)) {
        const net = subnet(value);
        if (net?.prefix === 0) throw new Error(_('Keep the management default route outside WireGuard.'));
        if (!unicast(net)) throw routeError();
        remotes.push({ ...net, name, peer: peer['.name'] });
      }
    }
  }
  for (const [i, local] of locals.entries()) {
    if (reserved.some(net => overlap(local, net))) throw routeError();
    for (const other of locals.slice(i + 1))
      if (local.address === other.address || (local.name !== other.name && overlap(local, other))) throw routeError();
  }
  for (const [i, remote] of remotes.entries()) {
    if (reserved.some(net => overlap(remote, net)) || endpoints.some(net => overlap(remote, net))) throw routeError();
    for (const local of locals)
      if ((local.name !== remote.name && overlap(local, remote)) ||
          (local.address >= remote.first && local.address <= remote.last)) throw routeError();
    for (const other of remotes.slice(i + 1))
      if ((remote.name !== other.name || remote.peer !== other.peer) && overlap(remote, other)) throw routeError();
  }
}

async function writable() {
  const permissions = await Promise.all([ access('uci', 'network', 'write'), access('uci', 'firewall', 'write') ]);
  return L.hasViewPermission() && permissions.every(value => value === true);
}
async function assertEditable() {
  await agentState.assertManual();
  if (!await writable()) throw new Error(_('WireGuard settings are read-only.'));
}
async function edit(map, operation) {
  try { return await (map._coordination?.run ? map._coordination.run(operation) : operation()); }
  catch (error) {
    ui.addNotification(null, E('p', {}, [ error?.message || _('Unable to update the WireGuard draft.') ]), 'error');
    return false;
  }
}
async function changeDraft(map, change) {
  map.checkDepends();
  await map.parse();
  change();
  // A native map.save() sends every loaded UCI package to the router. Keep
  // structural edits local until the shared Save & Apply validates the draft;
  // partial RPC failure must not leave hidden additions or deletions to retry.
  await map.load();
  return map.renderContents();
}
async function prepare(map) {
  await assertEditable();
  const links = (await interfaces())?.interface;
  if (!Array.isArray(links)) throw new Error(_('Unable to verify current network routes.'));
  provision(map._tunnelNames, { interfaces: links.filter(link => !map._removedTunnels?.has(link.interface)) });
}

// Keep existing assignments and user firewall rules. Only provision missing
// exit-node membership/forwarding and our own explicit UDP listener rules.
function provision(names, environment = {}) {
  names = names.filter(name => uci.get('network', name, 'proto') === 'wireguard');
  if (!names.length) return;
  const zones = uci.sections('firewall', 'zone');
  const uplinks = zones.filter(z => list(z.network).includes('lan'));
  if (!uplinks.length) throw new Error(_('No firewall zone is assigned to the management interface.'));
  const uplink = uplinks[0];
  const ambiguous = zone => zone && (!zone.name || zones.filter(other => other.name === zone.name).length !== 1);
  if (uplinks.length !== 1 || ambiguous(uplink))
    throw new Error(_('Tunnel and management firewall zones must be unambiguous.'));
  usableZone(uplink);
  // Preflight all names and routes before changing any firewall state.
  validate(names, environment);
  for (const name of names) {
    const memberships = zones.filter(zone => list(zone.network).includes(name));
    const zone = memberships[0] || zones.find(zone => zone.name === 'tunnel' || zone.name === 'airrelay_wg');
    if (memberships.length > 1 || ambiguous(zone))
      throw new Error(_('Tunnel and management firewall zones must be unambiguous.'));
    usableZone(zone);
    if (zone && zone.name !== uplink.name) {
      const forwards = uci.sections('firewall', 'forwarding').filter(f => f.src === zone.name && f.dest === uplink.name);
      if (forwards.length && !forwards.some(firewallEnabled))
        throw new Error(_('The firewall forwarding from the tunnel to the management zone is disabled.'));
    }
    const id = 'airrelay_wg_' + name;
    const existing = uci.get('firewall', id);
    if (existing && !listenerRule(name))
      throw new Error(_('A firewall rule name is already in use.'));
    if (uci.sections('network', 'wireguard_' + name).some(peer => list(peer.allowed_ips).some(defaultRoute)))
      throw new Error(_('Keep the management default route outside WireGuard.'));
  }
  for (const name of names) {
    if (uci.get('network', name, 'proto') !== 'wireguard') continue;
    for (const peer of uci.sections('network', 'wireguard_' + name))
      for (const [key, value] of Object.entries(peerDefaults))
        uci.set('network', peer['.name'], key, value);
    let zone = uci.sections('firewall', 'zone').find(z => list(z.network).includes(name));
    if (!zone) {
      zone = uci.sections('firewall', 'zone').find(z => z.name === 'tunnel' || z.name === 'airrelay_wg');
      if (!zone) {
        const id = uci.add('firewall', 'zone');
        for (const [key, value] of Object.entries({ name: 'airrelay_wg', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' }))
          uci.set('firewall', id, key, value);
        zone = { '.name': id, name: 'airrelay_wg', network: [] };
      }
      uci.set('firewall', zone['.name'], 'network', [ ...list(zone.network), name ]);
    }
    if (zone.name !== uplink.name) {
      if (!uci.sections('firewall', 'forwarding').some(f => f.src === zone.name && f.dest === uplink.name)) {
        const id = uci.add('firewall', 'forwarding');
        uci.set('firewall', id, 'src', zone.name);
        uci.set('firewall', id, 'dest', uplink.name);
      }
      uci.set('firewall', uplink['.name'], 'masq', '1');
    }
    const id = 'airrelay_wg_' + name;
    const port = uci.get('network', name, 'listen_port');
    if (Number(port) > 0 && uplink.input !== 'ACCEPT') {
      const existing = uci.get('firewall', id);
      if (!existing) uci.add('firewall', 'rule', id);
      for (const [key, value] of Object.entries({ name: 'AirRelay WireGuard ' + name, src: uplink.name,
        proto: 'udp', dest_port: port, target: 'ACCEPT', family: 'ipv4',
        enabled: tunnelDisabled(uci.get('network', name, 'disabled')) ? '0' : '1' }))
        uci.set('firewall', id, key, value);
    }
    else if (listenerRule(name))
      uci.remove('firewall', id);
  }
}

function fields(map, name) {
  const section = map.section(form.NamedSection, name, 'interface', name);
  section.addremove = true;
  section.delbtntitle = _('Delete interface');
  section.handleRemove = () => ui.showModal(_('Delete WireGuard interface?'), [
    E('p', {}, _('The interface %s and its peers will be removed when you save and apply.').format(name)),
    E('div', { class: 'ar-modal-actions' }, [
      E('button', { type: 'button', class: 'btn', click: () => ui.hideModal() }, _('Cancel')),
      E('button', {
        type: 'button', class: 'btn cbi-button cbi-button-remove',
        click: ui.createHandlerFn(null, async () => {
          ui.hideModal();
          return removeInterface(map, section, name);
        })
      }, _('Delete interface'))
    ])
  ]);
  let o = section.option(form.Flag, 'disabled', _('Enable tunnel'));
  o.enabled = '0'; o.disabled = '1'; o.default = '0'; o.rmempty = false;
  o.load = id => tunnelDisabled(uci.get('network', id, 'disabled')) ? '1' : '0';
  o = section.option(form.Value, 'private_key', _('Private key'));
  concealed(o); o.rmempty = false; o.validate = keyValid;
  o = section.option(form.Value, '_public_key', _('Local public key'));
  o.readonly = true;
  o.load = async () => {
    const key = uci.get('network', name, 'private_key');
    return key ? L.resolveDefault(publicKey(key).then(pair => pair.pub || ''), '') : '';
  };
  o.write = o.remove = () => {};
  const pub = o;
  let keyRequest = 0;
  section.getOption('private_key').onchange = async function(_event, id, value) {
    const request = ++keyRequest;
    pub.getUIElement(id)?.setValue('');
    if (value && keyValid(id, value) === true) {
      try {
        const pair = await publicKey(value);
        if (request === keyRequest) pub.getUIElement(id)?.setValue(pair.pub || '');
      }
      catch (_err) { /* A failed derivation leaves the public key blank. */ }
    }
  };
  o = section.option(form.DynamicList, 'addresses', _('Tunnel IPv4 addresses'));
  ipv4List(o); o.rmempty = false; o.placeholder = '10.77.0.2/32';
  o = section.option(form.Value, 'listen_port', _('Listen port'));
  o.datatype = 'port'; o.placeholder = _('Automatic');
  o = section.option(form.SectionValue, '_peers', form.TypedSection, 'wireguard_' + name, _('Peers'));
  const peers = o.subsection;
  peers.anonymous = true; peers.addremove = true; peers.addbtntitle = _('Add peer');
  peers.handleAdd = function() { return edit(map, async () => {
    await assertEditable();
    return changeDraft(map, () => {
      const id = uci.add('network', 'wireguard_' + name);
      for (const [key, value] of Object.entries(peerDefaults)) uci.set('network', id, key, value);
    });
  }); };
  const renderPeers = peers.renderContents;
  peers.renderContents = function(ids, nodes) {
    const node = renderPeers.call(this, ids, nodes);
    if (ids.length <= 1)
      node.querySelectorAll('.cbi-section-remove').forEach(buttons => buttons.remove());
    node.querySelectorAll(':scope > .cbi-section-node').forEach((row, index) => {
      const action = row.previousElementSibling;
      const fallback = _('Peer %d').format(index + 1);
      const title = E('h4', { 'data-default-title': fallback }, [uci.get('network', ids[index], 'description')?.trim() || fallback]);
      const heading = E('div', { class: 'ar-wg-heading' }, title);
      if (action?.classList.contains('cbi-section-remove')) heading.appendChild(action);
      row.prepend(heading);
    });
    return node;
  };
  peers.handleRemove = function(id) { return edit(map, async () => {
    await assertEditable();
    if (this.cfgsections().length <= 1) throw new Error(_('Keep at least one peer.'));
    // Exclude only the removal target while parsing: an incomplete new peer
    // may be deleted, but invalid remaining fields must not silently stage a
    // deletion when save rejects and leaves the old row visible.
    const previousFilter = this.filter;
    this.filter = section => section !== id && (!previousFilter || previousFilter.call(this, section));
    try { return await changeDraft(map, () => uci.remove('network', id)); }
    finally { this.filter = previousFilter; }
  }); };
  o = peers.option(form.Flag, 'disabled', _('Enable peer'));
  o.enabled = '0'; o.disabled = '1'; o.default = '0'; o.rmempty = false;
  o.load = id => uci.get('network', id, 'disabled') === '1' ? '1' : '0';
  o = peers.option(form.Value, 'description', _('Name'));
  o.onchange = function(_event, id, value) {
    const title = this.getUIElement(id)?.node.closest('.cbi-section-node')?.querySelector('h4[data-default-title]');
    if (title) title.textContent = value?.trim() || title.dataset.defaultTitle;
  };
  o = peers.option(form.DummyValue, '_status', _('Connection status'));
  o.renderWidget = id => E('span', { class: 'ar-pill', 'data-wg-status': name,
    'data-wg-peer': id }, _('Checking…'));
  o = peers.option(form.Value, 'public_key', _('Peer public key'));
  o.rmempty = false; o.validate = keyValid;
  o = peers.option(form.Value, 'preshared_key', _('Preshared key'));
  concealed(o); o.validate = keyValid;
  o = peers.option(form.Value, 'endpoint_host', _('Endpoint host'));
  o.datatype = 'host'; o.forcewrite = true;
  o.write = function(id, value) {
    const address = ipv4(value);
    uci.set('network', id, 'endpoint_host', address == null ? value : addressText(address));
  };
  o = peers.option(form.Value, 'endpoint_port', _('Endpoint port'));
  o.datatype = 'and(port,range(1,65535))';
  o = peers.option(form.DynamicList, 'allowed_ips', _('Allowed IPv4 addresses'));
  ipv4List(o); o.rmempty = false; o.placeholder = '10.77.0.1/32';
  o.validate = function(id, value) {
    if (list(value).some(defaultRoute))
      return _('Keep the management default route outside WireGuard.');
    return prefixValid(id, value);
  };
  for (const option of section.children.slice(1)) {
    option.depends('disabled', '0');
    option.retain = true;
  }
  // SectionValue parses its nested section even when its wrapper is hidden.
  const peerOption = section.getOption('_peers');
  const parsePeers = peerOption.parse;
  peerOption.parse = function(id) {
    if (this.isActive(id)) return parsePeers.call(this, id);
  };
}

function removeInterface(map, section, name) {
  return edit(map, async () => {
    await assertEditable();
    const index = map.children.indexOf(section);
    if (index < 0) return;
    // Save edits to the remaining interfaces even if the deleted form is incomplete.
    const parse = section.parse;
    section.parse = () => Promise.resolve();
    try {
      return await changeDraft(map, () => {
        for (const peer of uci.sections('network', 'wireguard_' + name))
          uci.remove('network', peer['.name']);
        uci.remove('network', name);
        for (const zone of uci.sections('firewall', 'zone')) {
          const networks = configuredList(zone.network);
          if (!networks.includes(name)) continue;
          const remaining = networks.filter(network => network !== name);
          uci.set('firewall', zone['.name'], 'network', remaining.length ? remaining : null);
        }
        const rule = listenerRule(name);
        if (rule) uci.remove('firewall', rule);
        map._removedTunnels.add(name);
        map._tunnelNames.splice(index, 1);
        map.children.splice(index, 1);
      });
    }
    finally { section.parse = parse; }
  });
}

function addInterface(map) {
  return edit(map, async () => {
    await assertEditable();
    return changeDraft(map, () => {
      let i = 0;
      let name;
      do {
        name = 'wg' + i++;
      } while (map._removedTunnels.has(name) || uci.get('network', name) || uci.sections('network', 'wireguard_' + name).length);
      uci.add('network', 'interface', name);
      uci.set('network', name, 'proto', 'wireguard');
      uci.set('network', name, 'tunlink', 'lan');
      if (!map._tunnelNames.length) uci.set('network', name, 'listen_port', '51820');
      map._tunnelNames.push(name);
      fields(map, name);
    });
  });
}

async function render(options = {}) {
  const names = uci.sections('network', 'interface').filter(s => s.proto === 'wireguard').map(s => s['.name']);
  const map = new form.Map('network');
  map._tunnelNames = names;
  map._removedTunnels = new Set();
  map.chain('firewall');
  map.readonly = !await writable().catch(() => false);
  map._apply = options.onApply;
  map._coordination = options.coordination || {};
  options.onMap?.(map);
  for (const name of names) fields(map, name);
  // Keep map identity distinct from the management-interface form.
  const original = map.renderContents;
  const refresh = async root => {
    const indicators = root.querySelectorAll('[data-wg-status]');
    if (!indicators.length) return;
    const instances = await L.resolveDefault(wgInstances(), null);
    for (const node of indicators) {
      const { wgStatus: name, wgPeer: id } = node.dataset;
      const peer = uci.get('network', id);
      const status = peerStatus(instances, name, peer?.public_key, peer?.disabled === '1');
      if (node.textContent !== status) node.textContent = status;
      node.classList.toggle('is-up', status === _('Recent handshake'));
    }
  };
  map.renderContents = function(...args) {
    for (const section of this.children) section.hidetitle = names.length === 1;
    return Promise.resolve(original.apply(this, args)).then(node => {
      node.id = 'cbi-relay-wireguard';
      node.classList.add('ar-wg-config');
      const heading = E('div', { class: 'ar-wg-heading' }, E('h2', {}, _('WireGuard')));
      for (const card of node.querySelectorAll(':scope > .cbi-section')) {
        const title = card.querySelector(':scope > h3');
        const action = card.querySelector(':scope > .cbi-section-remove');
        if (title) {
          const row = E('div', { class: 'ar-wg-heading' }, title);
          if (action) row.appendChild(action);
          card.prepend(row);
        }
        else if (action) heading.appendChild(action);
      }
      node.prepend(heading);
      const actions = E('div', { class: 'ar-wg-actions' }, [
        E('button', {
          type: 'button', class: 'btn cbi-button', disabled: this.readonly || null,
          click: ui.createHandlerFn(null, () => addInterface(this))
        }, _('Add interface')),
        names.length || this._removedTunnels.size ? E('button', {
          type: 'button', class: 'btn cbi-button cbi-button-apply important', disabled: this.readonly || null,
          click: ui.createHandlerFn(null, async () => {
            if (this._apply) return this._apply(this);
            await this.save(() => prepare(this));
            return ui.changes.apply(true);
          })
        }, _('Save & Apply')) : ''
      ]);
      node.appendChild(actions);
      void refresh(node);
      return node;
    });
  };
  const node = await map.render();
  const update = () => node.isConnected ? refresh(node) : poll.remove(update);
  poll.add(update, 10);
  return E('section', { class: 'ar-wg-editor' }, node);
}

return baseclass.extend({ keyValid, subnet, validate, provision, prepare, render });
