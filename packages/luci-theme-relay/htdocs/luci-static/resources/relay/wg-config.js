'use strict';
'require baseclass';
'require form';
'require uci';
'require ui';
'require rpc';
'require relay.agent-state as agentState';

const publicKey = rpc.declare({ object: 'luci.wireguard', method: 'getPublicAndPrivateKeyFromPrivate', params: [ 'privkey' ], expect: { keys: {} } });
const access = rpc.declare({ object: 'session', method: 'access', params: [ 'scope', 'object', 'function' ], expect: { access: false } });
const interfaces = rpc.declare({ object: 'network.interface', method: 'dump', expect: { interface: null } });

function keyValid(_id, value) {
  return !value || (typeof value === 'string' && value.length === 44 &&
    /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(value) && !/^A{43}=$/.test(value))
    ? true : _('Enter a valid WireGuard key.');
}

function list(value) { return Array.isArray(value) ? value : value ? [ value ] : []; }
const peerDefaults = { route_allowed_ips: '1', persistent_keepalive: '25' };

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
  const reservedPorts = new Set(environment.reservedPorts || []);
  const reserve = (value, mask, route = false) => {
    const net = subnet(value, mask);
    if (net && (net.prefix || !route)) reserved.push(net);
  };
  const reserveConfigured = (value, mask, wireguard, route = false) => {
    const net = configuredSubnet(value, mask, wireguard);
    if (net && (net.prefix || !route)) reserved.push(net);
  };
  for (const value of environment.routes || []) reserve(value, undefined, true);
  for (const section of uci.sections('network')) {
    if (Array.isArray(environment.routes) && section.relay_owner === 'relay-ipsec-v1') continue;
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
      if (reservedPorts.has(port)) throw new Error(_('WireGuard listen port conflicts with the enabled IPsec service.'));
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
async function prepare(map, routes, reservedPorts = []) {
  await assertEditable();
  const links = await interfaces();
  if (!Array.isArray(links)) throw new Error(_('Unable to verify current network routes.'));
  provision(map._tunnelNames, { interfaces: links, routes, reservedPorts });
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
    if (existing && (existing['.type'] !== 'rule' || existing.name !== 'AirRelay WireGuard ' + name))
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
    else if (uci.get('firewall', id, 'name') === 'AirRelay WireGuard ' + name)
      uci.remove('firewall', id);
  }
}

function fields(map, name) {
  const exists = uci.get('network', name, 'proto') === 'wireguard';
  const section = map.section(form.NamedSection, name, 'interface', name);
  section.addremove = !exists;
  section.addbtntitle = _('Create tunnel');
  section.handleAdd = function() { return edit(map, async () => {
    await assertEditable();
    if (uci.get('network', name)) throw new Error(_('Interface name is already in use.'));
    // Parse the current form before adding a section. Failed validation must
    // not leave an invisible draft section behind, and parse would otherwise
    // remove creation defaults for fields which have not been rendered yet.
    return changeDraft(map, () => {
      uci.add('network', 'interface', name);
      uci.set('network', name, 'proto', 'wireguard');
      // Creation must not expose an unguarded native Delete action on redraw.
      section.addremove = false;
      uci.set('network', name, 'tunlink', 'lan');
      uci.set('network', name, 'listen_port', '51820');
    });
  }); };
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
  if (name === map._tunnelNames[map._tunnelNames.length - 1]) {
    o = section.option(form.DummyValue, '_apply', ' ');
    o.renderWidget = () => E('button', {
      class: 'btn cbi-button cbi-button-apply important', disabled: map.readonly || null,
      click: ui.createHandlerFn(null, async () => {
        if (map._apply) return map._apply(map);
        await map.save(() => prepare(map));
        return ui.changes.apply(true);
      })
    }, _('Save & Apply'));
  }
}

async function render(options = {}) {
  const names = uci.sections('network', 'interface').filter(s => s.proto === 'wireguard').map(s => s['.name']);
  if (!names.length) {
    let i = 0;
    while (uci.get('network', 'wg' + i)) i++;
    names.push('wg' + i);
  }
  const map = new form.Map('network');
  map._tunnelNames = names;
  map.chain('firewall');
  map.readonly = !await writable().catch(() => false);
  map._apply = options.onApply;
  map._coordination = options.coordination || {};
  options.onMap?.(map);
  for (const name of names) fields(map, name);
  // Keep map identity distinct from the management-interface form.
  const original = map.renderContents;
  map.renderContents = function(...args) {
    return Promise.resolve(original.apply(this, args)).then(node => {
      node.id = 'cbi-relay-wireguard';
      node.classList.add('ar-wg-config');
      return node;
    });
  };
  return map.render().then(node => E('section', { class: 'ar-wg-editor' }, [
    E('h2', {}, _('WireGuard')),
    node
  ]));
}

return baseclass.extend({ keyValid, subnet, validate, provision, prepare, render });
