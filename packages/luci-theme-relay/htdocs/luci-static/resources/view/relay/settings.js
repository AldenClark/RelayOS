'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require relay.system as systemManager';
'require relay.agent-state as agentState';
'require relay.wg-config as wgConfig';

const access = rpc.declare({ object: 'session', method: 'access',
  params: [ 'scope', 'object', 'function' ], expect: { access: false } });
const displayApplyStatus = ui.changes.displayStatus;

function displayNetworkApplyStatus(type, content) {
  // Keep LuCI's apply callbacks and other progress dialogs intact.
  if (type === 'warning' && Array.isArray(content) && content[0]?.textContent === _('Connectivity change')) {
    const buttons = content[2]?.querySelector('.cbi-button-action.important');
    if (buttons) {
      content[1].textContent = _('Are you sure you want to change the IP address mode? If you are unfamiliar with the network topology, do not change it.');
      buttons.remove();
    }
  }
  return displayApplyStatus.call(this, type, content);
}

async function networkWritable() {
  try { return L.hasViewPermission() && await access('uci', 'network', 'write') === true; }
  catch (error) { return false; }
}

function list(value) { return Array.isArray(value) ? value : value ? [ value ] : []; }

function canonicalIPv4(option, prefixes = false, multiple = false) {
  // LuCI accepts decimal octets and prefixes with leading zeros, but native
  // inet_pton()/base-0 mask parsing does not. Normalize at write time, also
  // for unchanged loaded values, while leaving the visible draft untouched.
  option.forcewrite = true;
  option.write = function(id, value) {
    const values = list(value).map(value => {
      const parts = value.split('/');
      const address = parts[0].split('.').map(Number).join('.');
      const mask = parts.length === 2 ? parts[1].split('.').map(Number).join('.') : null;
      const net = wgConfig.subnet(address, mask);
      if (!net || parts.length > 2 || (parts.length === 2 && (!prefixes || !parts[1])))
        throw new Error(_('Enter a valid IPv4 address or prefix.'));
      return address + (parts.length === 2 ? '/' + net.prefix : '');
    });
    uci.set('network', id, this.option, multiple ? values : values[0]);
  };
}

function reloadRequired() {
  const error = new Error(_('Network changes may have been partially saved. Reload this page and review pending changes before applying again.'));
  error.networkNeedsReload = true;
  return error;
}

function lockMap(map) {
  const root = map?.root;
  if (!root) return () => {};
  const inert = root.hasAttribute('inert'), busy = root.getAttribute('aria-busy');
  const controls = [...root.querySelectorAll('input,select,textarea,button')].map(node => [ node, node.disabled ]);
  // The native forms are rebuilt after asynchronous preflight/save. Prevent
  // edits that would otherwise be discarded by that rebuild. Inert also
  // covers LuCI's custom dropdown/list controls and newly rendered children.
  root.setAttribute('inert', '');
  root.setAttribute('aria-busy', 'true');
  for (const [ node ] of controls) node.disabled = true;
  return () => {
    if (!inert) root.removeAttribute('inert');
    if (busy == null) root.removeAttribute('aria-busy');
    else root.setAttribute('aria-busy', busy);
    for (const [ node, disabled ] of controls) node.disabled = disabled;
  };
}

function validateManagement() {
  if (uci.get('network', 'lan', 'proto') !== 'static') return;
  const lan = list(uci.get('network', 'lan', 'ipaddr')).map(address =>
    wgConfig.subnet(address, uci.get('network', 'lan', 'netmask')));
  if (!lan.length || lan.some(net => !net || !net.prefix))
    throw new Error(_('Enter a valid management IPv4 address and contiguous subnet mask.'));
  const reserved = [];
  for (const section of uci.sections('network', 'interface')) {
    if (section.proto !== 'wireguard') continue;
    for (const address of list(section.addresses)) reserved.push(wgConfig.subnet(address));
    for (const peer of uci.sections('network', 'wireguard_' + section['.name']))
      for (const route of list(peer.allowed_ips)) reserved.push(wgConfig.subnet(route));
  }
  if (lan.some(local => reserved.some(route => route && local.first <= route.last && route.first <= local.last)))
    throw new Error(_('The management subnet conflicts with a WireGuard tunnel.'));
}

return view.extend({
  load() {
    return Promise.all([uci.load('network'), uci.load('firewall'),
      agentState.status().catch(() => null), networkWritable()]);
  },

  render([_network, _firewall, agent, writable]) {
    ui.changes.displayStatus = displayNetworkApplyStatus;
    const map = new form.Map('network', _('Network interfaces'));
    map.readonly = !writable;
    this._networkMap = map;
    this._wireguardMap = null;
    const coordination = { run: operation => this.runNetworkOperation(operation) };

    const section = map.section(form.NamedSection, 'lan', 'interface');
    section.addremove = false;
    section.anonymous = true;

    let option = section.option(form.ListValue, 'proto', _('IPv4 address mode'));
    option.value('dhcp', _('Automatic (DHCP client)'));
    option.value('static', _('Static IPv4'));
    option.rmempty = false;
    option.default = 'dhcp';

    option = section.option(form.Value, 'ipaddr', _('IPv4 address'));
    option.datatype = 'ip4addr';
    option.rmempty = false;
    option.placeholder = '192.168.1.20';
    option.depends('proto', 'static');
    canonicalIPv4(option, true);

    option = section.option(form.Value, 'netmask', _('Subnet mask'));
    option.datatype = 'ip4addr("nomask")';
    option.default = '255.255.255.0';
    option.rmempty = false;
    option.depends('proto', 'static');
    canonicalIPv4(option);

    option = section.option(form.Value, 'gateway', _('Default gateway'));
    option.datatype = 'ip4addr("nomask")';
    option.placeholder = '192.168.1.1';
    option.rmempty = true;
    option.depends('proto', 'static');
    canonicalIPv4(option);

    option = section.option(form.DynamicList, 'dns', _('DNS servers'));
    option.datatype = 'ip4addr("nomask")';
    option.rmempty = true;
    option.depends('proto', 'static');
    const dnsValid = option.isValid;
    option.isValid = function(id) {
      // Native DynamicList.getValue() omits invalid text in its add buffer.
      // Reject that visible input before parse can save/rebuild and lose it.
      const pending = this.getUIElement(id)?.node.querySelector('.add-item input.cbi-input-invalid');
      return dnsValid.call(this, id) && !(pending && pending.value.trim());
    };
    canonicalIPv4(option, false, true);

    option = section.option(form.DummyValue, '_apply', ' ');
    option.renderWidget = () => this.renderApplyButton();

    return Promise.all([map.render(), agent && !agent.managed ? wgConfig.render({
      onMap: wireguard => { this._wireguardMap = wireguard; },
      onApply: () => this.handleApplyClick(), coordination
    }) : Promise.resolve(null)]).then(([node, wireguard]) => {
      return E('div', { class: 'ar-settings-page' }, [
        E('div', { class: 'ar-page-heading' }, E('h2', {}, _('Settings'))),
        E('p', { class: 'ar-muted' }, _('Network and WireGuard changes are validated and applied together.')),
        node,
        wireguard || (agent ? '' : E('p', { class: 'ar-muted' }, _('Unable to detect AirRoute Agent.'))),
        systemManager.render()
      ]);
    });
  },

  async runNetworkOperation(operation) {
    if (this._networkNeedsReload) throw reloadRequired();
    // Pinned ui.changes.apply() returns undefined, not a completion promise.
    // Its synchronous modal remains active through confirmation/rollback.
    if (this._networkBusy || document.body.classList.contains('modal-overlay-active')) {
      throw new Error(_('Another network operation is in progress. Try again shortly.'));
    }
    this._networkBusy = true;
    const unlock = [ this._networkMap, this._wireguardMap ].map(lockMap);
    try { return await operation(); }
    finally {
      for (const restore of unlock) restore();
      this._networkBusy = false;
    }
  },

  handleApply() {
    // UCI pending changes are shared by both native maps. Parse and validate
    // both before saving either so the LAN button cannot apply an incomplete
    // peer or bypass WireGuard ownership/route checks. Keep confirmed apply.
    return this.runNetworkOperation(async () => {
      if (!await networkWritable()) throw new Error(_('Network settings are read-only.'));
      const maps = [ this._networkMap ];
      if (this._wireguardMap && !this._wireguardMap.readonly) maps.push(this._wireguardMap);
      else {
        // An Agent takeover/page reload can hide the WG editor while an older
        // structural edit is still staged in this rpcd session. A LAN-only
        // apply cannot validate or authorize those hidden peer changes.
        const pending = await uci.changes();
        if ([ 'network', 'firewall' ].some(config => pending[config]?.length))
          throw new Error(_('Discard pending network and firewall changes before applying without the WireGuard editor.'));
      }
      for (const map of maps) {
        map.checkDepends();
        await map.parse();
      }
      validateManagement();
      if (maps.length > 1) await wgConfig.prepare(this._wireguardMap);
      try { await uci.save(); }
      catch (error) {
        // Native UCI saves issue multiple RPCs in parallel. A rejection can
        // leave anonymous creations acknowledged remotely but still present
        // in state.creates locally; retrying would duplicate them. Preserve
        // the visible draft and require a fresh UCI cache before any write.
        this._networkNeedsReload = true;
        throw reloadRequired();
      }
      for (const map of maps) { await map.load(); await map.renderContents(); }
      return ui.changes.apply(true);
    });
  },

  handleApplyClick() {
    // ui.createHandlerFn only resets its button when a promise rejects; it
    // does not display errors. Keep preflight/RPC failures visible and consume
    // the event-handler rejection without rebuilding the user's draft.
    return this.handleApply().catch(error => {
      const content = [ E('p', {}, [ error.message || _('Unable to apply network settings.') ]) ];
      if (error.networkNeedsReload)
        content.push(E('button', { type: 'button', class: 'btn', click: () => window.location.reload() }, _('Reload page')));
      ui.addNotification(_('Save error'), E('div', {}, content), 'error');
      return false;
    });
  },

  renderApplyButton() {
    return E('button', {
      class: 'btn cbi-button cbi-button-apply important',
      disabled: this._networkMap.readonly || null,
      click: ui.createHandlerFn(this, 'handleApplyClick')
    }, _('Save & Apply'));
  },

  addFooter() {
    return E([]);
  }
});
