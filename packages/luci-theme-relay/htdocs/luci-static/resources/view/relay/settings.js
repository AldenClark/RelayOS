'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require relay.system as systemManager';
'require relay.agent-state as agentState';
'require relay.wg-config as wgConfig';
'require relay.ipsec as ipsec';

const access = rpc.declare({ object: 'session', method: 'access',
  params: [ 'scope', 'object', 'function' ], expect: { access: false } });

async function networkWritable() {
  try { return L.hasViewPermission() && await access('uci', 'network', 'write') === true; }
  catch (error) { return false; }
}

function list(value) { return Array.isArray(value) ? value : value ? [ value ] : []; }

function validateManagement(ipsecRoutes) {
  if (uci.get('network', 'lan', 'proto') !== 'static') return;
  const lan = list(uci.get('network', 'lan', 'ipaddr')).map(address =>
    wgConfig.subnet(address, uci.get('network', 'lan', 'netmask')));
  if (!lan.length || lan.some(net => !net || !net.prefix))
    throw new Error(_('Enter a valid management IPv4 address and contiguous subnet mask.'));
  const reserved = ipsecRoutes.map(route => wgConfig.subnet(route));
  for (const section of uci.sections('network', 'interface')) {
    if (section.proto !== 'wireguard') continue;
    for (const address of list(section.addresses)) reserved.push(wgConfig.subnet(address));
    for (const peer of uci.sections('network', 'wireguard_' + section['.name']))
      for (const route of list(peer.allowed_ips)) reserved.push(wgConfig.subnet(route));
  }
  if (lan.some(local => reserved.some(route => route && local.first <= route.last && route.first <= local.last)))
    throw new Error(_('The management subnet conflicts with a WireGuard or IPsec tunnel.'));
}

return view.extend({
  load() {
    return Promise.all([uci.load('network'), uci.load('firewall'),
      agentState.status().catch(() => null), ipsec.status().catch(() => null), networkWritable()]);
  },

  render([_network, _firewall, agent, ipsecState, writable]) {
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

    option = section.option(form.Value, 'netmask', _('Subnet mask'));
    option.datatype = 'ip4addr';
    option.default = '255.255.255.0';
    option.rmempty = false;
    option.depends('proto', 'static');

    option = section.option(form.Value, 'gateway', _('Default gateway'));
    option.datatype = 'ip4addr';
    option.placeholder = '192.168.1.1';
    option.rmempty = true;
    option.depends('proto', 'static');

    option = section.option(form.DynamicList, 'dns', _('DNS servers'));
    option.datatype = 'ip4addr';
    option.rmempty = true;
    option.depends('proto', 'static');

    option = section.option(form.DummyValue, '_apply', ' ');
    option.renderWidget = () => this.renderApplyButton();

    return Promise.all([map.render(), agent && !agent.managed ? wgConfig.render({
      onMap: wireguard => { this._wireguardMap = wireguard; },
      onApply: () => this.handleApply(), coordination
    }) : Promise.resolve(null)]).then(([node, wireguard]) => {
      return E('div', { class: 'ar-settings-page' }, [
        E('div', { class: 'ar-page-heading' }, E('h2', {}, _('Settings'))),
        E('p', { class: 'ar-muted' }, _('Network and WireGuard changes are validated and applied together. IPsec has its own Save & Apply.')),
        node,
        wireguard || (agent ? '' : E('p', { class: 'ar-muted' }, _('Unable to detect AirRoute Agent.'))),
        ipsec.render(ipsecState, agent, !L.hasViewPermission(), coordination),
        systemManager.render()
      ]);
    });
  },

  async runNetworkOperation(operation) {
    // Pinned ui.changes.apply() returns undefined, not a completion promise.
    // Its synchronous modal remains active through confirmation/rollback.
    if (this._networkBusy || document.body.classList.contains('modal-overlay-active')) {
      const error = new Error(_('Another network operation is in progress. Try again shortly.'));
      error.ipsecSafe = true;
      throw error;
    }
    this._networkBusy = true;
    try { return await operation(); }
    finally { this._networkBusy = false; }
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
      // IPsec changes update native network sections outside LuCI's UCI cache.
      // Always validate against the latest protected prefixes, including off
      // peers, instead of a stale page-load snapshot of generated sections.
      const current = await ipsec.status();
      const routes = current.peers.flatMap(peer => [ peer.local_address, ...peer.remote_subnets ]);
      validateManagement(routes);
      if (maps.length > 1) await wgConfig.prepare(this._wireguardMap, routes, current.enabled ? [ 500, 4500 ] : []);
      await uci.save();
      for (const map of maps) { await map.load(); await map.renderContents(); }
      return ui.changes.apply(true);
    });
  },

  renderApplyButton() {
    return E('button', {
      class: 'btn cbi-button cbi-button-apply important',
      disabled: this._networkMap.readonly || null,
      click: ui.createHandlerFn(this, 'handleApply')
    }, _('Save & Apply'));
  },

  addFooter() {
    return E([]);
  }
});
