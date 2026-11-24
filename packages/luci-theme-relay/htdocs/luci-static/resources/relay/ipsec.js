'use strict';
'require baseclass';
'require fs';
'require ui';

const helper = '/usr/libexec/relay-ipsec';
const statusKeys = [ 'enabled', 'ready', 'loaded', 'eip93', 'manual' ];

function decode(result) {
  if (!result || result.code !== 0)
    throw new Error(_('IPsec service operation failed.'));
  let state;
  try { state = JSON.parse(result.stdout); }
  catch (error) { throw new Error(_('IPsec service status is unavailable.')); }
  if (!state || statusKeys.some(key => typeof state[key] !== 'boolean'))
    throw new Error(_('IPsec service status is unavailable.'));
  return state;
}

async function status() {
  return decode(await fs.exec(helper, [ 'status' ]));
}

function canChange(state, agent, readonly) {
  return !!state && state.manual && !!agent && !agent.managed && !readonly;
}

return baseclass.extend({
  decode,
  status,
  canChange,

  async change(action, panel, agent, readonly) {
    if (!L.hasViewPermission() || readonly || !agent || agent.managed)
      return;
    if (action !== 'enable' && action !== 'disable')
      return;
    // Always re-read backend ownership before a mutation; the helper also
    // enforces this under its lock. Never send a shell fragment or a secret.
    try {
      const current = await status();
      if (!canChange(current, agent, readonly))
        throw new Error(_('IPsec is managed by AirRoute Agent or unavailable.'));
      const next = decode(await fs.exec(helper, [ action ]));
      L.dom.content(panel, this.content(next, agent, readonly, panel));
    } catch (error) {
      ui.addNotification(null, E('p', { class: 'alert-message danger' },
        _('IPsec service operation failed. Check the system log and SSH configuration.')));
      const next = await status().catch(() => null);
      L.dom.content(panel, this.content(next, agent, readonly, panel));
    }
  },

  content(state, agent, readonly, panel) {
    const writable = canChange(state, agent, readonly);
    const controls = E('div', { class: 'ar-modal-actions' }, []);
    const text = !state ? _('IPsec service status is unavailable.') :
      state.ready ? (state.enabled ? _('IKE service ready') : _('IKE service still responding')) :
      state.enabled ? _('IKE service not responding') : _('Disabled');
    const button = (action, label, disabled) => E('button', {
      class: 'btn cbi-button-action' + (action === 'enable' ? ' important' : ''),
      disabled: disabled ? true : null,
      click: ui.createHandlerFn(this, 'change', action, panel, agent, readonly)
    }, label);
    controls.appendChild(button('enable', _('Enable IPsec'), !writable || (state.enabled && state.ready)));
    controls.appendChild(button('disable', _('Disable IPsec'), !writable || (!state.enabled && !state.ready)));
    return [
      E('div', { class: 'ar-wg-head' }, E('h3', {}, _('IPsec (IKEv2)'))),
      E('p', {}, text),
      E('p', { class: 'ar-muted' }, state && state.ready ?
        (state.loaded ? _('Connection definitions loaded; this does not prove a tunnel is established.') :
          _('No connection definitions loaded.')) : ''),
      E('p', { class: 'ar-muted' }, state ?
        (state.eip93 ? _('EIP-93 driver registered; hardware use depends on the negotiated ESP algorithm.') :
          _('EIP-93 driver not registered.')) : ''),
      E('p', { class: 'ar-muted' },
        _('Configure peers, credentials and XFRM routes through SSH or AirRoute Agent. Enabling the service does not open firewall ports or change routes.')),
      !writable && state ? E('p', { class: 'ar-muted' }, _('IPsec is managed by AirRoute Agent or unavailable.')) : '',
      controls
    ];
  },

  render(state, agent, readonly) {
    const panel = E('section', { class: 'ar-panel ar-wg-panel' }, []);
    L.dom.content(panel, this.content(state, agent, readonly, panel));
    return panel;
  }
});
