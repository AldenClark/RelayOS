'use strict';
'require baseclass';
'require rpc';

const callServices = rpc.declare({ object: 'rc', method: 'list', params: [ 'name' ], expect: { '': {} } });

function classify(services) {
  if (!services || typeof services !== 'object' || Array.isArray(services))
    throw new Error(_('Unable to detect AirRoute Agent.'));
  if (!Object.prototype.hasOwnProperty.call(services, 'airroute-agent'))
    return { installed: false, enabled: false, managed: false };
  const service = services['airroute-agent'];
  if (!service || typeof service !== 'object' || Array.isArray(service) ||
      (service.enabled !== true && service.running !== true &&
       (service.enabled !== false || service.running !== false)))
    throw new Error(_('Unable to detect AirRoute Agent.'));
  return { installed: true, enabled: service.enabled === true,
    managed: service.enabled === true || service.running === true };
}

async function status() {
  return classify(await callServices('airroute-agent'));
}

async function assertManual() {
  if ((await status()).managed)
    throw new Error(_('AirRoute Agent is managing WireGuard. Refresh this page.'));
}

return baseclass.extend({ classify, status, assertManual });
