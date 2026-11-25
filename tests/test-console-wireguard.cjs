#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const resources = path.resolve(__dirname, '../packages/luci-theme-relay/htdocs/luci-static/resources/relay');
let serviceState = {}, serviceError = null, writeAllowed = true, runtimeInterfaces = [], keyReplies = null;
const notifications = [];
const dependencies = {
  baseclass: { extend: value => value }, _: value => value, form: {}, ui: { createHandlerFn: (_context, fn) => fn, addNotification: (_title, content) => notifications.push(content) },
  L: { hasViewPermission: () => true }, E: (tag,attrs,children) => ({tag,attrs,children}),
  poll: { add() {}, remove() {} }, requestAnimationFrame() {},
  rpc: { declare: spec => (...args) => spec.object === 'rc'
    ? (serviceError ? Promise.reject(serviceError) : Promise.resolve(serviceState))
    : spec.object === 'session' ? Promise.resolve(writeAllowed)
    : spec.object === 'network.interface' ? Promise.resolve({ interface: runtimeInterfaces })
    : keyReplies ? new Promise(resolve => keyReplies.push({ key: args[0], resolve })) : Promise.resolve({}) }
};
function module(name) {
  const names = Object.keys(dependencies);
  return new Function(...names, fs.readFileSync(path.join(resources, name + '.js'), 'utf8'))(...names.map(n=>dependencies[n]));
}
const agent = dependencies.agentState = module('agent-state');
let db, serial, changes;
const uci = dependencies.uci = {
  sections(config, type) { return Object.entries(db[config]).filter(([,v])=>type == null || v['.type']===type).map(([id,v])=>({...v,'.name':id})); },
  get(config,id,key) { return key == null ? db[config][id] : db[config][id]?.[key]; },
  set(config,id,key,value) { changes++; db[config][id][key]=value; },
  add(config,type,id='test'+(++serial)) { changes++; assert.equal(db[config][id], undefined); db[config][id]={'.type':type}; return id; },
  remove(config,id) { changes++; delete db[config][id]; }
};
const wg = module('wg-config');
function reset() {
  serial=0; changes=0;
  db={network:{wg0:{'.type':'interface',proto:'wireguard',listen_port:'51820',addresses:['10.77.0.2/32']},peer:{'.type':'wireguard_wg0',allowed_ips:['10.77.0.1/32']}},firewall:{up:{'.type':'zone',name:'uplink',network:['lan','extra'],input:'REJECT'},custom:{'.type':'rule',name:'User rule',dest_port:'22'}}};
}
async function draftFailure(operation, message) {
  const count = notifications.length;
  assert.equal(await operation(), false);
  assert.equal(notifications.length, count + 1);
  assert.match(notifications.at(-1).children[0], message);
}
async function run() {
  assert.deepEqual(agent.classify({}), {installed:false,enabled:false,managed:false});
  assert.equal(agent.classify({'airroute-agent':{enabled:true,running:false}}).managed,true);
  assert.equal(agent.classify({'airroute-agent':{enabled:false,running:true}}).managed,true);
  assert.equal(agent.classify({'airroute-agent':{enabled:false,running:false}}).managed,false);
  assert.throws(()=>agent.classify(null));
  serviceState={'airroute-agent':{enabled:true}};
  await assert.rejects(agent.assertManual(),/managing/);
  serviceState={}; await agent.assertManual();
  serviceError=new Error('RPC unavailable');
  await assert.rejects(agent.assertManual(),/RPC unavailable/);
  serviceError=null;
  assert.equal(wg.keyValid('',Buffer.alloc(32,1).toString('base64')),true);
  for (const value of ['bad','A'.repeat(43)+'=', 'x'.repeat(43)+'=', Buffer.alloc(32,1).toString('base64')+'\n'])
    assert.notEqual(wg.keyValid('',value),true);
  reset(); const custom=structuredClone(db.firewall.custom);
  wg.provision(['wg0']);
  assert.deepEqual(db.firewall.up.network,['lan','extra']);
  assert.equal(db.firewall.up.masq,'1');
  assert.deepEqual(db.firewall.custom,custom);
  const tunnel=uci.sections('firewall','zone').find(s=>s.name==='airrelay_wg');
  assert.deepEqual(tunnel.network,['wg0']);
  assert.equal(tunnel.input,'REJECT');
  assert.ok(uci.sections('firewall','forwarding').some(s=>s.src==='airrelay_wg'&&s.dest==='uplink'));
  assert.equal(db.firewall.airrelay_wg_wg0.dest_port,'51820');
  assert.equal(db.firewall.airrelay_wg_wg0.proto,'udp');
  const count=Object.keys(db.firewall).length;
  wg.provision(['wg0']); assert.equal(Object.keys(db.firewall).length,count);
  db.network.wg0.listen_port='51821'; wg.provision(['wg0']);
  assert.equal(db.firewall.airrelay_wg_wg0.dest_port,'51821');
  db.network.wg0.disabled='1'; wg.provision(['wg0']);
  assert.equal(db.firewall.airrelay_wg_wg0.enabled,'0');
  db.network.wg0.disabled='true'; wg.provision(['wg0']);
  assert.equal(db.firewall.airrelay_wg_wg0.enabled,'0');
  delete db.network.wg0.listen_port; wg.provision(['wg0']);
  assert.equal(db.firewall.airrelay_wg_wg0,undefined);
  db.network.wg0.listen_port='0'; wg.provision(['wg0']);
  assert.equal(db.firewall.airrelay_wg_wg0,undefined, 'Automatic port 0 must not open UDP port 0');
  reset(); db.firewall.vpn={'.type':'zone',name:'vpn',network:['wg0','other'],input:'ACCEPT'};
  db.firewall.up.input='ACCEPT'; const before=structuredClone(db.firewall);
  wg.provision(['wg0']);
  assert.deepEqual(db.firewall.vpn,before.vpn); assert.deepEqual(db.firewall.custom,before.custom);
  assert.equal(db.firewall.up.masq,'1');
  assert.ok(uci.sections('firewall','forwarding').some(s=>s.src==='vpn'&&s.dest==='uplink'));
  assert.equal(db.firewall.airrelay_wg_wg0,undefined);
  reset(); delete db.firewall.up;
  assert.throws(()=>wg.provision(['wg0']),/No firewall zone/); assert.equal(changes,0);
  reset(); db.firewall.airrelay_wg_wg0={'.type':'rule',name:'User-owned rule'};
  assert.throws(()=>wg.provision(['wg0']),/already in use/); assert.equal(changes,0);
  for (const zones of [
    {other:{'.type':'zone',name:'other',network:['lan']}},
    {other:{'.type':'zone',name:'uplink',network:['other']}},
    {a:{'.type':'zone',name:'a',network:['wg0']},b:{'.type':'zone',name:'b',network:['wg0']}},
    {a:{'.type':'zone',name:'tunnel',network:[]},b:{'.type':'zone',name:'tunnel',network:[]}}
  ]) {
    reset(); Object.assign(db.firewall,zones);
    assert.throws(()=>wg.provision(['wg0']),/unambiguous/); assert.equal(changes,0);
  }
  for (const enabled of ['0','off','false','no','invalid','']) {
    reset(); db.firewall.up.enabled=enabled;
    assert.throws(()=>wg.provision(['wg0']),/zones must be enabled/); assert.equal(changes,0);
    reset(); db.firewall.tun={'.type':'zone',name:'vpn',network:['wg0'],enabled};
    assert.throws(()=>wg.provision(['wg0']),/zones must be enabled/); assert.equal(changes,0);
  }
  for (const family of ['inet6','ipv6','6','invalid']) {
    reset(); db.firewall.up.family=family;
    assert.throws(()=>wg.provision(['wg0']),/support IPv4/); assert.equal(changes,0);
  }
  reset(); db.firewall.tun={'.type':'zone',name:'vpn',network:['wg0']};
  db.firewall.forward={'.type':'forwarding',src:'vpn',dest:'uplink',enabled:'0'};
  assert.throws(()=>wg.provision(['wg0']),/forwarding.*disabled/); assert.equal(changes,0);
  db.firewall.forward.enabled='yes'; wg.provision(['wg0']);
  assert.equal(db.firewall.forward.enabled,'yes', 'Respect the existing enabled forwarding');
  for (const ip of ['0.0.0.0/0','10.1.2.3/0','0.0.0.0/0.0.0.0','0.0.0.0/00','0.0.0.0/000.000.000.000']) {
    reset(); db.network.peer={'.type':'wireguard_wg0',allowed_ips:[ip],route_allowed_ips:'1'};
    assert.throws(()=>wg.provision(['wg0']),/default route/); assert.equal(changes,0);
  }
  reset();
  db.network.peer={'.type':'wireguard_wg0',allowed_ips:['10.77.0.1/32'],route_allowed_ips:'0',persistent_keepalive:'0'};
  wg.provision(['wg0']);
  assert.equal(db.network.peer.route_allowed_ips,'1');
  assert.equal(db.network.peer.persistent_keepalive,'25');

  // Reject conflicts with configured routes and addresses, management DHCP and peers.
  for (const conflicting of [
    { '.type':'interface',proto:'static',ipaddr:'10.77.0.2/32' },
    { '.type':'route',target:'10.77.0.0/24',interface:'rpa_00000001' },
    { '.type':'route',target:'10.77.0.1',netmask:'255.255.255.255',type:'unreachable' },
    { '.type':'wireguard_wg0',allowed_ips:['10.77.0.1/32'] }
  ]) {
    reset(); db.network.conflict=conflicting;
    assert.throws(()=>wg.provision(['wg0']),/conflict/); assert.equal(changes,0);
  }
  reset();
  assert.throws(()=>wg.provision(['wg0'],{interfaces:[{interface:'lan','ipv4-address':[{address:'10.77.0.50',mask:24}]}]}),/conflict/);
  assert.equal(changes,0);
  assert.throws(()=>wg.provision(['wg0'],{interfaces:[{interface:'lan',route:[{target:'10.77.0.1',mask:32}]}]}),/conflict/);
  assert.equal(changes,0);
  for (const external of [
    {'.type':'interface',proto:'static',ipaddr:'10.77.0.9/030'},
    {'.type':'interface',proto:'static',ipaddr:'10.77.0.9/0x18'},
    {'.type':'interface',proto:'static',ipaddr:'10.77.0.9',netmask:'030'},
    {'.type':'interface',proto:'static',disabled:'1',ipaddr:'10.78.0.9/0'},
    {'.type':'interface',proto:'static',ipaddr:'192.0.2.1/24 10.77.0.9/24'},
    {'.type':'interface',proto:'static',ipaddr:'192.0.2.1/24\t10.77.0.9/24'},
    {'.type':'interface',proto:'wireguard',addresses:'192.0.2.1/32 10.77.0.1/32'},
    {'.type':'route',target:'10.77.0.0/030',interface:'offline'},
    {'.type':'route',target:'10.77.0.0/0x18',interface:'offline'},
    {'.type':'route',target:'10.77.0.0',netmask:'0x18',interface:'offline'}
  ]) {
    reset(); db.network.external=external;
    assert.throws(()=>wg.provision(['wg0'],{interfaces:[]}),/conflict/);
    assert.equal(changes,0, 'Offline static reservations must be checked before mutation');
  }
  reset(); db.network.external={'.type':'interface',proto:'static',ipaddr:'10.78.0.9/030'};
  wg.provision(['wg0'],{interfaces:[]});
  reset(); db.network.external={'.type':'interface',proto:'wireguard',addresses:['10.77.0.9/030']};
  wg.provision(['wg0'],{interfaces:[]}); // WireGuard /030 is decimal /30, not static /24.
  reset(); db.network.external={'.type':'interface',proto:'static',ipaddr:['2001:db8::1/64']};
  wg.provision(['wg0'],{interfaces:[]});
  reset(); db.network.external={'.type':'route',target:'0.0.0.0',netmask:'0',interface:'offline'};
  wg.provision(['wg0'],{interfaces:[]}); // Default routes are shared; interface /0 addresses are not.
  reset();
  assert.throws(()=>wg.provision(['wg0'],{interfaces:[{interface:'lan','ipv4-address':[{address:'10.78.0.9',mask:0}]}]}),/conflict/);
  for (const bad of ['10.77.0.1/255.0.255.0','127.0.0.1/32','169.254.1.1/32','224.0.0.1/32']) {
    reset(); db.network.peer.allowed_ips=[bad];
    assert.throws(()=>wg.provision(['wg0']),/conflict/); assert.equal(changes,0);
  }
  reset(); db.network.wg0.addresses=['10.77.0.2/1'];
  assert.throws(()=>wg.provision(['wg0']),/conflict/); assert.equal(changes,0);
  reset(); db.network.peer.endpoint_host='10.77.0.1';
  assert.throws(()=>wg.provision(['wg0']),/conflict/); assert.equal(changes,0);
  reset(); db.network.wg1={'.type':'interface',proto:'wireguard',addresses:['10.78.0.2/32'],listen_port:'51820'};
  db.network.peer1={'.type':'wireguard_wg1',allowed_ips:['10.78.0.1/32']};
  assert.throws(()=>wg.provision(['wg0','wg1']),/different listen ports/); assert.equal(changes,0);
  db.network.wg1.listen_port='51821'; wg.provision(['wg0','wg1']);
  reset(); db.network.peer.public_key='one'; db.network.peer2={'.type':'wireguard_wg0',public_key:'one',allowed_ips:['10.77.0.3/32']};
  assert.throws(()=>wg.provision(['wg0']),/different public key/); assert.equal(changes,0);
  reset(); delete db.network.peer;
  assert.throws(()=>wg.provision(['wg0']),/at least one enabled peer/); assert.equal(changes,0);
  reset(); db.network.peer.disabled='1';
  assert.throws(()=>wg.provision(['wg0']),/at least one enabled peer/); assert.equal(changes,0);
  db.network.wg0.disabled='1'; wg.provision(['wg0']);
  db.network.wg0.disabled='true'; wg.provision(['wg0']);
  reset(); db.network.wg0.addresses=['10.77.0.2/24']; wg.provision(['wg0']);
  assert.equal(wg.subnet('10.77.0.1/255.255.255.0').prefix,24);
  assert.equal(wg.subnet('10.77.0.1/255.0.255.0'),null);

  // Exercise peer UI guards with synthetic native-form objects; no device UCI.
  const maps=[];
  let removedButtons=0;
  class Section {
    constructor(map,type,args) { this.map=map; this.options={}; this.children=[]; this.sectiontype=type==='named'?args[1]:args[0]; }
    option(type,name,...args) {
      const o={ option:name, renderWidget() {}, depends() {} };
      if(type==='section') o.subsection=new Section(this.map,'typed',args.slice(1));
      this.children.push(o);
      this.options[name]=o; return o;
    }
    getOption(name) { return this.options[name]; }
    cfgsections() { return uci.sections('network',this.sectiontype).map(s=>s['.name']); }
    renderContents() { return {querySelectorAll: selector => selector === '.cbi-section-remove' ? [{remove(){removedButtons++;}}] : []}; }
  }
  Object.assign(dependencies.form,{NamedSection:'named',TypedSection:'typed',SectionValue:'section',
    Map: class {
      constructor(){this.sections=[];this.children=this.sections;this.saves=0;maps.push(this);}
      chain(){}
      section(type,...args){const s=new Section(this,type,args);this.sections.push(s);return s;}
      checkDepends(){}
      parse(){return Promise.resolve();}
      load(){return Promise.resolve();}
      save(cb){this.saves++;return Promise.resolve().then(cb);}
      renderContents(){return {classList:{add(){}},id:'',querySelectorAll:()=>[],appendChild(){},prepend(){}};}
      render(){return this.renderContents();}
    }});
  reset();
  db.network.lan={'.type':'interface',proto:'dhcp'};
  db.network.peer={'.type':'wireguard_wg0',allowed_ips:['10.77.0.1/32']};
  await wg.render();
  const map=maps.at(-1), tunnelSection=map.sections[0], peers=tunnelSection.options._peers.subsection;
  assert.equal(tunnelSection.options._generate,undefined);
  assert.equal(peers.options.route_allowed_ips,undefined);
  assert.equal(peers.options.persistent_keepalive,undefined);
  assert.equal(peers.options.disabled.enabled,'0');
  assert.equal(peers.options.disabled.disabled,'1');
  assert.equal(peers.options.endpoint_port.datatype,'and(port,range(1,65535))');
  assert.equal(tunnelSection.options.addresses.validate('', ['10.77.0.2/255.0.255.0']), 'Enter a valid IPv4 address or prefix.');
  tunnelSection.options.addresses.write('wg0', ['010.077.000.002/255.255.255.0']);
  assert.deepEqual(db.network.wg0.addresses, ['10.77.0.2/24']);
  peers.options.allowed_ips.write('peer', ['010.077.000.001/255.255.255.255']);
  assert.deepEqual(db.network.peer.allowed_ips, ['10.77.0.1/32']);
  peers.options.endpoint_host.write('peer', '192.000.002.001');
  assert.equal(db.network.peer.endpoint_host, '192.0.2.1');
  changes=0;
  peers.renderContents(['peer'],[]); assert.equal(removedButtons,1);
  peers.renderContents(['peer','peer2'],[]); assert.equal(removedButtons,1);
  await draftFailure(()=>peers.handleRemove('peer'),/at least one/);
  assert.equal(changes,0);
  db.network.peer2={'.type':'wireguard_wg0'};
  await peers.handleRemove('peer');
  assert.equal(db.network.peer,undefined); assert.ok(db.network.peer2);
  await peers.handleAdd();
  assert.equal(map.saves,0, 'Structural edits must not flush global UCI changes');
  const added=uci.sections('network','wireguard_wg0').find(p=>p['.name']!=='peer2');
  assert.equal(added.route_allowed_ips,'1');
  assert.equal(added.persistent_keepalive,'25');
  assert.deepEqual(db.network.lan,{'.type':'interface',proto:'dhcp'});
  serviceState={'airroute-agent':{enabled:true}};
  const protectedState=structuredClone(db);
  await draftFailure(()=>peers.handleAdd(),/managing/);
  assert.deepEqual(db,protectedState);
  serviceState={};
  writeAllowed=false;
  await wg.render(); assert.equal(maps.at(-1).readonly,true);
  await draftFailure(()=>peers.handleAdd(),/read-only/);
  assert.deepEqual(notifications.at(-1).children, ['WireGuard settings are read-only.']);
  writeAllowed=true;
  reset();
  runtimeInterfaces=null;
  await assert.rejects(wg.prepare({_tunnelNames:['wg0']}),/verify current network/); assert.equal(changes,0);
  runtimeInterfaces=[{interface:'lan','ipv4-address':[{address:'10.77.0.9',mask:24}]}];
  await assert.rejects(wg.prepare({_tunnelNames:['wg0']}),/conflict/); assert.equal(changes,0);
  runtimeInterfaces=[];
  await wg.prepare({_tunnelNames:['wg0']});

  // Out-of-order key derivation cannot relabel the latest private key.
  await wg.render();
  const keySection=maps.at(-1).sections[0], visible=[];
  keySection.options._public_key.getUIElement=()=>({setValue:value=>visible.push(value)});
  keyReplies=[];
  const oldKey=keySection.options.private_key.onchange({},'wg0',Buffer.alloc(32,1).toString('base64'));
  const newKey=keySection.options.private_key.onchange({},'wg0',Buffer.alloc(32,2).toString('base64'));
  keyReplies[1].resolve({pub:'new'}); await newKey;
  keyReplies[0].resolve({pub:'old'}); await oldKey;
  assert.equal(visible.at(-1),'new');
  await keySection.options.private_key.onchange({},'wg0',''); assert.equal(visible.at(-1),'');
  keyReplies=null;

  console.log('RelayOS WireGuard: Agent ownership, keys, route protection and firewall preservation OK');
}
run().catch(e=>{console.error(e);process.exitCode=1;});
