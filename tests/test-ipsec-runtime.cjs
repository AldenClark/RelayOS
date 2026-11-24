#!/usr/bin/env node
// Real pinned ucode/UCI execution, isolated files and simulated device commands.
// No network interface, service, SA, firewall or router is actually changed.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const ucode = process.env.UCODE;
const uci = process.env.UCI;
assert.ok(ucode && path.isAbsolute(ucode), 'Set UCODE to a host ucode with fs/uci modules');
assert.ok(uci && path.isAbsolute(uci), 'Set UCI to the host UCI CLI');
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-ipsec-test-'));
const files = path.join(root, 'packages/relay-ipsec/files');
const configDir = path.join(fixture, 'config');
const bin = path.join(fixture, 'bin');
const stateFile = path.join(fixture, 'device.json');
const env = { ...process.env, TEST_IPSEC_FIXTURE: fixture, TEST_UCODE: ucode, TEST_UCI: uci };
let assertions = 0;
for (const dir of ['config', 'run', 'bin', 'extra', 'deltas', 'rpcd']) fs.mkdirSync(path.join(fixture, dir));

// This fake device persists runtime state between commands so regressions can
// detect global restarts, stale SAs, unintended routes and partial failures.
const fakeProgram = `#!${process.execPath}
'use strict';
const fs=require('node:fs'),path=require('node:path'),{spawnSync,spawn}=require('node:child_process');
const dir=process.env.TEST_IPSEC_FIXTURE, file=path.join(dir,'device.json');
const cmd=path.basename(process.argv[1]), args=process.argv.slice(2);
let s=JSON.parse(fs.readFileSync(file));
s.calls.push([cmd,...args]);
function save(){fs.writeFileSync(file,JSON.stringify(s));}
function concurrentWrite(phase){
  if(s.concurrentWrite!==phase)return;
  const configFile=path.join(dir,'config',phase==='status'?'relay_ipsec':'network');
  const text=fs.readFileSync(configFile,'utf8');
  fs.writeFileSync(configFile,phase==='status'?text.replace('Cloud 1','Concurrent Cloud'):text.replace('synthetic-wireguard-key','concurrent-new-wireguard-key'));
  s.concurrentWrite='';s.concurrentObserved=true;
}
// Do not exit with queued asynchronous stdout writes: larger route/ubus JSON
// responses must reach the worker intact at the configured resource ceiling.
function result(data='',code=0){save();if(data)fs.writeFileSync(1,typeof data==='string'?data:JSON.stringify(data));process.exit(code);}
function cfg(name){const code='import { cursor } from "uci"; printf("%J", cursor('+JSON.stringify(path.join(dir,'config'))+').get_all('+JSON.stringify(name)+'));';const r=spawnSync(process.env.TEST_UCODE,['-e',code],{encoding:'utf8',env:process.env});if(r.status!==0)throw new Error(r.stderr);return JSON.parse(r.stdout);}
function reject(key){if(s.fail===key){if(!s.failPersistent)s.fail='';result('',1);}}
const conns=()=>Object.entries(cfg('ipsec')).filter(([,v])=>v['.type']==='connection'&&v.enabled==='1').map(([id])=>id);
const net=()=>s.netdefs||cfg('network');
function initiate(name){if(!s.sas[name])s.sas[name]={number:++s.serial,state:'ESTABLISHED',child:'INSTALLED'};}
if(cmd==='uci'){
  if(s.pending)return result('network.lan.proto=static\\n');
  const r=spawnSync(process.env.TEST_UCI,['-c',path.join(dir,'config'),'-P',path.join(dir,'deltas'),...args],{encoding:'utf8',env:process.env});
  return result(r.stdout,r.status);
}
if(cmd==='ubus'){
  reject('ubus');
  if(args.includes('list'))return result(s.agentUnknown?{}:{'airroute-agent':{enabled:!!s.agent,running:!!s.agent}});
  if(args.includes('dump'))return result({interface:Object.entries(net()).filter(([,v])=>v['.type']==='interface').map(([name,v])=>({interface:name,up:!s.xfrmDown,l3_device:v.proto==='xfrm'?name:v.device?.slice(1),'ipv4-address':v.ipaddr?[{address:v.ipaddr.split('/')[0],mask:32}]:[]}))});
  if(args.includes('status')){const name=args[args.indexOf('call')+1].split('.').pop(),v=net()[name]||{};return result({up:!s.xfrmDown,l3_device:v.proto==='xfrm'?name:v.device?.slice(1),'ipv4-address':v.ipaddr?[{address:v.ipaddr.split('/')[0],mask:32}]:[]});}
}
if(cmd==='ip'){
  if(args.includes('-batch')){
    if(args[args.length-1].endsWith('.guards-add'))concurrentWrite('guards');
    const lines=fs.readFileSync(args[args.indexOf('-batch')+1],'utf8').trim().split('\\n').filter(Boolean);
    for(let i=0;i<lines.length;i++){
      const parts=lines[i].split(' '),operation=parts[1],dst=parts[3],metric=Number(parts[parts.indexOf('metric')+1]),protocol=Number(parts[parts.indexOf('proto')+1]);
      if(parts[0]!=='route'||parts[2]!=='unreachable'||!['replace','add','del'].includes(operation))throw new Error('Unexpected batch route');
      if(operation!=='del')reject('guard');
      else reject('guard_release');
      s.routes=s.routes.filter(r=>r.dst!==dst||r.metric!==metric);
      if(operation!=='del')s.routes.push({type:'unreachable',dst,metric,protocol});
      if(s.fail==='partial_guards'&&i===0){s.fail='';return result('',1);}
    }
    return result();
  }
  if(args.includes('addr'))return result([{ifname:'br-lan',addr_info:[{family:'inet',local:'192.168.10.2',prefixlen:24}]},{ifname:'wg0',addr_info:[{family:'inet',local:'10.77.0.2',prefixlen:32}]}].concat(Object.entries(net()).filter(([,v])=>v.proto==='static'&&v.device?.startsWith('@rpx_')).map(([name,v])=>({ifname:v.device.slice(1),addr_info:s.xfrmDown?[]:[{family:'inet',local:v.ipaddr.split('/')[0],prefixlen:32}]}))).concat(s.foreignAddresses||[]));
  if(args.includes('link'))return result(Object.entries(net()).filter(([,v])=>v.proto==='xfrm').map(([name,v])=>({ifname:name,mtu:Number(v.mtu),flags:s.xfrmDown?[]:['UP'],linkinfo:{info_kind:'xfrm',info_data:{if_id:'0x'+Number(v.ifid).toString(16)}}})).concat(s.foreignLinks||[]));
  if(args.includes('route')&&args.includes('show'))return result(s.routes);
  if(args.includes('route')&&(args.includes('replace')||args.includes('add'))){
    reject('guard');
    const kind=args.includes('unreachable')?'unreachable':'unicast';
    const ri=args.indexOf(kind), dst=ri>=0?args[ri+1]:args[args.indexOf('replace')+1];
    const metric=Number(args[args.indexOf('metric')+1]);
    s.routes=s.routes.filter(r=>r.dst!==dst||r.metric!==metric);
    s.routes.push({type:kind,dst,metric,protocol:'static'});return result();
  }
  if(args.includes('route')&&args.includes('del')){const ri=args.indexOf('unreachable'),dst=args[ri+1],metric=Number(args[args.indexOf('metric')+1]);s.routes=s.routes.filter(r=>r.dst!==dst||r.metric!==metric);return result();}
}
if(cmd==='network'){
  if(args[0]!=='reload')throw new Error('Only differential network reload is authorized');
  reject('network');
  if(s.fail==='network_skip'){s.fail='';return result();}
  s.netdefs=cfg('network');
  // Netifd replaces only its owned route set. Out-of-band transaction guards
  // at another metric are retained, as the kernel would retain them.
  s.routes=s.routes.filter(r=>!r.netifd);
  for(const [name,v]of Object.entries(cfg('network'))){
    if(v['.type']!=='route')continue;
    if(s.xfrmDown&&v.interface?.startsWith('rpa_'))continue;
    const metric=Number(v.metric||0),type=v.type||'unicast';
    s.routes=s.routes.filter(r=>r.dst!==v.target||r.metric!==metric);
    s.routes.push({dst:v.target,type,metric,protocol:'static',dev:net()[v.interface]?.device?.slice(1)||v.interface,netifd:true});
  }
  if(s.fail==='network_address'){s.fail='';delete s.netdefs.rpa_00000003.ipaddr;}
  if(s.fail==='network_ifid'){s.fail='';s.netdefs.rpx_00000003.ifid='4';}
  if(s.fail==='network_mtu'){s.fail='';s.netdefs.rpx_00000003.mtu='1280';}
  if(s.fail==='network_route'){s.fail='';s.routes=s.routes.filter(r=>!(r.dst==='10.78.3.1/32'&&r.type==='unicast'));}
  return result();
}
if(cmd==='fw4'){
  if(s.fail==='timeout'){
    s.fail='';const child=spawn(process.execPath,['-e','process.on("SIGTERM",()=>{});setInterval(()=>{},1000);'],{stdio:['ignore','inherit','inherit']});
    s.stubbornChild=child.pid;save();process.on('SIGTERM',()=>{});setInterval(()=>{},1000);return;
  }
  reject('fw4');return result();
}
if(cmd==='firewall'){if(args[0]!=='reload')throw new Error('Only firewall reload allowed');reject('firewall');return result();}
if(cmd==='init'){
  if(args[0]==='enable')return result();
  if(args[0]==='stop'){reject('stop');s.running=false;s.connections=[];s.sas={};return result();}
  if(args[0]==='reload'||args[0]==='start'){
    reject('start');s.running=cfg('ipsec').globals.enabled==='1';
    if(s.running){s.connections=conns();for(const name of s.connections)initiate(name);}
    concurrentWrite('load');
    return result();
  }
  throw new Error('Unexpected daemon action '+args[0]);
}
if(cmd==='pidof')return result(s.running?'1234':'',s.running?0:1);
if(cmd==='swan'){
  if(args.includes('--stats')){concurrentWrite('status');if(s.statsFailure)return result('',1);return result('',s.running?0:1);}
  if(!s.running)return result('',1);
  if(args.includes('--list-sas')){if(s.failListSAOnce){s.failListSAOnce=false;return result('',1);}return result(Object.entries(s.sas).map(([name,v])=>name+': #'+v.number+', '+v.state+', IKEv2, test\\n  '+name+'_child: #'+v.number+', reqid 1, '+v.child+', TUNNEL, ESP:test\\n').join(''));}
  if(args.includes('--list-conns'))return result(s.connections.map(n=>n+': IKEv2, test\\n  '+n+'_child: TUNNEL\\n').join(''));
  if(args.includes('--terminate')){
    const name=args[args.indexOf('--ike')+1];
    if(s.connections.includes(name))throw new Error('Affected connection must be quiesced before terminating its SA');
    const protectedRoutes=cfg('ipsec')[name+'_child']?.remote_ts||[];
    for(const dst of protectedRoutes)if(!s.routes.some(r=>r.dst===dst&&r.type==='unreachable'))throw new Error('SA teardown without protected route');
    if(!s.terminateStuck)delete s.sas[name];
    return result();
  }
  if(args.includes('--load-creds')){
    const keys=Object.entries(cfg('ipsec')).filter(([,v])=>v['.type']==='secret').map(([id])=>'ike-'+id);
    if(args.includes('--raw')){
      let existing=s.keys||[],missing=s.missingKeyInventory,negative=false;
      if(s.fail==='credential_inventory'){s.fail='';existing=existing.concat(['ike-stale-key']);}
      if(s.fail==='credential_missing_inventory'){s.fail='';missing=true;}
      if(s.fail==='credential_raw_failure'){s.fail='';negative=true;}
      const inventory=missing?'':'get-shared reply {keys=['+existing.join(' ')+']}\\n';
      return result(inventory+keys.map((id,i)=>'load-shared reply {success='+(negative&&i===0?'no':'yes')+'}\\n').join(''));
    }
    if(s.fail==='credentials'){s.fail='';keys.pop();}
    if(s.fail==='credential_stderr'){s.fail='';process.stderr.write('synthetic-private-credential-diagnostic\\n');}
    s.keys=keys.concat(s.staleKey?['ike-unexpected-stale-key']:[]);
    return result(keys.map(id=>"loaded ike secret '"+id+"'\\n").join(''));
  }
  if(args.includes('--load-conns')){
    reject('connections');s.connections=conns();
    if(s.fail==='connections_silent'){s.fail='';s.connections=[];}
    if(s.fail==='late_status'){s.fail='';s.failListSAOnce=true;}
    for(const name of s.connections)initiate(name);return result();
  }
  if(args.includes('--initiate')){const name=args[args.indexOf('--child')+1].replace(/_child$/,'');if(s.connections.includes(name))initiate(name);return result();}
}
throw new Error('Unexpected fake command '+cmd+' '+args.join(' '));
`;
const fake = path.join(bin, 'fake.cjs');
fs.writeFileSync(fake, fakeProgram, { mode: 0o700 });
for (const cmd of ['swan','init','network','firewall','fw4','ip','ubus','uci','pidof']) fs.symlinkSync(fake,path.join(bin,cmd));
const workerPaths = { config:configDir,runtime:path.join(fixture,'run'),crypto:path.join(fixture,'crypto'),agent:path.join(fixture,'agent'),extra:path.join(fixture,'extra'),swan_config:path.join(fixture,'swanctl.conf'),strong_config:path.join(fixture,'strongswan.conf'),rpcd:path.join(fixture,'rpcd') };
const workerCommands = Object.fromEntries(['swan','init','network','firewall','fw4','ip','ubus','uci','pidof'].map(x=>[x,path.join(bin,x)]));
Object.assign(workerCommands,{timeout:'/usr/bin/timeout',sha256:'/usr/bin/sha256sum',sleep:'/bin/sleep'});
let worker = fs.readFileSync(path.join(files,'relay-ipsec-worker.uc'),'utf8')
  .replace("'/usr/share/relay-ipsec/model.uc'",JSON.stringify(path.join(files,'relay-ipsec-model.uc')))
  .replace(/const paths = \{[\s\S]*?\};/, 'const paths = '+JSON.stringify(workerPaths)+';')
  .replace(/const cmd = \{[\s\S]*?\};/, 'const cmd = '+JSON.stringify(workerCommands)+';');
assert.ok(!worker.includes('time()'), 'Transaction deadlines must not depend on NTP-adjustable wall time');
assert.ok(worker.includes('clock(true)'), 'Use the pinned ucode monotonic clock for bounded work and rollback');
if (process.env.IPSEC_TEST_DEBUG)
  worker = worker.replaceAll('} catch (error) {', '} catch (error) { fs.writefile('+JSON.stringify(path.join(fixture,'debug-error'))+', sprintf("Fixture failure: %J\\n%J", error, error.stacktrace));');
assert.ok(!worker.includes("init: '/etc/init.d/"),'All device commands must be isolated');
fs.writeFileSync(path.join(fixture,'worker.uc'),worker);
fs.writeFileSync(workerPaths.crypto,'name : authenc(hmac(sha256),cbc(aes))\ndriver : authenc(hmac(sha256-eip93),cbc(aes-eip93))\n');
fs.writeFileSync(workerPaths.swan_config,'include /var/swanctl/swanctl.conf\ninclude conf.d/*.conf\n');
// Upstream strongSwan 6.0.7 template, with the OpenWrt package's appended include.
fs.writeFileSync(workerPaths.strong_config,'charon {\n load_modular = yes\n plugins {\n  include strongswan.d/charon/*.conf\n }\n}\ninclude strongswan.d/*.conf\ninclude /var/ipsec/strongswan.conf\n');
function device() { return JSON.parse(fs.readFileSync(stateFile)); }
function patchDevice(patch) { fs.writeFileSync(stateFile,JSON.stringify({...device(),...patch})); }
function reset() {
  fs.writeFileSync(stateFile,JSON.stringify({calls:[],running:false,connections:[],sas:{},routes:[],keys:[],serial:0}));
  const sources={
    relay_ipsec:"config globals 'globals'\n option enabled '0'\n",
    ipsec:"config globals 'globals'\n option enabled '0'\n option rtinstall_enabled '0'\nconfig syslog 'syslog'\n",
    network:"config interface 'loopback'\n option proto 'static'\n option ipaddr '127.0.0.1'\n option netmask '255.0.0.0'\nconfig interface 'lan'\n option proto 'dhcp'\nconfig interface 'wg0'\n option proto 'wireguard'\n list addresses '10.77.0.2/32'\n option private_key 'synthetic-wireguard-key'\nconfig wireguard_wg0 'original_wg_peer'\n list allowed_ips '10.77.0.1/32'\n option public_key 'synthetic-wireguard-public'\n",
    firewall:"config zone 'uplink'\n option name 'uplink'\n option masq '1'\n list network 'lan'\nconfig rule 'user_rule'\n option name 'User-defined rule'\n option dest_port '22'\n"
  };
  for(const [name,text]of Object.entries(sources))fs.writeFileSync(path.join(configDir,name),text,{mode:0o600});
  patchDevice({netdefs:rawConfig('network')});
}
function call(action,body) {
  const child=spawnSync(ucode,[path.join(fixture,'worker.uc'),action],{env,encoding:'utf8',input:body?JSON.stringify(body):'',timeout:35000});
  assert.equal(child.status,0,child.stderr || child.error?.message);
  assert.equal(child.stderr,'','No sensitive diagnostics may escape the worker');
  try{return JSON.parse(child.stdout);}catch(e){throw new Error('Invalid worker JSON: '+child.stdout+' '+e.message);}
}
function read(packageName) { return fs.readFileSync(path.join(configDir,packageName),'utf8'); }
function filesSnapshot() { return Object.fromEntries(['relay_ipsec','ipsec','network','firewall'].map(n=>[n,read(n)])); }
function rawConfig(packageName) {
  const code='import { cursor } from "uci"; printf("%J", cursor('+JSON.stringify(configDir)+').get_all('+JSON.stringify(packageName)+'));';
  const child=spawnSync(ucode,['-e',code],{env,encoding:'utf8'}); assert.equal(child.status,0,child.stderr);return JSON.parse(child.stdout);
}
function peer(suffix=1) { return {id:'p'+suffix.toString(16).padStart(8,'0'),name:'Cloud '+suffix,enabled:true,remote:'198.51.100.'+suffix,local_id:'relay-'+suffix,remote_id:'cloud-'+suffix,psk:'synthetic-test-secret-'+suffix,local_address:'10.78.'+suffix+'.2/32',remote_subnets:['10.78.'+suffix+'.1/32'],ike:'aes128-sha256-modp2048',esp:'aes128-sha256-noesn',dpd_delay:30,mtu:1400}; }
function apply(config) { return call('apply',{config}); }
function nextConfig(state) { return {revision:state.revision,enabled:state.enabled,peers:state.peers.map(({psk_set,state,...peer})=>({...peer,remote_subnets:peer.remote_subnets.slice()}))}; }
function debugResult() { return process.env.IPSEC_TEST_DEBUG?'\n'+(fs.existsSync(path.join(fixture,'debug-error'))?fs.readFileSync(path.join(fixture,'debug-error'),'utf8'):'')+'\n'+JSON.stringify(device().calls.slice(-65)):''; }
function expectOk(result) { assert.equal(result.ok,true,JSON.stringify(result)+debugResult()); assertions++;return result; }
function expectError(result,code) { assert.equal(result.ok,false,JSON.stringify(result)+debugResult());assert.equal(result.error,code,JSON.stringify(result)+debugResult());assertions++; }
try {
  // Netifd accepts dotted, decimal, octal and hexadecimal IPv4 masks. These
  // committed reservations must count even before the interface is up, when
  // the kernel has no normalized address/route to expose to environment().
  for (const definition of [
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.78.1.9/255.255.255.0'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.78.1.9/030'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.78.1.9/0x18'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/24\t10.78.1.9/24'\n",
    "config route 'dormant_route'\n option interface 'dormant'\n option target '10.78.1.0/255.255.255.0'\n",
    "config route 'dormant_route'\n option interface 'dormant'\n option target '10.78.1.0/030'\n",
    "config route 'dormant_route'\n option interface 'dormant'\n option target '10.78.1.0/0x18'\n",
    "config route 'dormant_route'\n option interface 'dormant'\n option target '0.0.0.0'\n option netmask '128.0.0.0'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/0.0.0.0'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9'\n option netmask '0'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/255.0.255.0'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/33'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/08'\n",
    "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9/019'\n"
  ]) {
    reset(); fs.appendFileSync(path.join(configDir,'network'),definition);
    const current=expectOk(call('get')), before=filesSnapshot(); patchDevice({calls:[]});
    expectError(apply({revision:current.revision,enabled:true,peers:[peer(1)]}),'route_conflict');
    assert.deepEqual(filesSnapshot(),before);
    assert.ok(!device().calls.some(c=>['init','network','firewall'].includes(c[0])));
  }
  // Separate numeric netmasks are also native syntax. Disjoint reservations,
  // IPv6 addresses and a true default route must not block a valid apply.
  for (const mask of ['24','030','0x18']) {
    reset();
    fs.writeFileSync(path.join(configDir,'network'),read('network').replace(
      "list addresses '10.77.0.2/32'", "list addresses '10.77.0.2/32'\n list addresses '2001:db8::1/64'"));
    fs.appendFileSync(path.join(configDir,'network'),
      "config interface 'dormant'\n option proto 'static'\n option auto '0'\n option ipaddr '10.91.1.9 10.92.1.9'\n option netmask '"+mask+"'\n"+
      "config route 'default_route'\n option interface 'lan'\n option target '0.0.0.0'\n option netmask '0'\n");
    const current=expectOk(call('get'));
    expectOk(apply({revision:current.revision,enabled:true,peers:[peer(1)]}));
  }
  // WireGuard's ucode protocol converts numeric prefixes in decimal, unlike
  // netifd's native static parser. /030 reserves only a /30, not an octal /24.
  reset();
  fs.writeFileSync(path.join(configDir,'network'),read('network')
    .replace('10.77.0.2/32','10.90.0.2/030').replace('10.77.0.1/32','10.90.0.1/030'));
  const decimalState=expectOk(call('get'));
  expectOk(apply({revision:decimalState.revision,enabled:true,
    peers:[{...peer(1),local_address:'10.90.0.6/32',remote_subnets:['10.90.0.5/32']}]}));
  reset();
  let state=expectOk(call('get'));
  assert.equal(state.manual,true);assert.equal(state.enabled,false);assert.equal(state.eip93,true);assert.equal(state.peers.length,0);
  const baseline=filesSnapshot(), original=rawConfig('network');
  for(const id of ['p00000000','p80000000','pffffffff']){
    const invalid=peer(1);invalid.id=id;
    expectError(apply({revision:state.revision,enabled:true,peers:[invalid]}),'invalid_config');
    assert.deepEqual(filesSnapshot(),baseline);
  }
  let config={revision:state.revision,enabled:true,peers:[peer(1),peer(2)]};
  state=expectOk(apply(config));
  assert.equal(state.peers.length,2);assert.equal(JSON.stringify(state).includes('synthetic-test-secret'),false);
  for(const name of ['relay_ipsec','ipsec'])assert.equal(fs.statSync(path.join(configDir,name)).mode&0o777,0o600);
  for(const name of ['loopback','lan','wg0','original_wg_peer'])assert.deepEqual(rawConfig('network')[name],original[name]);
  assert.equal(rawConfig('firewall').user_rule.name,'User-defined rule');
  // Never return old peer data paired with a newer external writer's revision.
  patchDevice({concurrentWrite:'status'});expectError(call('get'),'stale_revision');
  state=expectOk(call('get'));assert.equal(state.peers[0].name,'Concurrent Cloud');
  const bSA=device().sas.rp_00000002.number;
  // Cosmetic update must not terminate any SA or restart the daemon.
  patchDevice({calls:[]});config=nextConfig(state);config.peers[0].name='Renamed peer';state=expectOk(apply(config));
  assert.equal(device().calls.some(c=>c.includes('--terminate')),false);
  assert.equal(device().sas.rp_00000002.number,bSA);
  // Literal key bytes are encoded, even if the password begins with 0x.
  patchDevice({calls:[]});config=nextConfig(state);config.peers[0].psk='0xliteral-secret-value';state=expectOk(apply(config));
  assert.equal(rawConfig('ipsec').rp_00000001_key.secret,'0x'+Buffer.from('0xliteral-secret-value').toString('hex'));
  assert.ok(device().calls.some(c=>c.includes('--terminate')&&c.includes('rp_00000001')));
  assert.ok(!device().calls.some(c=>c.includes('--terminate')&&c.includes('rp_00000002')));
  assert.equal(device().sas.rp_00000002.number,bSA);
  // Disable one peer: guard persists, SA removed, other SA retained.
  config=nextConfig(state);config.peers[0].enabled=false;state=expectOk(apply(config));
  assert.equal(device().sas.rp_00000001,undefined);assert.equal(device().sas.rp_00000002.number,bSA);
  assert.ok(device().routes.some(r=>r.dst==='10.78.1.1/32'&&r.type==='unreachable'));
  // Stale revision and validation failures must be mutation-free.
  const stable=filesSnapshot();config=nextConfig(state);config.revision='stale';expectError(apply(config),'stale_revision');assert.deepEqual(filesSnapshot(),stable);
  config=nextConfig(state);config.peers[0].remote_subnets=['10.77.0.1/32'];expectError(apply(config),'route_conflict');assert.deepEqual(filesSnapshot(),stable);
  config=nextConfig(state);config.peers[0].remote_subnets=['192.168.10.0/24'];expectError(apply(config),'route_conflict');assert.deepEqual(filesSnapshot(),stable);
  patchDevice({pending:true});expectError(apply(nextConfig(state)),'pending_changes');assert.deepEqual(filesSnapshot(),stable);patchDevice({pending:false});
  // rpcd uses per-session savedirs, not only the CLI's default /tmp/.uci.
  for(const dirname of ['uci-fixture-session','snapshot-files','snapshot-delta']){
    const dir=path.join(workerPaths.rpcd,dirname);fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir,'network'),dirname.startsWith('uci-')?"network.lan.proto='static'\n":'');
    expectError(apply(nextConfig(state)),'pending_changes');assert.deepEqual(filesSnapshot(),stable);
    fs.unlinkSync(path.join(dir,'network'));fs.rmdirSync(dir);
  }
  // Main-table routes learned outside UCI must not bypass the protected route.
  const priorRoutes=device().routes;
  patchDevice({routes:[...priorRoutes,{dst:'10.90.0.0/24',type:'unicast',dev:'wan',metric:10,protocol:16}]});
  config=nextConfig(state);config.peers[0].remote_subnets=['10.90.0.0/24'];
  expectError(apply(config),'route_conflict');assert.deepEqual(filesSnapshot(),stable);patchDevice({routes:priorRoutes});
  patchDevice({foreignLinks:[{ifname:'operator-xfrm',linkinfo:{info_kind:'xfrm',info_data:{if_id:'0x3'}}}]});
  config=nextConfig(state);config.peers.push(peer(3));expectError(apply(config),'name_conflict');assert.deepEqual(filesSnapshot(),stable);patchDevice({foreignLinks:[]});
  const priorConnections=device().connections;
  patchDevice({connections:[...priorConnections,'rp_12345678']});
  expectError(apply(nextConfig(state)),'unmanaged_config');assert.deepEqual(filesSnapshot(),stable);patchDevice({connections:priorConnections});
  patchDevice({statsFailure:true,calls:[]});expectError(apply(nextConfig(state)),'unavailable');
  assert.deepEqual(filesSnapshot(),stable);assert.ok(!device().calls.some(c=>c[0]==='init'));patchDevice({statsFailure:false});
  // A partially successful batch before config publication is cleaned up.
  patchDevice({fail:'partial_guards'});expectError(apply(nextConfig(state)),'apply_failed');
  assert.deepEqual(filesSnapshot(),stable);assert.ok(!device().routes.some(r=>r.metric===42759));
  // All service errors must return an explicit failure and restore the files.
  for(const failure of ['fw4','network','firewall','credentials','credential_stderr','credential_inventory','credential_missing_inventory','credential_raw_failure','connections','connections_silent','late_status','guard_release','timeout']){
    const before=filesSnapshot();const current=expectOk(call('get'));config=nextConfig(current);config.peers[1].name='failure '+failure;
    patchDevice({fail:failure});expectError(apply(config),failure==='late_status'?'unavailable':'apply_failed');assert.deepEqual(filesSnapshot(),before,failure+' failed to restore original files');
    assert.equal(device().sas.rp_00000002.number,bSA,failure+' restarted unchanged peer');
    assert.ok(!device().routes.some(r=>r.metric===42759),failure+' left transaction guards after successful rollback');
  }
  // Successful exit status is not enough: kernel addresses, if_id and active
  // routes must agree with the generated XFRM configuration.
  for(const failure of ['network_skip','network_address','network_ifid','network_mtu','network_route']){
    const before=filesSnapshot();state=expectOk(call('get'));config=nextConfig(state);config.peers.push(peer(3));
    patchDevice({fail:failure});expectError(apply(config),'apply_failed');assert.deepEqual(filesSnapshot(),before);
    assert.equal(device().sas.rp_00000002.number,bSA);assert.ok(!device().routes.some(r=>r.dst==='10.78.3.1/32'));
  }
  state=expectOk(call('get'));config=nextConfig(state);config.peers=config.peers.filter(p=>p.id!=='p00000001');state=expectOk(apply(config));
  assert.equal(state.peers.length,1);assert.ok(!Object.keys(rawConfig('network')).some(n=>n.includes('00000001')));
  assert.ok(!device().routes.some(r=>r.dst==='10.78.1.1/32'));
  config=nextConfig(state);config.enabled=false;state=expectOk(apply(config));assert.equal(device().running,false);assert.equal(Object.keys(device().sas).length,0);
  assert.ok(device().routes.some(r=>r.dst==='10.78.2.1/32'&&r.type==='unreachable'));
  assert.deepEqual(rawConfig('network').wg0,original.wg0);
  // Agent ownership is server-side, not just a hidden control.
  fs.writeFileSync(workerPaths.agent,'#!/bin/sh\nexit 0\n',{mode:0o700});patchDevice({agent:true});
  const guarded=filesSnapshot();expectError(apply(nextConfig(state)),'managed');assert.deepEqual(filesSnapshot(),guarded);
  patchDevice({agent:false,agentUnknown:true});expectError(apply(nextConfig(state)),'managed');assert.deepEqual(filesSnapshot(),guarded);
  fs.unlinkSync(workerPaths.agent);
  // Reserved foreign sections may not be silently claimed.
  reset();fs.appendFileSync(path.join(configDir,'network'),"config interface 'rpx_00000001'\n option proto 'static'\n");state=expectOk(call('get'));
  const collision=filesSnapshot();expectError(apply({revision:state.revision,enabled:true,peers:[peer(1)]}),'name_conflict');assert.deepEqual(filesSnapshot(),collision);
  // An unrecoverable runtime failure must be explicit and retain protection.
  reset();state=expectOk(call('get'));state=expectOk(apply({revision:state.revision,enabled:true,peers:[peer(1),peer(2)]}));
  const unaffected=device().sas.rp_00000002.number;
  config=nextConfig(state);config.peers[0].psk='replacement-synthetic-secret';
  patchDevice({fail:'firewall',failPersistent:true});expectError(apply(config),'rollback_failed');
  assert.equal(device().sas.rp_00000002.number,unaffected);
  assert.ok(device().routes.some(r=>r.type==='unreachable'&&r.metric===42759&&r.dst==='10.78.1.1/32'));
  // IKE and NAT-T have fixed listeners. Reject enabling IPsec when an enabled
  // WireGuard interface already reserves either UDP port; no runtime writes.
  for(const port of [500,4500]){
    reset();
    const networkFile=path.join(configDir,'network');
    fs.writeFileSync(networkFile,read('network').replace(" option proto 'wireguard'", " option proto 'wireguard'\n option listen_port '"+port+"'"));
    state=expectOk(call('get'));const prior=filesSnapshot();patchDevice({calls:[]});
    expectError(apply({revision:state.revision,enabled:true,peers:[peer(1)]}),'port_conflict');
    assert.deepEqual(filesSnapshot(),prior);
    assert.ok(!device().calls.some(c=>['init','network','firewall'].includes(c[0])));
    state=expectOk(apply({revision:state.revision,enabled:false,peers:[peer(1)]}));
    assert.equal(state.enabled,false);
    const networkWithListener=read('network');
    for(const disabled of ['1','true']){
      fs.writeFileSync(networkFile,networkWithListener.replace("option proto 'wireguard'", "option proto 'wireguard'\n\toption disabled '"+disabled+"'"));
      state=expectOk(call('get'));state=expectOk(apply({...nextConfig(state),enabled:true}));
    }
  }
  // Detect committed changes during device commands before publication. The
  // other writer's WireGuard settings must never be replaced with our snapshot.
  reset();state=expectOk(call('get'));
  const beforeConcurrent=filesSnapshot();
  patchDevice({concurrentWrite:'guards'});
  expectError(apply({revision:state.revision,enabled:true,peers:[peer(1)]}),'stale_revision');
  assert.equal(device().concurrentObserved,true);
  assert.equal(rawConfig('network').wg0.private_key,'concurrent-new-wireguard-key');
  for(const name of ['relay_ipsec','ipsec','firewall'])assert.equal(read(name),beforeConcurrent[name]);
  assert.ok(!device().routes.some(r=>r.metric===42759));
  // A conflicting write after publication cannot be rolled back safely. Report
  // that explicitly, preserve the concurrent bytes and keep route protection.
  for(const rotating of [true,false]){
    reset();state=expectOk(call('get'));state=expectOk(apply({revision:state.revision,enabled:true,peers:[peer(1),peer(2)]}));
    const preserved=device().sas.rp_00000002.number;
    config=nextConfig(state);
    if(rotating)config.peers[0].psk='replacement-synthetic-secret';else config.peers[0].name='Cosmetic change';
    patchDevice({concurrentWrite:'load'});
    expectError(apply(config),'rollback_failed');
    assert.equal(device().concurrentObserved,true);
    assert.equal(rawConfig('network').wg0.private_key,'concurrent-new-wireguard-key');
    assert.equal(device().sas.rp_00000002.number,preserved);
    assert.ok(device().routes.some(r=>r.type==='unreachable'&&r.metric===42759));
  }
  // Postconditions include removal, not only presence of the desired state.
  // A reload returning zero without applying deletion/MTU/address edits must
  // fail and restore the previous configuration instead of reporting success.
  for(const edit of ['delete','prefix','mtu','address']){
    reset();state=expectOk(call('get'));
    const first={...peer(1),remote_subnets:['10.78.1.1/32','10.78.1.3/32']};
    state=expectOk(apply({revision:state.revision,enabled:true,peers:[first,peer(2)]}));
    const prior=filesSnapshot(),preserved=device().sas.rp_00000002.number;
    config=nextConfig(state);
    if(edit==='delete')config.peers.shift();
    if(edit==='prefix')config.peers[0].remote_subnets.pop();
    if(edit==='mtu')config.peers[0].mtu=1300;
    if(edit==='address')config.peers[0].local_address='10.78.1.4/32';
    patchDevice({fail:'network_skip'});expectError(apply(config),'apply_failed');
    assert.deepEqual(filesSnapshot(),prior);
    assert.equal(device().sas.rp_00000002.number,preserved);
    assert.ok(!device().routes.some(r=>r.metric===42759));
  }
  // Native fw4 ignores disabled or duplicate zones and restricts IPv6-only
  // zones without making `fw4 check` fail. Reject unusable IPv4 uplinks before
  // publishing anything, even if device commands would all return success.
  for (const alter of [
    ...['0','off','false','no','invalid'].map(value => text =>
      text.replace(" option name 'uplink'", " option name 'uplink'\n option enabled '"+value+"'")),
    ...['ipv6','inet6','invalid'].map(value => text =>
      text.replace(" option name 'uplink'", " option name 'uplink'\n option family '"+value+"'")),
    text => "config zone 'other'\n option name 'uplink'\n list network 'other'\n"+text,
    text => text+"config zone 'other'\n option name 'uplink'\n list network 'other'\n"
  ]) {
    reset();fs.writeFileSync(path.join(configDir,'firewall'),alter(read('firewall')));
    const current=expectOk(call('get')),before=filesSnapshot();patchDevice({calls:[]});
    expectError(apply({revision:current.revision,enabled:true,peers:[peer(1)]}),'unmanaged_config');
    assert.deepEqual(filesSnapshot(),before);
    assert.ok(!device().calls.some(c=>['init','network','firewall','fw4'].includes(c[0])));
    assert.deepEqual(device().routes,[]);
  }
  reset();fs.writeFileSync(path.join(configDir,'firewall'),read('firewall').replace(
    " option name 'uplink'", " option name 'uplink'\n option enabled 'yes'\n option family 'ipv4'"));
  state=expectOk(call('get'));expectOk(apply({revision:state.revision,enabled:true,peers:[peer(1)]}));
  // Exercise the resource ceiling with real UCI parsing, not just model mocks.
  reset();state=expectOk(call('get'));
  const group=Array.from({length:64},(_,i)=>({...peer(i+1),remote_subnets:Array.from({length:4},(_,j)=>'10.79.'+(i+1)+'.'+(j+1)+'/32')}));
  const scaleStart=Date.now();state=expectOk(apply({revision:state.revision,enabled:true,peers:group}));
  assert.equal(state.peers.length,64);assert.equal(Object.keys(device().sas).length,64);
  assert.equal(device().routes.filter(r=>r.type==='unreachable'&&r.metric===42760).length,256);
  assert.ok(!device().routes.some(r=>r.metric===42759));assert.deepEqual(rawConfig('network').wg0,original.wg0);
  const scaleMs=Date.now()-scaleStart;
  const scaleFiles=filesSnapshot();config=nextConfig(state);config.peers[0].remote_subnets.push('10.90.1.1/32');config.peers[0].enabled=false;
  expectError(apply(config),'invalid_config');assert.deepEqual(filesSnapshot(),scaleFiles);
  // Batch credential rotation and disable must still reconcile the complete
  // native connection set, not restart the service or leave stale credentials.
  const beforeRotation=device().sas;
  config=nextConfig(state);for(const p of config.peers)p.psk='rotated-synthetic-secret-'+p.id;
  patchDevice({calls:[]});state=expectOk(apply(config));
  for(const [name,sa]of Object.entries(beforeRotation))assert.notEqual(device().sas[name].number,sa.number);
  assert.equal(device().calls.filter(c=>c.includes('--terminate')).length,64);
  assert.equal(device().calls.some(c=>c[0]==='init'&&c[1]==='stop'),false);
  config=nextConfig(state);for(const p of config.peers)p.enabled=false;
  state=expectOk(apply(config));assert.equal(Object.keys(device().sas).length,0);
  assert.deepEqual(device().keys,[]);assert.equal(state.ready,true);
  assert.equal(device().routes.filter(r=>r.type==='unreachable'&&r.metric===42760).length,256);
  config=nextConfig(state);config.peers=[];state=expectOk(apply(config));
  assert.equal(state.peers.length,0);assert.equal(device().routes.length,0);
  assert.deepEqual(rawConfig('network'),original);assert.equal(state.ready,true);
  config=nextConfig(state);config.enabled=false;state=expectOk(apply(config));
  assert.equal(state.ready,false);
  for(const name of fs.readdirSync(configDir))assert.ok(!name.startsWith('.relay-ipsec-'),'No request snapshot may leak after completion');
  assert.deepEqual(fs.readdirSync(workerPaths.runtime),[],'Private diagnostic files are auto-unlinked');
  console.log('RelayOS IPsec native runtime: '+assertions+' result checks; real ucode/UCI, simulated device, peer isolation/redaction/guards/rollback/ownership OK');
  console.log('Host fixture resource ceiling: 64 peers / 256 prefixes applied in '+scaleMs+' ms (not router performance or crypto throughput)');
} finally { fs.rmSync(fixture,{recursive:true,force:true}); }
