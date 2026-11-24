#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../packages/luci-theme-relay/htdocs/luci-static/resources/relay/ipsec.js'),'utf8');
const state = { enabled:false,ready:false,loaded:false,eip93:true,manual:true };
const agent = { managed:false };
let calls = [], allowed = true, next = state;
const mockFs = { exec: async (p,args) => {
  assert.equal(p,'/usr/libexec/relay-ipsec');
  assert.equal(args.length,1);
  calls.push(args[0]);
  return { code:0,stdout:JSON.stringify(next) };
}};
const E = (tag,attr,children) => ({
  tag, attr, children, appendChild(child) { this.children.push(child); }
});
const L = { hasViewPermission:()=>allowed,dom:{content:(panel,children)=>{panel.children=children;}} };
const ui = { createHandlerFn:()=>()=>{},addNotification:()=>{} };
const mod = new Function('baseclass','fs','ui','E','L','_',source)({extend:o=>o},mockFs,ui,E,L,s=>s);
(async()=>{
  assert.deepEqual(await mod.status(),state);
  assert.throws(()=>mod.decode({code:1,stdout:'{}'}));
  assert.throws(()=>mod.decode({code:0,stdout:'{}'}));
  assert.throws(()=>mod.decode({code:0,stdout:'invalid'}));
  assert.equal(mod.canChange(state,agent,false),true);
  assert.equal(mod.canChange(state,null,false),false);
  assert.equal(mod.canChange(state,{managed:true},false),false);
  assert.equal(mod.canChange({...state,manual:false},agent,false),false);
  assert.equal(mod.canChange(state,agent,true),false);
  const panel = mod.render(state,agent,false);
  assert.ok(panel.children.length);
  const controls=panel.children.at(-1).children;
  assert.equal(controls[0].attr.disabled,null);
  assert.equal(controls[1].attr.disabled,true);
  calls=[];
  allowed=false;
  await mod.change('enable',panel,agent,false);
  assert.deepEqual(calls,[]);
  allowed=true;
  await mod.change('other',panel,agent,false);
  assert.deepEqual(calls,[]);
  next={...state,manual:false};
  await mod.change('enable',panel,agent,false);
  assert.ok(!calls.includes('enable'));
  calls=[]; next={...state,enabled:true,ready:true};
  await mod.change('enable',panel,agent,false);
  assert.deepEqual(calls,['status','enable']);
  assert.equal(panel.children.at(-1).children[0].attr.disabled,true);
  assert.equal(panel.children.at(-1).children[1].attr.disabled,null);
  console.log('RelayOS IPsec UI: status schema, fixed commands, read-only and Agent ownership OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
