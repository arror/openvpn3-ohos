#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
let ts;try{ts=require(process.env.TYPESCRIPT_PATH||'typescript');}catch{ts=require('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript');}
const source=fs.readFileSync(path.join(process.env.ARKOVPN_APP_ROOT || path.join(__dirname,'../ohos'),'entry/src/ohosTest/ets/test/LabReadiness.ets'),'utf8');
const sandbox={exports:{},Error,Promise,setTimeout,console:{info(){}}};
vm.runInNewContext(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS}}).outputText,sandbox);
(async()=>{
 let calls=0;await sandbox.exports.waitForLabReady(async()=>{++calls;return true;});assert.equal(calls,1);
 calls=0;await sandbox.exports.waitForLabReady(async()=>{if(++calls===1)throw new Error('LAB_TRANSPORT:health:2300028');return true;});assert.equal(calls,2);
 calls=0;await assert.rejects(sandbox.exports.waitForLabReady(async()=>{++calls;throw new Error('LAB_TRANSPORT:health:2300028');}),/2300028/);assert.equal(calls,3);
 calls=0;await assert.rejects(sandbox.exports.waitForLabReady(async()=>{++calls;throw new Error('LAB_CONTROL:403');}),/403/);assert.equal(calls,1);
 calls=0;await assert.rejects(sandbox.exports.waitForLabReady(async()=>{++calls;return false;}),/LAB_HEALTH_INVALID/);assert.equal(calls,1);
 console.log('Lab readiness regressions passed: 5 (only idempotent health transport failures retry)');
})().catch(e=>{console.error(e);process.exitCode=1});
