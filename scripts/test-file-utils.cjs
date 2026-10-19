#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
let ts;try{ts=require(process.env.TYPESCRIPT_PATH||'typescript');}catch{ts=require('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript');}
const source=fs.readFileSync(path.join(process.env.ARKOVPN_APP_ROOT || path.join(__dirname,'../ohos'),'entry/src/main/ets/utils/FileUtils.ets'),'utf8').replace(/^import .*\n/gm,'');
const code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS}}).outputText;
let passed=0;
for(const fault of ['none','open','write','short','sync','close','write-and-close']){
 let closes=0,syncs=0;const logs=[];const error=stage=>Object.assign(new Error('injected-'+stage),{code:stage});
 const sandbox={exports:{},Error,console:{error:x=>logs.push(x)},util:{TextEncoder:class{encodeInto(s){return Buffer.from(s,'utf8');}}},fs:{OpenMode:{READ_WRITE:1,CREATE:2,TRUNC:4},
 openSync(){if(fault==='open')throw error('open');return{fd:23};},
 writeSync(fd,s){assert.equal(fd,23);if(fault==='write'||fault==='write-and-close')throw error('write');return Buffer.byteLength(s)-(fault==='short'?1:0);},
 fsyncSync(){++syncs;if(fault==='sync')throw error('sync');},
 closeSync(){++closes;if(fault==='close'||fault==='write-and-close')throw error('close');}}};
 vm.runInNewContext(code,sandbox);let thrown;
 try{sandbox.exports.FileUtils.writeTextSync('/test-owned-path','配置');}catch(e){thrown=e;}
 if(fault==='none'){assert.equal(thrown,undefined);assert.equal(syncs,1);}else{assert.ok(thrown);assert.ok(thrown.message.length>0);}
 assert.equal(closes,fault==='open'?0:1);
 if(fault==='write-and-close'){assert.match(thrown.message,/injected-write/);assert.equal(logs.length,1);}
 if(fault==='close')assert.match(thrown.message,/关闭文件失败/);
 if(fault==='short')assert.match(thrown.message,/写入不完整/);
 console.log('PASS durable write:',fault);++passed;
}
console.log('File error regressions passed:',passed);
