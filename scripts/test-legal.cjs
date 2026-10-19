#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
let ts;try{ts=require(process.env.TYPESCRIPT_PATH||'typescript');}catch{ts=require('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript');}
const app=process.env.ARKOVPN_APP_ROOT||path.join(__dirname,'../ohos');
const source=fs.readFileSync(path.join(app,'entry/src/main/ets/modules/settings/OpenSourceData.ets'),'utf8').replace(/^import .*\n/gm,'');
const code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS}}).outputText;
let override=new Map(),calls=0;
const sandbox={exports:{},Error,JSON,Array,util:{TextDecoder:class{decodeToString(bytes){return Buffer.from(bytes).toString('utf8');}}},AppContext:{getContext(){return{resourceManager:{async getRawFileContent(name){++calls;if(override.has(name)){const value=override.get(name);if(value instanceof Error)throw value;return Buffer.from(value);}return fs.readFileSync(path.join(app,'entry/src/main/resources/rawfile',name));}}};}}};
vm.runInNewContext(code,sandbox);const api=sandbox.exports;
(async()=>{
 const items=await api.readLegalComponents();assert.equal(items.length,6);assert.equal(new Set(items.map(i=>i.id)).size,items.length);
 for(const item of items){const original=await api.readLegalText(item.file);assert.ok(original.length>500);assert.equal(api.reflowLicenseText(original).replace(/\s/g,''),original.replace(/\s/g,''));}
 let source=await api.readSourceInformation();assert.equal(source.url,'https://github.com/arror/openvpn3-ohos');assert.equal(source.placeholder,false);
 calls=0;await assert.rejects(api.readLegalText('../private.json'),/INVALID_LEGAL_RESOURCE/);assert.equal(calls,0);
 override.set('licenses/MPL-2.0.txt',new Error('injected'));await assert.rejects(api.readLegalText('MPL-2.0.txt'),/LEGAL_RESOURCE_READ_FAILED/);
 override.set('licenses/components.json','[]');await assert.rejects(api.readLegalComponents(),/INVALID_LEGAL_COMPONENTS/);
 override.set('licenses/components.json','invalid-json');await assert.rejects(api.readLegalComponents());
 override.set('licenses/source.json',JSON.stringify({url:'http://invalid',placeholder:false,license:'MPL-2.0'}));await assert.rejects(api.readSourceInformation(),/INVALID_SOURCE_INFORMATION/);
 console.log('Legal resource regressions passed: 9 (catalog, full texts, exact source URL, lossless paragraph reflow, traversal, read errors, empty/malformed catalog, invalid URL)');
})().catch(e=>{console.error(e);process.exitCode=1});
