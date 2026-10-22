#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
let ts; try { ts = require(process.env.TYPESCRIPT_PATH || 'typescript'); }
catch { ts = require('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript'); }
const root = process.env.ARKOVPN_APP_ROOT || path.join(__dirname, '../ohos');
function load(file, globals = {}) {
  if (globals.Nav) for (const [key, value] of Object.entries({ getAllPathName: () => [], getParamByIndex: () => undefined, size: () => 0 })) {
    if (!(key in globals.Nav.stack)) globals.Nav.stack[key] = value;
  }
  if (file === 'CertificateImportService' || file === 'CertificateImportPrompt') {
    globals = { CertificateKeyProtection: load('CertificateKeyProtection', globals).CertificateKeyProtection, ...globals };
  }
  if (file === 'CertificateImportService') {
    const prompt = load('CertificateImportPrompt', { ...globals, ObservedV2: value => value, Trace: () => {} });
    globals = { CertificateImportPrompt: prompt.CertificateImportPrompt, certificatePasswordRequest: prompt.certificatePasswordRequest, ...globals };
  }
  const source = fs.readFileSync(path.join(root, 'entry/src/main/ets/modules/config', file + '.ets'), 'utf8').replace(/^import .*\n/gm, '').replace(/^export \{ CertificatePasswordRequest \} from.*\n/gm, '');
  const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS } }).outputText;
  const box = { exports: {}, ObservedV2: value => value, Trace: () => {}, OvpnGeneratePrivateKeyPassword: () => require('node:crypto').randomBytes(32).toString('hex'), FrameCallback: class {}, Error, ArrayBuffer, Uint8Array, JSON, OvpnImportCertificates: async files => ({ errorCode: files[0]?.data.byteLength === 0 ? 'EMPTY_FILE' : '', certificates: [], keys: [], fileIndex: -1 }), ...globals }; vm.runInNewContext(code, box); return box.exports;
}
const model = load('CertificateImportModel');
const cert = (id, ca, pub, fileIndex, issuers = [], issuer = id) => ({ id, ca, publicKeyId: pub, fileIndex, issuerIds: issuers,
  name: id, issuer, selfSigned: issuer === id, pem: `PEM-${id}`, validFrom: '', validTo: '', algorithm: 'RSA', expired: false, clientUsage: true });
const result = { errorCode: '', fileIndex: -1, unverifiedIntegrity: false, certificates: [cert('root', true, 'root-key', 0),
  cert('client', false, 'key', 1, ['inter'], 'inter'), cert('inter', true, 'inter-key', 3, ['root'], 'root')],
  keys: [{ id: 'key', fileIndex: 2, pem: 'ENCRYPTED-KEY', encrypted: true, algorithm: 'RSA' }] };
const files = Array.from({ length: 4 }, () => ({ data: new ArrayBuffer(1), password: 'source password', passwordProvided: true, outputPassword: 'ab'.repeat(32) }));
const before = { ca: 'old-ca', cert: 'old-cert', key: 'old-key', extraCerts: 'old-chain', password: 'old-password' };
let passed = 0;
function test(name, action) { action(); ++passed; console.log('PASS certificate import:', name); }
function throws(code, action) { assert.throws(action, e => e.message === code); }
test('bulk classifies all three types without names/extensions', () => {
  const choice = model.initialCertificateSelection(result, 'all');
  assert.equal(choice.certId, 'client'); assert.equal(choice.keyId, 'key'); assert.deepEqual([...choice.caIds], []);
});
test('PFX additional CAs are not implicitly trusted', () => {
  const pfx = structuredClone(result); pfx.certificates.forEach(c => c.fileIndex = 0); pfx.keys[0].fileIndex = 0;
  assert.equal(model.initialCertificateSelection(pfx, 'all').caIds.length, 0);
});
test('pure preparation preserves original and keeps chain separate from trust', () => {
  const choice = model.initialCertificateSelection(result, 'all'); choice.caIds = ['root'];
  const next = model.prepareCertificateDraft(before, result, choice, files, 'all');
  assert.equal(next.ca, 'PEM-root'); assert.equal(next.extraCerts, 'PEM-inter'); assert.equal(next.password, files[2].outputPassword);
  assert.equal(before.cert, 'old-cert'); assert.equal(before.password, 'old-password');
});
test('missing selected fields preserve their original value', () => {
  const next = model.prepareCertificateDraft(before, result, { caIds: ['root'], certId: '', keyId: '', chainIndex: 0 }, files, 'all');
  assert.equal(next.cert, before.cert); assert.equal(next.key, before.key); assert.equal(next.password, before.password); assert.equal(next.extraCerts, before.extraCerts);
});
test('certificate replacement clears stale chain', () => {
  const r = structuredClone(result); r.certificates = [cert('new', false, 'new-key', 0)]; r.keys = [];
  const next = model.prepareCertificateDraft(before, r, { caIds: [], certId: 'new', keyId: '', chainIndex: 0 }, files, 'cert');
  assert.equal(next.extraCerts, '');
});
test('mismatched imported identities fail without modifying draft', () => {
  const r = structuredClone(result); r.keys[0].id = 'other';
  throws('KEY_MISMATCH', () => model.prepareCertificateDraft(before, r, { caIds: [], certId: 'client', keyId: 'other', chainIndex: 0 }, files, 'all'));
  assert.equal(before.cert, 'old-cert');
});
test('all-or-nothing failed batch', () => {
  throws('INVALID_FORMAT', () => model.prepareCertificateDraft(before, { ...result, errorCode: 'INVALID_FORMAT' },
    { caIds: ['root'], certId: '', keyId: '', chainIndex: 0 }, files, 'all'));
});
test('target-specific import cannot overwrite unrelated fields', () => {
  const choice = model.initialCertificateSelection(result, 'key');
  const next = model.prepareCertificateDraft(before, result, choice, files, 'key');
  assert.equal(next.ca, before.ca); assert.equal(next.cert, before.cert); assert.equal(next.extraCerts, before.extraCerts);
  throws('TARGET_MISMATCH', () => model.prepareCertificateDraft(before, result, { ...choice, certId: 'client' }, files, 'key'));
});
test('chain-only import preserves trust and identity', () => {
  const next = model.prepareCertificateDraft(before, result, { caIds: ['inter'], certId: '', keyId: '', chainIndex: 0 }, files, 'chain');
  assert.equal(next.ca, before.ca); assert.equal(next.cert, before.cert); assert.equal(next.extraCerts, 'PEM-inter');
});
test('no accidental selection when several matching identities exist', () => {
  const r = structuredClone(result); r.certificates.push(cert('second', false, 'key2', 4)); r.keys.push({ id: 'key2', fileIndex: 4 });
  const choice = model.initialCertificateSelection(r, 'all'); assert.equal(choice.certId, ''); assert.equal(choice.keyId, '');
});
test('cross-signed chains require explicit path selection', () => {
  const r = structuredClone(result); r.certificates[1].issuerIds.push('inter2');
  r.certificates.push(cert('inter2', true, 'other-inter', 4, ['root'], 'root'));
  assert.equal(model.certificateChains('client', r.certificates).length, 2);
  throws('CHAIN_REQUIRED', () => model.prepareCertificateDraft(before, r, { caIds: [], certId: 'client', keyId: 'key', chainIndex: -1 }, files, 'all'));
});
test('cyclic chain rejected', () => {
  const r = structuredClone(result); r.certificates[0].issuer = 'inter'; r.certificates[0].issuerIds = ['inter']; r.certificates[0].selfSigned = false;
  throws('CHAIN_INVALID', () => model.certificateChains('client', r.certificates));
});
test('unprotected key cannot enter a draft and source password cannot become storage password', () => {
  const r = structuredClone(result); r.keys[0].encrypted = false;
  throws('KEY_PROTECTION_FAILED',()=>model.prepareCertificateDraft(before,r,{caIds:[],certId:'',keyId:'key',chainIndex:0},files,'key'));
  const missing=structuredClone(files);missing[2].outputPassword='';
  throws('KEY_PROTECTION_FAILED',()=>model.prepareCertificateDraft(before,result,{caIds:[],certId:'',keyId:'key',chainIndex:0},missing,'key'));
});
test('output key password wins over container password', () => {
  const f = structuredClone(files); f[2].outputPassword = 'new private key password';
  assert.equal(model.prepareCertificateDraft(before, result, { caIds: [], certId: '', keyId: 'key', chainIndex: 0 }, f, 'key').password, f[2].outputPassword);
});
test('empty selection never clears existing fields', () => throws('NO_SELECTION', () => model.prepareCertificateDraft(before, result,
  { caIds: [], certId: '', keyId: '', chainIndex: 0 }, files, 'all')));

test('merged provenance lists every origin without repeating an origin', () => {
  assert.equal(model.certificateSources(1, [0, 1, 1, 2], ['CA.der', 'bundle.pfx', 'key.pem']), 'CA.der、bundle.pfx、key.pem');
});
test('identical basenames retain distinct input identities', () => {
  assert.equal(model.certificateSources(0, [0, 1], ['证书.pem', '证书.pem']), '证书.pem（文件 1）、证书.pem（文件 2）');
});
test('missing source metadata has a safe index fallback', () => {
  assert.equal(model.certificateSources(2, undefined, ['CA.der']), '文件 3');
});
test('multi-level chain exports both intermediates but not its root', () => {
  const r = structuredClone(result); r.certificates[1].issuerIds = ['lower'];
  r.certificates.push(cert('lower', true, 'lower-key', 2, ['inter'], 'inter'));
  const paths = model.certificateChains('client', r.certificates);
  assert.deepEqual([...paths[0].ids], ['lower', 'inter']); assert.equal(paths[0].anchorId, 'root');
  const next = model.prepareCertificateDraft(before, r, { caIds: [], certId: 'client', keyId: 'key', chainIndex: 0 }, files, 'all');
  assert.equal(next.extraCerts, 'PEM-lowerPEM-inter'); assert.equal(next.ca, before.ca);
});
test('cross-signed alternatives identify their root and export only the chosen path', () => {
  const r = structuredClone(result); r.certificates.push(cert('root2', true, 'root2-key', 0));
  r.certificates.push(cert('inter2', true, 'inter-key', 3, ['root2'], 'root2')); r.certificates[1].issuerIds.push('inter2');
  const paths = model.certificateChains('client', r.certificates);
  assert.equal(paths.length, 2); assert.notEqual(paths[0].label, paths[1].label);
  const next = model.prepareCertificateDraft(before, r, { caIds: [], certId: 'client', keyId: 'key', chainIndex: 1 }, files, 'all');
  assert.equal(next.extraCerts, 'PEM-inter2'); assert.equal(next.ca, before.ca);
});
test('expiry presentation uses an unambiguous compact date with a safe fallback', () => {
  assert.equal(model.certificateExpiry('Jan  1 00:00:00 2040 GMT'), '2040-01-01');
  assert.equal(model.certificateExpiry('Dec 31 23:59:59 2027 GMT'), '2027-12-31');
  assert.equal(model.certificateExpiry('custom value'), 'custom value'); assert.equal(model.certificateExpiry(''), '未知');
});
test('explicit chain omission clears stale chain while preserving trust',()=>{
  const next=model.prepareCertificateDraft(before,result,{caIds:[],certId:'client',keyId:'key',chainIndex:-2},files,'all');
  assert.equal(next.extraCerts,'');assert.equal(next.ca,before.ca);
  const untouched=model.prepareCertificateDraft(before,result,{caIds:['root'],certId:'',keyId:'',chainIndex:-2},files,'all');
  assert.equal(untouched.extraCerts,before.extraCerts);
  throws('CHAIN_REQUIRED',()=>model.prepareCertificateDraft(before,result,{caIds:[],certId:'client',keyId:'key',chainIndex:-3},files,'all'));
});
function navigationHarness(extra = {}) {
  const entries = [{ name: 'editor', param: {} }], events = [];
  const Nav = { stack: {
    getAllPathName: () => entries.map(p => p.name), getParamByIndex: i => entries[i]?.param, size: () => entries.length,
    pushPath(p, animated) { assert.equal(animated, true); events.push('push'); entries.push(p); },
    replacePath() { throw new Error('replace must never be used'); },
    removeByIndexes(indexes) { assert.equal(indexes.includes(entries.length - 1), false); events.push('prune');
      [...indexes].sort((a,b) => b-a).forEach(i => entries.splice(i, 1)); return indexes.length; },
    pop(animated) { assert.equal(animated, true); events.push('pop'); entries.pop(); }
  } };
  const service = load('CertificateImportService', { Nav, PageName: { OPEN_VPN_CERTIFICATE_IMPORT_PAGE: 'review', OPEN_VPN_CERTIFICATE_FILES_PAGE: 'files' }, ...extra }).CertificateImportService;
  const args = { form: {}, files: [{ data: new Uint8Array([7]).buffer, password: 'secret', passwordProvided: true, outputPassword: '' }], names: ['key'], target: 'all', before };
  service.attach(args); entries.push({ name: 'review', param: args });
  return { service, entries, events, args, Nav };
}
for (const scenario of ['shown', 'cancel-before-shown', 'stale-shown', 'unrelated-same-name', 'stale-different-flow']) {
  test('scoped review route cleanup: ' + scenario, () => {
    const {service,args,entries,events,Nav}=navigationHarness();
    const next={...args,files:[{data:new Uint8Array([9]).buffer,password:'',passwordProvided:false,outputPassword:''}],flow:undefined,routeId:undefined};
    service.attach(next);next.flow.retired=[args.flow.id];
    if(scenario==='unrelated-same-name') entries.push({name:'review',param:{...next,flow:{id:999,closed:false,owner:1},routeId:1}});
    Nav.stack.pushPath({name:'review',param:next},true);
    if(scenario==='stale-different-flow') {service.cancel(args);assert.equal(entries.length,3);assert.equal(new Uint8Array(args.files[0].data)[0],7);return;}
    if(scenario==='stale-shown') {service.shown(args);assert.deepEqual(events,['push']);}
    if(scenario==='cancel-before-shown') {service.cancel(next);assert.deepEqual(events,['push','prune','pop']);assert.equal(entries.length,1);return;}
    service.shown(next);assert.deepEqual(events,['push','prune']);
    assert.equal(entries.length,scenario==='unrelated-same-name'?3:2);assert.equal(new Uint8Array(next.files[0].data)[0],9);
    assert.equal(args.files.length,0);service.cancel(next);assert.equal(next.files.length,0);
  });
}

async function ioTests() {
  for(const mode of ['plain','encrypted','error','unprotected','locked']) {
    let calls=0, seen;
    const protection=load('CertificateKeyProtection',{util:{TextEncoder:class{encodeInto(s){return new TextEncoder().encode(s)}}},async OvpnImportCertificates(inputs){calls++;seen=inputs;
      assert.equal(inputs[0].outputPassword.length,64);assert.notEqual(inputs[0].outputPassword,inputs[0].password);
      return {errorCode:mode==='error'?'UNLOCK_FAILED':'',certificates:[],keys:[{pem:'ENCRYPTED RESULT',encrypted:mode!=='unprotected'}]};}}).CertificateKeyProtection;
    const text=mode==='locked'?'ENCRYPTED PRIVATE KEY':'SOURCE PRIVATE KEY';
    if(['error','unprotected'].includes(mode))await assert.rejects(protection.protect(text,'source'),e=>['UNLOCK_FAILED','KEY_PROTECTION_FAILED'].includes(e.message));
    else{const secured=await protection.protect(text,mode==='encrypted'?'source':'');assert.equal(secured.key,mode==='locked'?text:'ENCRYPTED RESULT');assert.equal(secured.password.length,mode==='locked'?0:64);}
    assert.equal(calls,mode==='locked'?0:1);if(seen){assert.equal(seen[0].password,'');assert.equal(seen[0].outputPassword,'');assert(new Uint8Array(seen[0].data).every(v=>v===0));}++passed;
  }
  for (const fault of ['none', 'open', 'read', 'close', 'read-close', 'empty', 'oversize']) {
    let closed = 0, calls = 0; const logs = [];
    const api = { OpenMode: { READ_ONLY: 1 }, async open() { if (fault === 'open') throw new Error('open'); return { fd: 3 }; },
      async read(fd, buffer, options) { assert.equal(fd, 3); assert.equal(options.offset, calls * 3); ++calls;
        if (fault.startsWith('read')) throw new Error('read');
        if (fault === 'oversize') { new Uint8Array(buffer).fill(1); return buffer.byteLength; }
        if (fault === 'empty' || calls > 2) return 0; new Uint8Array(buffer).set([1, 2, 3]); return 3; },
      async close() { ++closed; if (fault.includes('close')) throw new Error('close'); } };
    const service = load('CertificateImportService', { fs: api, CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, console: { error: x => logs.push(x) } }).CertificateImportService;
    if (fault === 'oversize') api.read = async () => 65536;
    if (fault === 'none') assert.deepEqual([...new Uint8Array(await service.readFile('owned-uri'))], [1, 2, 3, 1, 2, 3]);
    else await assert.rejects(service.readFile('owned-uri'), e => fault === 'read-close' ? e.message === 'read' : true);
    assert.equal(closed, fault === 'open' ? 0 : 1); ++passed; console.log('PASS certificate file I/O:', fault);
  }
  for (const state of ['success', 'cancel', 'stale', 'read-failure', 'changed']) {
    let pushes = [], alerts = [], chooseOptions;
    const draft = { ...before, connectPrivateKeyPassword: before.password };
    const service = load('CertificateImportService', { CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, Keyboard: { dismiss() {} },
      picker: { DocumentSelectOptions: class {}, DocumentViewPicker: class { async select(options) { chooseOptions = options; return state === 'cancel' ? [] : ['cert']; } } },
      fileUri: { FileUri: class { constructor(uri) { this.name = uri; } } },
      Nav: { stack: { pushPath(p, animated) { assert.equal(animated, true); pushes.push(p); } } }, PageName: { OPEN_VPN_CERTIFICATE_IMPORT_PAGE: 'import', OPEN_VPN_CERTIFICATE_FILES_PAGE: 'files' },
      AlertDialogController: { show(...args) { alerts.push(args); } }, DialogButtonStyle: { Normal: 0 }
    }).CertificateImportService;
    service.readFile = async uri => { if (state === 'read-failure' && uri === 'cert') throw new Error('read');
      if (state === 'changed') draft.ca = 'changed while picker open'; return new Uint8Array([1, 2]).buffer; };
    await service.select(draft, {}, 'all', () => state !== 'stale');
    if (state !== 'stale') assert.equal(chooseOptions.maxSelectNumber, 8);
    assert.equal(pushes.length, ['success', 'read-failure'].includes(state) ? 1 : 0);
    assert.equal(alerts.length, ['changed'].includes(state) ? 1 : 0);
    if (state === 'success') { assert.equal(pushes[0].param.files.length, 1); assert.equal(pushes[0].param.files[0].data.byteLength, 2); }
    if (state !== 'changed') assert.equal(draft.ca, before.ca);
    ++passed; console.log('PASS certificate picker lifecycle:', state);
  }
  for (const target of ['all', 'ca', 'chain', 'cert', 'key']) {
    const maxFiles = 8;
    for (const count of [maxFiles, maxFiles + 1]) {
      const pushes = [], alerts = []; let chooseOptions, reads = 0;
      const service = load('CertificateImportService', { CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, Keyboard: { dismiss() {} },
        picker: { DocumentSelectOptions: class {}, DocumentViewPicker: class { async select(options) { chooseOptions = options; return Array.from({ length: count }, (_, i) => `file-${i}`); } } },
        fileUri: { FileUri: class { constructor(uri) { this.name = uri; } } },
        Nav: { stack: { pushPath(p, animated) { assert.equal(animated, true); pushes.push(p); } } }, PageName: { OPEN_VPN_CERTIFICATE_IMPORT_PAGE: 'import', OPEN_VPN_CERTIFICATE_FILES_PAGE: 'files' },
        AlertDialogController: { show(context, args) { alerts.push(args); } }, DialogButtonStyle: { Normal: 0 }
      }).CertificateImportService;
      service.readFile = async () => { ++reads; return new Uint8Array([1]).buffer; };
      await service.select({ ...before, connectPrivateKeyPassword: before.password }, {}, target);
      assert.equal(chooseOptions.maxSelectNumber, maxFiles);
      assert.equal(pushes.length, count === maxFiles ? 1 : 0);
      assert.equal(reads, count === maxFiles ? count : 0);
      if (count > maxFiles) assert.equal(alerts[0].message, model.CERTIFICATE_ERRORS.FILE_LIMIT);
      else assert.equal(pushes[0].param.target, target);
      ++passed; console.log('PASS target-specific file selection:', target, count);
    }
  }
  for (const fault of ['total-size', 'later-read', 'gone-during-read', 'replace', 'replace-cancel']) {
    const buffers = [], pushes = [], replacements = [], alerts = []; let reads = 0, alive = true;
    const service = load('CertificateImportService', { CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, Keyboard: { dismiss() {} },
      picker: { DocumentSelectOptions: class {}, DocumentViewPicker: class { async select(options) { assert.equal(options.maxSelectNumber, 8); return fault === 'replace-cancel' ? [] : ['ca', 'cert', 'key']; } } },
      fileUri: { FileUri: class { constructor(uri) { this.name = uri; } } },
      Nav: { stack: { pushPath(p, animated) { assert.equal(animated, true); pushes.push(p); }, replacePath(p, animated) { assert.equal(animated, true); replacements.push(p); } } },
      PageName: { OPEN_VPN_CERTIFICATE_IMPORT_PAGE: 'import', OPEN_VPN_CERTIFICATE_FILES_PAGE: 'files' }, AlertDialogController: { show(...args) { alerts.push(args); } }, DialogButtonStyle: { Normal: 0 }
    }).CertificateImportService;
    service.readFile = async () => {
      ++reads;
      if (fault === 'later-read' && reads === 2) throw new Error('read');
      const bytes = new Uint8Array(fault === 'total-size' ? 8 * 1024 * 1024 : 4); bytes.fill(7); buffers.push(bytes);
      if (fault === 'gone-during-read' && reads === 2) alive = false;
      return bytes.buffer;
    };
    await service.select({ ...before, connectPrivateKeyPassword: before.password }, {}, 'all', () => alive, fault.startsWith('replace'));
    assert.equal(pushes.length, ['replace', 'later-read'].includes(fault) ? 1 : 0); assert.equal(replacements.length, 0);
    assert.equal(alerts.length, fault === 'total-size' ? 1 : 0);
    if (fault === 'total-size') assert.equal(reads, 3);
    if (fault === 'gone-during-read') assert.equal(reads, 2);
    for (const bytes of buffers) assert.equal(bytes.every(b => b === (['replace', 'later-read'].includes(fault) ? 7 : 0)), true, 'failure/cancel must wipe every accumulated input');
    if (fault === 'replace') { assert.equal(pushes[0].param.files.length, 3); assert.equal(pushes[0].param.names.join(','), 'ca,cert,key'); }
    ++passed; console.log('PASS batch ownership and animated push:', fault);
  }
  {
    let opens = 0, release;
    const service = load('CertificateImportService', { CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, Keyboard: { dismiss() {} },
      picker: { DocumentSelectOptions: class {}, DocumentViewPicker: class { async select() { ++opens; return new Promise(resolve => { release = resolve; }); } } }
    }).CertificateImportService;
    const draft = { ...before, connectPrivateKeyPassword: before.password };
    const first = service.select(draft, {}); await service.select(draft, {}); assert.equal(opens, 1); release([]); await first;
    const retry = service.select(draft, {}); assert.equal(opens, 2); release([]); await retry;
    ++passed; console.log('PASS picker double-tap guard and cancellation retry');
  }
  for (const response of ['PASSWORD_REQUIRED', 'INVALID_FORMAT', 'navigation-failure']) {
    let nativeCalls = 0; const bytes = new Uint8Array([8]), pushes = [], alerts = [];
    const service = load('CertificateImportService', {
      CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS, Keyboard:{dismiss(){}},
      picker:{DocumentSelectOptions:class{},DocumentViewPicker:class{async select(){return ['source']}}},
      fileUri:{FileUri:class{constructor(){this.name='source'}}},
      async OvpnImportCertificates(){++nativeCalls; throw new Error('must inspect on file list page');},
      PageName:{OPEN_VPN_CERTIFICATE_IMPORT_PAGE:'review',OPEN_VPN_CERTIFICATE_FILES_PAGE:'files'},
      Nav:{stack:{pushPath(p,animated){assert.equal(animated,true);if(response==='navigation-failure')throw new Error('nav');pushes.push(p)}}},
      AlertDialogController:{show(...args){alerts.push(args)}},DialogButtonStyle:{Normal:0}
    }).CertificateImportService;
    service.readFile=async()=>bytes.buffer;await service.select({...before},{},'all');
    assert.equal(nativeCalls,0);assert.equal(pushes.length,response==='navigation-failure'?0:1);
    assert.equal(bytes[0],response==='navigation-failure'?0:8);
    if(pushes.length){assert.equal(pushes[0].name,'files');assert.equal(pushes[0].param.inspected,undefined);}
    assert.equal(alerts.length,response==='navigation-failure'?1:0);++passed;
  }
  {
    const {service,args,entries,events}=navigationHarness();
    entries[entries.length-1].name='files'; const bytes=new Uint8Array(args.files[0].data);
    service.review(args,result);assert.deepEqual(events,['push']);assert.equal(entries.length,3);
    const next=entries.at(-1).param;assert.equal(next.flow.id,args.flow.id);assert.notEqual(next.routeId,args.routeId);
    service.release(args);assert.equal(bytes[0],7);assert.equal(service.current(next),true);
    service.shown(next);assert.deepEqual(events,['push','prune']);assert.equal(entries.length,2);assert.equal(bytes[0],7);
    service.cancel(next);assert.equal(bytes[0],0);assert.equal(entries.length,1);++passed;
    console.log('PASS file-list to review ownership and post-shown cleanup');
  }
  {
    const h = navigationHarness({ Keyboard: { dismiss() {} }, picker: { DocumentSelectOptions: class {}, DocumentViewPicker: class { async select() { return ['new']; } } },
      fileUri: { FileUri: class { constructor() { this.name = 'new'; } } }, CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS,
      AlertDialogController: { show() { throw new Error('unexpected alert'); } }, DialogButtonStyle: { Normal: 0 } });
    const { service, args, entries, events } = h; const oldBytes = new Uint8Array(args.files[0].data), newBytes = new Uint8Array([8]);
    service.readFile = async () => newBytes.buffer; await service.select(args.form, {}, 'all', () => true, true);
    assert.deepEqual(events, ['push']); assert.equal(oldBytes[0], 7); assert.equal(entries.length, 3);
    const next = entries.at(-1).param; assert.notEqual(next.flow.id, args.flow.id);
    service.shown(next); assert.equal(entries.length, 2); assert.equal(oldBytes[0], 0); assert.equal(newBytes[0], 8);
    service.cancel(next); assert.equal(newBytes[0], 0); assert.equal(entries.length, 1);
    ++passed; console.log('PASS reselect uses push then retires only the previous flow after shown');
  }
  for (const response of ['match', 'mismatch', 'error', 'locked']) {
    let calls = 0; const service = load('CertificateImportService', { util: { TextEncoder: class { encodeInto(s) { return new TextEncoder().encode(s); } } },
      async OvpnImportCertificates() { ++calls; return { errorCode: response === 'error' ? 'UNLOCK_FAILED' : '',
        certificates: [{ ca: false, publicKeyId: 'a' }], keys: [{ id: response === 'mismatch' ? 'b' : 'a' }] }; }
    }).CertificateImportService;
    const d = { ...before, key: response === 'locked' ? 'ENCRYPTED PRIVATE KEY' : before.key, password: response === 'locked' ? '' : 'pass' };
    if (response === 'mismatch' || response === 'error') await assert.rejects(service.validatePair(d), e => e.message === (response === 'mismatch' ? 'KEY_MISMATCH' : 'UNLOCK_FAILED'));
    else await service.validatePair(d, true);
    assert.equal(calls, response === 'locked' ? 0 : 1); ++passed; console.log('PASS existing identity validation:', response);
  }

  for (const scenario of ['mixed', 'all-invalid', 'locked-before-invalid', 'stale', 'busy']) {
    const seen = [], buffers = [1, 2, 3, 4].map(n => new Uint8Array([n])); let alive = true, batches = 0;
    const service = load('CertificateImportService', { async OvpnImportCertificates(input) {
      assert.equal(input.length, 1); const n = new Uint8Array(input[0].data)[0]; seen.push(n);
      if (scenario === 'stale') alive = false;
      return { errorCode: scenario === 'busy' ? 'IMPORT_BUSY' : scenario === 'all-invalid' || n % 2 === 0 ? 'INVALID_FORMAT' : scenario === 'locked-before-invalid' ? 'PASSWORD_REQUIRED' : '', fileIndex: 0, certificates: [], keys: [] };
    } }).CertificateImportService;
    const args = { files: buffers.map(b => ({data:b.buffer,password:'',passwordProvided:false,outputPassword:''})), names:['one','two','three','four'] };
    if (scenario === 'stale' || scenario === 'busy') {
      await assert.rejects(service.checkFiles(args.files, () => alive), e => e.message === (scenario === 'busy' ? 'IMPORT_BUSY' : 'IMPORT_CANCELLED'));
      assert.deepEqual(seen, [1]);
    } else {
      const check = await service.checkFiles(args.files);
      assert.deepEqual(seen,[1,2,3,4]);
      assert.deepEqual([...check.rejected],scenario==='all-invalid'?[0,1,2,3]:[1,3]);
      assert.equal(check.items.length,4);
      if(scenario==='locked-before-invalid')assert.equal(check.items[0].state,'locked');
      const retained=service.retainRecognized(args,check);
      assert.equal(!!retained,!['all-invalid','locked-before-invalid'].includes(scenario));
      assert.equal(service.canContinue(check),!['all-invalid','locked-before-invalid'].includes(scenario));
      if(retained){assert.deepEqual([...args.names],['one','three']);assert.deepEqual([...retained.items.map(i=>i.index)],[0,1]);assert.equal(buffers[1][0],0);assert.equal(buffers[3][0],0);assert.equal(buffers[0][0],1);}

    }
    ++passed; console.log('PASS aggregate preflight:', scenario);
  }
  {
    let calls=0;const service=load('CertificateImportService',{async OvpnImportCertificates(inputs){++calls;
      const file=inputs[0];return file.passwordProvided?{...result,certificates:result.certificates,keys:result.keys}:{...result,errorCode:'PASSWORD_REQUIRED',fileIndex:0};
    }}).CertificateImportService;
    const input={data:new ArrayBuffer(1),password:'',passwordProvided:false,outputPassword:''};
    const locked=await service.checkFiles([input]);assert.equal(locked.items[0].state,'locked');assert.equal(locked.items[0].request.fileIndex,0);assert.equal(service.canContinue(locked),false);
    input.password='fixture-secret';input.passwordProvided=true;
    const unlocked=await service.checkFiles([input]);assert.equal(unlocked.items[0].state,'unlocked');assert.equal(unlocked.items[0].request,undefined);assert.equal(service.canContinue(unlocked),true);
    assert.equal(unlocked.items[0].detail,'CA 证书 · 中间证书 · 客户端证书 · 私钥');++passed;
    const invalid={index:1,state:'invalid',detail:'无法识别'};
    assert.equal(service.canContinue({accepted:[0],rejected:[1],items:[unlocked.items[0],invalid]}),true);assert.equal(service.canContinue(undefined),false);++passed;
    const untouched={files:[input],names:['locked']};const blocked={accepted:[0],rejected:[],items:locked.items};
    assert.equal(service.retainRecognized(untouched,blocked),undefined);assert.equal(untouched.files.length,1);++passed;
    console.log('PASS click-to-unlock states, material types, unknown-file skipping, and continuation gate');
  }
  const makePrompt = (native = async () => result, alerts = {show(){},close(){}}) => load('CertificateImportPrompt', {
    ObservedV2: value => value, Trace: () => {}, OvpnImportCertificates: native, Keyboard: {dismiss(){}},
    CERTIFICATE_ERRORS: model.CERTIFICATE_ERRORS, AlertDialogController: alerts, DialogButtonStyle: {Normal:0,Accent:1}
  }).CertificateImportPrompt;
  for (const scenario of ['success','retry','multiple','cancel','stale-result','invalid-password','native-failure']) {
    const inputs=[0,1].map(()=>({data:new Uint8Array([9]).buffer,password:'',passwordProvided:false,outputPassword:''}));
    let calls=0, complete; const Prompt=makePrompt(async () => {
      ++calls;
      if (scenario==='stale-result') return new Promise(resolve=>{complete=resolve});
      if (scenario==='native-failure') throw new Error('CONVERSION_FAILED');
      if (scenario==='invalid-password') return {...result,errorCode:'PASSWORD_INVALID',fileIndex:0};
      if (scenario==='retry' && calls===1) return {...result,errorCode:'UNLOCK_FAILED',fileIndex:0};
      if (scenario==='multiple' && calls===1) return {...result,errorCode:'PASSWORD_REQUIRED',fileIndex:1};
      return result;
    });
    const prompt=new Prompt(), protecting=scenario==='protect-cancel';
    const pending=prompt.open(inputs,['first.pfx','second.key'],{fileIndex:0,output:protecting,error:false},()=>true);
    prompt.password='secret'; let submitted;
    if (scenario==='cancel') prompt.cancel();
    else if (scenario==='protect-cancel') { prompt.cancel(); }
    else { submitted=prompt.submit(); if(scenario==='stale-result'){prompt.cancel();prompt.dismissed();complete(result);} await submitted; }
    if (scenario==='multiple') {
      assert.equal(prompt.visible,false);assert.equal(prompt.filename,'first.pfx');assert.equal(prompt.presentation,1);
      let frame;prompt.dismissed({postFrameCallback(callback){frame=callback}});
      await Promise.resolve();assert.equal(prompt.visible,false,'next sheet waits for a frame after native disappearance');
      assert.equal(await prompt.open(inputs,['interleaved'],{fileIndex:0,output:false,error:false},()=>true),undefined,'another import cannot steal the pending close frame');
      frame.onIdle(0);await Promise.resolve();assert.equal(prompt.presentation,2);
    }
    if (scenario==='retry' || scenario==='multiple') {
      assert.equal(prompt.visible,true); assert.equal(prompt.password,'');
      assert.equal(prompt.filename,scenario==='multiple'?'second.key':'first.pfx');
      if(scenario==='retry') {assert.equal(inputs[0].password,'');assert.equal(prompt.error,true);}
      else assert.equal(inputs[0].password,'secret');
      prompt.password='correct'; await prompt.submit();
    }
    if(['invalid-password','native-failure'].includes(scenario)) { assert.equal(prompt.visible,true);assert.equal(prompt.error,true);prompt.cancel(); }
    let resolved=false;pending.then(()=>{resolved=true});await Promise.resolve();
    if(scenario!=='stale-result') assert.equal(resolved,false,'must wait for native sheet disappearance');
    prompt.dismissed(); const outcome=await pending;
    assert.equal(!!outcome,['success','retry','multiple'].includes(scenario));
    assert.equal(prompt.password,'');assert.equal(prompt.busy,false);assert.equal(prompt.visible,false);
    if(!outcome) { assert.equal(inputs[0].password,'');assert.equal(inputs[0].passwordProvided,false);assert.equal(inputs[0].outputPassword.length,64); }
    else assert.equal(inputs[0].password,scenario==='retry'?'correct':'secret');
    ++passed;console.log('PASS password sheet lifecycle:',scenario);
  }
  {
    const protection=load('CertificateKeyProtection').CertificateKeyProtection;
    const inputs=Array.from({length:8},()=>({data:new ArrayBuffer(1),password:'container',passwordProvided:false,outputPassword:''}));
    assert.equal(protection.ensure(inputs),true);assert.equal(new Set(inputs.map(i=>i.outputPassword)).size,8);
    assert(inputs.every(i=>/^[0-9a-f]{64}$/.test(i.outputPassword)&&i.password==='container'));
    const snapshot=inputs.map(i=>i.outputPassword);assert.equal(protection.ensure(inputs),false);assert.deepEqual(inputs.map(i=>i.outputPassword),snapshot);++passed;
    for(const mode of ['throws','short','invalid']){
      const broken=load('CertificateKeyProtection',{OvpnGeneratePrivateKeyPassword(){if(mode==='throws')throw Error('entropy');return mode==='short'?'abc':'z'.repeat(64)}}).CertificateKeyProtection;
      const source={data:new ArrayBuffer(1),password:'source',passwordProvided:false,outputPassword:''};throws('KEY_PROTECTION_FAILED',()=>broken.ensure([source]));assert.equal(source.outputPassword,'');++passed;
    }
    const unsupported=load('CertificateImportPrompt').certificatePasswordRequest({...result,errorCode:'OUTPUT_PASSWORD_REQUIRED'});assert.equal(unsupported,undefined);++passed;
    console.log('PASS automatic CSPRNG protection, independent per-file secrets, retry stability, fail closed, no output-password prompt');
  }
  {
    const Prompt=makePrompt(),prompt=new Prompt();let alive=true;
    const source={data:new Uint8Array([1]).buffer,password:'prior-secret',passwordProvided:true,outputPassword:''};
    const pending=prompt.open([source],['locked.pfx'],{fileIndex:0,output:false,error:false},()=>alive);
    alive=false;source.password='';source.passwordProvided=false;prompt.cancel();prompt.dismissed();await pending;
    assert.equal(source.password,'');assert.equal(source.outputPassword,'');assert.equal(source.passwordProvided,false);++passed;
    console.log('PASS disposed single-file prompt cannot resurrect cleared credentials');
  }
  const sheetSource=fs.readFileSync(path.join(root,'entry/src/main/ets/modules/config/CertificatePasswordSheet.ets'),'utf8');
  assert.equal(sheetSource.includes('设置私钥密码'),false);assert.equal(/\bScroll\(/.test(sheetSource),false);assert.equal(sheetSource.includes('certificateUnlockFilename'),false);++passed;
  const kinds={CA:0,CERTIFICATE:1,PRIVATE_KEY:2,TLS_KEY:3,CERTIFICATE_CHAIN:4};
  const encode={TextEncoder:class{encodeInto(s){return new TextEncoder().encode(s)}},Base64Helper:class{decodeSync(s){return new Uint8Array(Buffer.from(s,'base64'))}}};
  const pem='-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----';
  const keyPem='-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----';
  const material=load('ProfileMaterialValidation',{ProfileMaterialKind:kinds,util:encode,CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS,certificateExpiry:model.certificateExpiry,
    async OvpnImportCertificates(input){const text=new TextDecoder().decode(input[0].data);return text.includes('PRIVATE KEY')?{...result,certificates:[],keys:[{algorithm:'RSA',encrypted:false}]}:{...result,certificates:[cert('test',false,'key',0)],keys:[]};}}).ProfileMaterialValidation;
  const checkMaterial=async(kind,text,state,password='',type='',current=()=>true)=>{
    assert.equal((await material.validate(kind,text,password,type,current)).state,state);++passed;
  };
  await checkMaterial(kinds.CERTIFICATE,pem,'valid');
  await checkMaterial(kinds.CA,pem,'invalid');
  await checkMaterial(kinds.CERTIFICATE_CHAIN,pem,'invalid');
  assert.equal((await material.validate(kinds.PRIVATE_KEY,keyPem)).information[0].value,'RSA');++passed;
  for(const text of ['bad',pem+'\nextra',pem.slice(0,50),keyPem])await checkMaterial(kinds.CERTIFICATE,text,'invalid');
  await checkMaterial(kinds.CERTIFICATE,'','empty');
  await checkMaterial(kinds.CERTIFICATE,pem,'empty','','',()=>false);
  for(const code of ['PASSWORD_REQUIRED','UNLOCK_FAILED','IMPORT_BUSY']){
    const v=load('ProfileMaterialValidation',{ProfileMaterialKind:kinds,util:encode,CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS,async OvpnImportCertificates(){return {...result,errorCode:code}}}).ProfileMaterialValidation;
    assert.equal((await v.validate(kinds.PRIVATE_KEY,keyPem)).state,code==='PASSWORD_REQUIRED'?'locked':code==='IMPORT_BUSY'?'pending':'invalid');++passed;
  }
  for(const flag of ['expired','usage']){
    const c=cert('leaf',false,'key',0);c.expired=flag==='expired';c.clientUsage=flag!=='usage';
    const v=load('ProfileMaterialValidation',{ProfileMaterialKind:kinds,util:encode,CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS,certificateExpiry:model.certificateExpiry,async OvpnImportCertificates(){return {...result,certificates:[c],keys:[]}}}).ProfileMaterialValidation;
    const info=await v.validate(kinds.CERTIFICATE,pem);assert.equal(info.state,'warning');assert.equal(info.information.some(i=>i.label==='有效期'),true);++passed;
  }
  {
    let active=0,maximum=0;
    const v=load('ProfileMaterialValidation',{ProfileMaterialKind:kinds,util:encode,CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS,certificateExpiry:model.certificateExpiry,async OvpnImportCertificates(){++active;maximum=Math.max(active,maximum);await Promise.resolve();--active;return {...result,certificates:[cert('leaf',false,'key',0)],keys:[]}}}).ProfileMaterialValidation;
    await Promise.all([v.validate(kinds.CERTIFICATE,pem),v.validate(kinds.CERTIFICATE,pem)]);assert.equal(maximum,1);++passed;
  }
  for (const kind of [kinds.CA,kinds.CERTIFICATE_CHAIN]) {
    const first=cert('aa'.repeat(32),true,'key-a',0,[],'Issuer A'),second=cert('bb'.repeat(32),true,'key-b',0,[],'Issuer B');
    first.name='CA A';second.name='CA B';first.selfSigned=false;second.selfSigned=false;second.expired=true;
    first.validFrom='Jan  1 00:00:00 2020 GMT';first.validTo='Jan  1 00:00:00 2030 GMT';
    second.validFrom='Feb  2 00:00:00 2021 GMT';second.validTo='Feb  2 00:00:00 2031 GMT';
    const v=load('ProfileMaterialValidation',{ProfileMaterialKind:kinds,util:encode,CERTIFICATE_ERRORS:model.CERTIFICATE_ERRORS,certificateExpiry:model.certificateExpiry,
      async OvpnImportCertificates(){return {...result,certificates:[first,second],keys:[]}}}).ProfileMaterialValidation;
    const details=await v.validate(kind,pem+'\n'+pem);
    assert.equal(details.certificates.length,2);assert.equal(details.information.length,0,'multiple certificates must never share flattened fields');
    for(const [index,c] of details.certificates.entries()){
      const field=name=>c.information.find(i=>i.label===name)?.value;
      assert.equal(field('名称'),index===0?'CA A':'CA B');assert.equal(field('签发者'),index===0?'Issuer A':'Issuer B');
      assert.equal(field('有效期'),index===0?'2020-01-01 — 2030-01-01':'2021-02-02 — 2031-02-02');
      assert.equal(field('SHA-256 指纹'),Array(32).fill(index===0?'AA':'BB').join(':'));
      assert.equal(c.warning,index===0?'':'证书已过期或尚未生效');
    }
    const preview=v.certificateDetails(second,'second.pfx');assert.equal(preview.information.find(i=>i.label==='来源').value,'second.pfx');
    ++passed;console.log('PASS independent certificate groups:',kind);
  }
  {
    const v=load('ProfileMaterialValidation',{certificateExpiry:model.certificateExpiry}).ProfileMaterialValidation;
    const first=cert('aa'.repeat(32),true,'a',0),second=cert('bb'.repeat(32),true,'b',0),third=cert('cc'.repeat(32),true,'c',0);
    first.name=second.name='Same CA name';const groups=[first,second,third].map(c=>v.certificateDetails(c));
    const remaining=v.withoutCertificate(groups,first.id);assert.deepEqual([...remaining.map(c=>c.id)],[second.id,third.id]);assert.equal(remaining.map(c=>c.pem).join(''),second.pem+third.pem);
    assert.equal(groups.length,3);assert.equal(groups[0].id,first.id);++passed;
    const middle=v.withoutCertificate(groups,second.id);assert.equal(middle.map(c=>c.pem).join(''),first.pem+third.pem);++passed;
    const last=v.withoutCertificate([groups[0]],first.id);assert.equal(last.length,0);assert.equal(last.map(c=>c.pem).join(''),'');++passed;
    throws('DRAFT_CHANGED',()=>v.withoutCertificate(groups,'missing'));++passed;
    console.log('PASS individual CA removal uses fingerprint, preserves all other PEMs, leaves snapshots unchanged, and supports final removal');
  }
  const staticKey='-----BEGIN OpenVPN Static key V1-----\n'+'ab'.repeat(256)+'\n-----END OpenVPN Static key V1-----';
  await checkMaterial(kinds.TLS_KEY,staticKey,'valid','','tls-auth');
  await checkMaterial(kinds.TLS_KEY,staticKey,'invalid','','tls-crypt-v2');
  await checkMaterial(kinds.TLS_KEY,staticKey.replace('abab','ab'),'invalid','','tls-crypt');
  const v2=(n)=>'-----BEGIN OpenVPN tls-crypt-v2 client key-----\n'+Buffer.alloc(n,7).toString('base64')+'\n-----END OpenVPN tls-crypt-v2 client key-----';
  await checkMaterial(kinds.TLS_KEY,v2(288),'valid','','tls-crypt-v2');
  for(const n of [287,1281])await checkMaterial(kinds.TLS_KEY,v2(n),'invalid','','tls-crypt-v2');
  console.log('PASS material validation: type, structure, empty, stale, encrypted, expiry, usage, serialization, TLS key formats');
  console.log('Certificate application regressions passed:', passed);
}
ioTests().catch(error => { console.error(error); process.exitCode = 1; });
