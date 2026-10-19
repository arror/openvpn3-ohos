#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Execute the production ArkTS adapter with controlled platform promises and time.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
let ts;
try { ts = require(process.env.TYPESCRIPT_PATH || 'typescript'); }
catch { ts = require('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript'); }
const source = fs.readFileSync(process.env.TUN_PROXY_SOURCE || path.join(process.env.ARKOVPN_APP_ROOT || path.join(__dirname, '../ohos'), 'entry/src/main/ets/vpn/TunProxyClient.ets'), 'utf8').replace(/^import .*\n/gm, '');
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS } }).outputText;
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 35; ++i) await Promise.resolve(); };
function harness() {
  let now = 0, timerId = 0, pid = 0, connectionId = 0, nextFd = 100;
  const timers = new Map(), connections = new Map(), closed = [], logs = [];
  const h = { starts: 0, stops: 0, binds: 0, unbinds: 0, current: undefined, startGate: undefined, stopGate: undefined, unbindGate: undefined, failStop: false };
  class Parcel {
    value = ''; fd = -1;
    writeInterfaceToken() {} writeString(v) { this.value = v; } readString() { return this.value; }
    writeRemoteObject() {} containFileDescriptors() { return this.fd >= 0; }
    readFileDescriptor() { const fd = this.fd; this.fd = -1; return fd; } reclaim() { if (this.fd >= 0) closed.push(this.fd); this.fd = -1; }
  }
  class Remote {
    dead = false; recipients = new Set(); id = `process-${++pid}`; attempted = false; createGate = undefined; helloGate = undefined;
    registerDeathRecipient(r) { if (h.failWatch) throw new Error('injected-watch-registration'); this.recipients.add(r); }
    unregisterDeathRecipient(r) { this.recipients.delete(r); }
    isObjectDead() { return this.dead; }
    die() { if (this.dead) return; this.dead = true; for (const r of this.recipients) r.onRemoteDied(); }
    async sendMessageRequest(code, data, reply) {
      const req = JSON.parse(data.value);
      if (code === 1 && this.helloGate) await this.helloGate.promise;
      if (code === 2) { this.attempted = true; if (this.createGate) await this.createGate.promise; reply.fd = nextFd++; }
      reply.value = JSON.stringify({ protocolVersion: 2, status: 'ok', tunId: req.tunId, processInstanceId: this.id, createAttempted: this.attempted });
      return { errCode: 0, reply };
    }
  }
  const context = {
    connectServiceExtensionAbility(want, callbacks) {
      ++h.binds; const id = ++connectionId; connections.set(id, callbacks);
      // Preserve actual asynchronous onConnect ordering.
      Promise.resolve().then(() => callbacks.onConnect({}, h.current)); return id;
    },
    disconnectServiceExtensionAbility(id) {
      ++h.unbinds;
      const complete = () => { connections.get(id)?.onDisconnect(); connections.delete(id); };
      if (h.unbindGate) return h.unbindGate.promise.then(complete);
      complete(); return Promise.resolve();
    }
  };
  const sandbox = { exports: {}, Promise, Set, Error, Math, JSON, console: { error: (...args) => logs.push(args.join(' ')) },
    Date: class extends Date { static now() { return now; } },
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, at: now + ms }); return id; }, clearTimeout(id) { timers.delete(id); },
    rpc: { RemoteObject: class {}, MessageOption: class { static TF_ACCEPT_FDS = 1; setFlags() {} setWaitTime() {} }, MessageSequence: { create: () => new Parcel(), closeFileDescriptor: fd => closed.push(fd), dupFileDescriptor: () => nextFd++ } },
    VPN_BUNDLE: 'com.arror.ovpn', VPN_ABILITY: 'VpnAbility', TUN_PROTOCOL_VERSION: 2, TUN_DESCRIPTOR: 'test', TunOperationCode: { Hello: 1, Create: 2, Claim: 3, Release: 6 },
    ovpn: { OvpnNotifyTunEvent() {} }, AppContext: { getContext: () => context },
    vpnExtension: {
      startVpnExtensionAbility() {
        ++h.starts;
        const complete = () => { h.current = new Remote(); };
        if (h.startGate) return h.startGate.promise.then(complete);
        complete(); return Promise.resolve();
      },
      stopVpnExtensionAbility() {
        ++h.stops;
        if (h.failStop) return Promise.reject(Object.assign(new Error('injected'), { code: 123 }));
        const complete = () => h.current?.die();
        if (h.stopGate) return h.stopGate.promise.then(complete);
        complete(); return Promise.resolve();
      }
    }
  };
  vm.runInNewContext(compiled, sandbox);
  h.client = new sandbox.exports.TunProxyClient(); h.closed = closed; h.logs = logs;
  h.advance = async ms => {
    const end = now + ms;
    await flush();
    for (;;) {
      const candidates = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at);
      if (!candidates.length) break;
      const [id, t] = candidates[0]; now = t.at; timers.delete(id); t.fn(); await flush();
    }
    now = end; await flush();
  };
  return h;
}
function tracked(promise) { const result = { status: 'pending', error: '' }; promise.then(value => { result.status = 'resolved'; result.value = value; }, error => { result.status = 'rejected'; result.error = error.message; }); return result; }
const request = (session = 'one', tun = 'tun-one') => ({ engineInstanceId: 'engine', sessionId: session, attemptId: 'attempt-' + session, tunId: tun, config: { addresses: [], routes: [] } });
async function retire(h, req) { const result = tracked(h.client.release(req)); await h.advance(500); assert.equal(result.status, 'resolved', result.error); }
const tests = [];
function test(name, run) { tests.push({ name, run }); }
test('unsettled start cannot hold stop; late start is stopped before a new process', async () => {
  const h = harness(), req = request(); h.startGate = deferred();
  const prepare = tracked(h.client.prepare(req)); await flush();
  const release = tracked(h.client.release(req)); assert.equal(h.stops, 1);
  await h.advance(10000); assert.equal(prepare.status, 'rejected'); assert.equal(release.status, 'rejected'); assert.match(release.error, /START_UNSETTLED/);
  const blocked = tracked(h.client.prepare(request('two'))); await flush(); assert.equal(blocked.status, 'rejected'); assert.equal(h.starts, 1);
  h.startGate.resolve(); await flush(); assert.ok(h.current.dead); assert.ok(h.stops >= 2); assert.equal(h.binds, 0);
  h.startGate = undefined; await retire(h, req); await h.client.prepare(request('two')); assert.equal(h.starts, 2); assert.ok(!h.current.dead);
  await retire(h, request('two'));
});
test('hung create is retired independently; late fd closes without stopping new owner', async () => {
  const h = harness(), req = request(); await h.client.prepare(req);
  const old = h.current; old.createGate = deferred(); const create = tracked(h.client.create(req)); await flush();
  await retire(h, req); await h.client.prepare(request('two')); const fresh = h.client.processIdentity, stops = h.stops;
  old.createGate.resolve(); await flush(); assert.equal(create.status, 'rejected'); assert.ok(h.closed.length > 0); assert.equal(h.client.processIdentity, fresh); assert.equal(h.stops, stops); assert.ok(!h.current.dead);
  await retire(h, request('two'));
});
test('hung unbind does not prevent stop; a real retry finishes after unbind settles', async () => {
  const h = harness(), req = request(); await h.client.prepare(req); h.unbindGate = deferred();
  const release = tracked(h.client.release(req)); assert.equal(h.stops, 1); await h.advance(10000); assert.equal(release.status, 'rejected'); assert.ok(h.current.dead);
  h.unbindGate.resolve(); await flush(); h.unbindGate = undefined; await retire(h, req); assert.ok(h.stops >= 2);
});
test('failed stop remains fenced and retry actually calls stop again', async () => {
  const h = harness(), req = request(); await h.client.prepare(req); h.failStop = true;
  const release = tracked(h.client.release(req)); await flush(); assert.equal(release.status, 'rejected'); assert.ok(!h.current.dead);
  const blocked = tracked(h.client.prepare(request('two'))); await flush(); assert.equal(blocked.status, 'rejected');
  h.failStop = false; await retire(h, req); assert.equal(h.stops, 2); await h.client.prepare(request('two')); await retire(h, request('two'));
});
test('an unsettled stop cannot affect a new process after a successful retry', async () => {
  const h = harness(), req = request(); await h.client.prepare(req); const gate = h.stopGate = deferred();
  const old = tracked(h.client.release(req)); await h.advance(10000); assert.equal(old.status, 'rejected');
  h.stopGate = undefined; const retry = tracked(h.client.release(req)); await flush(); assert.ok(h.stops >= 2); assert.equal(retry.status, 'pending');
  gate.resolve(); await h.advance(500); assert.equal(retry.status, 'resolved', retry.error); await h.client.prepare(request('two')); assert.ok(!h.current.dead); await retire(h, request('two'));
});
test('late hello cannot overwrite the next process identity', async () => {
  const h = harness(), req = request(); await h.client.prepare(req); const remote = h.current; remote.helloGate = deferred();
  const create = tracked(h.client.create(req)); await flush(); await retire(h, req);
  await h.client.prepare(request('two')); const identity = h.client.processIdentity; remote.helloGate.resolve(); await flush();
  assert.equal(create.status, 'rejected'); assert.equal(h.client.processIdentity, identity); await retire(h, request('two'));
});
test('each fd has a fresh process and stale release/destroy cannot retire it', async () => {
  const h = harness(), req = request(); await h.client.prepare(req); const firstFd = await h.client.create(req); const first = h.client.processIdentity;
  const next = request('one', 'tun-two'); const second = tracked(h.client.create(next)); await h.advance(500); assert.equal(second.status, 'resolved', second.error); assert.notEqual(h.client.processIdentity, first);
  assert.notEqual(firstFd, second.value); const identity = h.client.processIdentity;
  await h.client.destroy(req); await h.client.release(request('old')); assert.equal(h.client.processIdentity, identity); await retire(h, next);
});
test('death-watch registration errors fail binding and still retire the started process', async () => {
  const h = harness(), req = request(); h.failWatch = true;
  const prepare = tracked(h.client.prepare(req)); await flush(); assert.equal(prepare.status, 'rejected'); assert.match(prepare.error, /DEATH_WATCH_FAILED/);
  await retire(h, req); assert.ok(h.current.dead); h.failWatch = false;
  await h.client.prepare(request('two')); await retire(h, request('two'));
});
test('cleanup with no started resources does not stop an unrelated process', async () => {
  const h = harness(); await h.client.release(request()); assert.equal(h.stops, 0);
});
(async () => { for (const {name,run} of tests) { let timer; try { await Promise.race([run(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('TEST_STALLED: ' + name)), 5000); })]); } finally { clearTimeout(timer); } console.log('PASS', name); } console.log(`Tun proxy regressions passed: ${tests.length}`); })().catch(error => { console.error(error); process.exitCode = 1; });
