// SPDX-License-Identifier: MPL-2.0
// Included by the single OpenVPN translation unit. Owns the NAPI environment only.
#include "../runtime/session_runtime.hpp"
#include <unistd.h>
#include <dirent.h>
#include <deque>
#include <map>
#include <utility>
#include <array>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using RuntimeWork = ovpn_runtime::Work;
static std::string RunCoreSession(std::shared_ptr<RuntimeWork> work);
struct NativeBridge;
static NativeBridge *g_bridge = nullptr;

static napi_value JsString(napi_env env, const std::string &s) {
    napi_value v; napi_create_string_utf8(env, s.data(), s.size(), &v); return v;
}
static void SetString(napi_env e, napi_value o, const char *k, const std::string &s) {
    napi_set_named_property(e, o, k, JsString(e, s));
}
static void SetNumber(napi_env e, napi_value o, const char *k, double n) {
    napi_value v; napi_create_double(e, n, &v); napi_set_named_property(e, o, k, v);
}
static void SetBool(napi_env e, napi_value o, const char *k, bool b) {
    napi_value v; napi_get_boolean(e, b, &v); napi_set_named_property(e, o, k, v);
}
static napi_value Object(napi_env env) { napi_value o; napi_create_object(env, &o); return o; }
static napi_value Null(napi_env env) { napi_value o; napi_get_null(env, &o); return o; }
static std::string Field(napi_env env, napi_value obj, const char *key) {
    napi_value v; napi_valuetype t;
    if (obj && napi_get_named_property(env, obj, key, &v) == napi_ok &&
        napi_typeof(env, v, &t) == napi_ok && t == napi_string) return NapiGetString(env, v);
    return "";
}
static bool BoolField(napi_env env, napi_value obj, const char *key) {
    napi_value v; bool b = false;
    if (obj && napi_get_named_property(env, obj, key, &v) == napi_ok) napi_get_value_bool(env, v, &b);
    return b;
}
static void ClearException(napi_env env) {
    bool pending = false; napi_is_exception_pending(env, &pending);
    if (pending) { napi_value e; napi_get_and_clear_last_exception(env, &e); }
}

struct TunOperation {
    std::shared_ptr<RuntimeWork> work;
    std::string kind, tunId;
    uint64_t sequence = 0;
    VpnConfig config;
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false, ok = false, abandoned = false;
    int fd = -1;
    std::function<void(bool)> completion;
};

static napi_value ConnectionObject(napi_env env, const OvpnConnectionInfo &i) {
    auto o = Object(env); SetBool(env, o, "defined", i.defined);
    SetString(env, o, "user", i.user); SetString(env, o, "serverHost", i.serverHost);
    SetString(env, o, "serverPort", i.serverPort); SetString(env, o, "serverProto", i.serverProto);
    SetString(env, o, "serverIp", i.serverIp); SetString(env, o, "vpnIp4", i.vpnIp4);
    SetString(env, o, "vpnIp6", i.vpnIp6); SetString(env, o, "vpnMtu", i.vpnMtu);
    SetString(env, o, "gw4", i.gw4); SetString(env, o, "gw6", i.gw6);
    SetString(env, o, "clientIp", i.clientIp); SetString(env, o, "tunName", i.tunName);
    return o;
}

struct NativeBridge {
    napi_env env;
    napi_threadsafe_function wake = nullptr;
    napi_ref observer = nullptr, provider = nullptr, shutdownPromise = nullptr;
    napi_deferred shutdownDeferred = nullptr;
    uint64_t shutdownSeq = 0;
    std::atomic<bool> closing{false};
    std::unique_ptr<ovpn_runtime::Runtime> runtime;
    std::mutex mutex;
    std::deque<std::shared_ptr<TunOperation>> tasks;
    std::vector<std::shared_ptr<TunOperation>> operations;
    std::map<std::string, std::string> tunIds;
    StatsData stats;
    std::string statsSession, statsAttempt;
    bool statsDirty = false;
    uint64_t statsEpoch = 0;
    uint64_t statsSeq = 0, tunSerial = 0, operationSerial = 0, notifiedVersion = 0;
    std::array<unsigned char, 32> commandKey{};
    explicit NativeBridge(napi_env e) : env(e) {
        if (RAND_bytes(commandKey.data(), commandKey.size()) != 1) throw std::runtime_error("ENGINE_RANDOM_FAILED");
    }
    std::string digest(const ovpn_runtime::Request &r, const std::string &kind) {
        auto ctx = HMAC_CTX_new();
        if (!ctx) throw std::runtime_error("ENGINE_HMAC_FAILED");
        HMAC_Init_ex(ctx, commandKey.data(), commandKey.size(), EVP_sha256(), nullptr);
        for (const auto &field : {kind, r.profileId, r.revision, r.profile, r.username, r.password,
             r.privateKeyPassword, r.response, r.cookie}) {
            uint64_t length = field.size(); HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(&length), sizeof(length));
            HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(field.data()), field.size());
        }
        unsigned char flags[] = {static_cast<unsigned char>(r.ipv6), static_cast<unsigned char>(r.legacy)};
        HMAC_Update(ctx, flags, sizeof(flags));
        unsigned char output[EVP_MAX_MD_SIZE]; unsigned int length = 0;
        HMAC_Final(ctx, output, &length); HMAC_CTX_free(ctx);
        return std::string(reinterpret_cast<char *>(output), length);
    }
    void notify() {
        if (!closing && wake) napi_call_threadsafe_function(wake, nullptr, napi_tsfn_nonblocking);
    }
    void start() {
        runtime.reset(new ovpn_runtime::Runtime({RunCoreSession,
            [this](std::shared_ptr<RuntimeWork> w, std::function<void(bool)> done) {
                auto op = std::make_shared<TunOperation>(); op->work = w; op->kind = "release";
                op->completion = std::move(done); enqueue(op);
            }, [this](const ovpn_runtime::Snapshot &s) {
                OH_LOG_Print(LOG_APP, LOG_INFO, 0x0750, "OVPN_TRACE",
                    "state version=%{public}llu phase=%{public}s session=%{public}s attempt=%{public}s error=%{public}s released=%{public}d",
                    static_cast<unsigned long long>(s.version), s.phase.c_str(), s.session.c_str(),
                    s.attempt.c_str(), s.error.c_str(), static_cast<int>(s.resourcesReleased));
                notify();
            },
            [this](const ovpn_runtime::Request &r, const std::string &kind) { return digest(r, kind); }, true}));
    }
    void enqueue(const std::shared_ptr<TunOperation> &op) {
        { std::lock_guard<std::mutex> lock(mutex); op->sequence = ++operationSerial; tasks.push_back(op); operations.push_back(op); }
        notify();
    }
    std::string newTunId(const std::shared_ptr<RuntimeWork> &w) {
        std::lock_guard<std::mutex> lock(mutex);
        auto id = w->attempt + ":tun:" + std::to_string(++tunSerial); tunIds[w->attempt] = id; return id;
    }
    std::string currentTunId(const std::shared_ptr<RuntimeWork> &w) {
        std::lock_guard<std::mutex> lock(mutex); return tunIds[w->attempt];
    }
    int wait(const std::shared_ptr<TunOperation> &op, bool cancellable) {
        if (closing) return -1;
        enqueue(op);
        std::unique_lock<std::mutex> lock(op->mutex);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (!op->done && !closing && !(cancellable && op->work->cancelled)) {
            if (op->cv.wait_until(lock, std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(25))) == std::cv_status::timeout &&
                std::chrono::steady_clock::now() >= deadline) break;
        }
        if (!op->done || !op->ok || closing || (cancellable && op->work->cancelled)) {
            op->abandoned = true;
            if (op->fd >= 0) { ::close(op->fd); op->fd = -1; }
            return -1;
        }
        int fd = op->fd; op->fd = -1; return fd;
    }
    void received(const std::shared_ptr<TunOperation> &op, bool ok, int fd) {
        { std::lock_guard<std::mutex> lock(op->mutex);
          if (op->done || op->abandoned || closing) { if (fd >= 0) ::close(fd); }
          else { op->fd = fd; op->ok = ok; }
          op->done = true; op->cv.notify_all(); }
        if (op->kind == "release" && ok && !op->abandoned && !closing) {
            std::lock_guard<std::mutex> lock(mutex);
            for (auto &other : operations) {
                if (other->work != op->work || other->sequence >= op->sequence) continue;
                std::lock_guard<std::mutex> operationLock(other->mutex);
                if (other->done) continue;
                other->abandoned = true; other->done = true; other->ok = false;
                if (other->fd >= 0) { ::close(other->fd); other->fd = -1; }
                other->cv.notify_all();
            }
        }
        completeReleases();
    }
    void completeReleases() {
        std::vector<std::pair<std::function<void(bool)>, bool>> callbacks;
        { std::lock_guard<std::mutex> lock(mutex);
          for (auto &op : operations) {
              if (op->kind != "release" || !op->completion || !op->done) continue;
              bool settled = true;
              for (auto &other : operations)
                  if (op->ok && other->work == op->work && other->sequence < op->sequence && !other->done) settled = false;
              if (settled) {
                  tunIds.erase(op->work->attempt);
                  callbacks.push_back({std::move(op->completion), op->ok});
              }
          }
          operations.erase(std::remove_if(operations.begin(), operations.end(), [](const auto &op) {
              return op->done && !op->completion;
          }), operations.end()); }
        for (auto &entry : callbacks) if (!closing) entry.first(entry.second);
    }
    void updateStats(const std::shared_ptr<RuntimeWork> &w, const StatsData &s) {
        if (w->cancelled || closing) return;
        const auto snapshot = runtime->snapshot();
        if (snapshot.session != w->session || snapshot.attempt != w->attempt) return;
        { std::lock_guard<std::mutex> lock(mutex);
          statsEpoch = snapshot.connectionEpoch;
          stats = s; statsSession = w->session; statsAttempt = w->attempt; ++statsSeq; statsDirty = true; }
        notify();
    }
    void call(napi_ref ref, const char *name, napi_value arg) {
        if (!ref || closing) return;
        napi_value obj, fn; napi_valuetype type;
        if (napi_get_reference_value(env, ref, &obj) != napi_ok ||
            napi_get_named_property(env, obj, name, &fn) != napi_ok ||
            napi_typeof(env, fn, &type) != napi_ok || type != napi_function) return;
        napi_value ignored; napi_call_function(env, obj, fn, 1, &arg, &ignored); ClearException(env);
    }
};

static napi_value SnapshotObject(napi_env env, const ovpn_runtime::Snapshot &s) {
    auto o = Object(env);
    SetString(env, o, "engineInstanceId", s.engine); SetString(env, o, "phase", s.phase);
    SetBool(env, o, "acceptingCommands", s.acceptingCommands);
    SetBool(env, o, "baselineKnown", s.baselineKnown);
    SetString(env, o, "sessionId", s.session); SetString(env, o, "attemptId", s.attempt);
    SetString(env, o, "profileId", s.profileId); SetString(env, o, "profileRevision", s.revision);
    SetString(env, o, "targetSessionId", s.target); SetString(env, o, "lastError", s.error);
    SetNumber(env, o, "version", s.version); SetNumber(env, o, "appliedCommandSeq", s.appliedCommandSeq);
    SetNumber(env, o, "connectionEpoch", s.connectionEpoch); SetBool(env, o, "resourcesReleased", s.resourcesReleased);
    auto clean = Object(env); SetBool(env, clean, "workerExited", s.workerExited);
    SetBool(env, clean, "tunReleased", s.tunReleased); SetBool(env, clean, "bindingReleased", s.bindingReleased);
    SetBool(env, clean, "pendingSettled", s.pendingSettled); napi_set_named_property(env, o, "cleanup", clean);
    auto challenge = Null(env);
    if (!s.challengeId.empty()) { challenge = Object(env); SetString(env, challenge, "challengeId", s.challengeId);
        SetString(env, challenge, "prompt", s.prompt); SetBool(env, challenge, "echo", s.echo);
        SetString(env, challenge, "kind", s.challengeKind); SetString(env, challenge, "originAttemptId", s.attempt);
        SetNumber(env, challenge, "connectionEpoch", s.connectionEpoch); SetNumber(env, challenge, "deadline", s.challengeDeadlineMs); }
    napi_set_named_property(env, o, "connectionInfo", ConnectionObject(env, s.connectionInfo));
    napi_set_named_property(env, o, "challenge", challenge);
    return o;
}
static napi_value StatsObject(napi_env env) {
    auto b = g_bridge; auto o = Object(env);
    const auto snapshot = b->runtime->snapshot();
    std::lock_guard<std::mutex> lock(b->mutex);
    const bool valid = snapshot.phase == "connected" && snapshot.session == b->statsSession &&
        snapshot.attempt == b->statsAttempt && snapshot.connectionEpoch == b->statsEpoch;
    const auto sample = valid ? b->stats : StatsData{};
    SetBool(env, o, "valid", valid); SetString(env, o, "engineInstanceId", snapshot.engine);
    SetNumber(env, o, "connectionEpoch", b->statsEpoch);
    SetString(env, o, "sessionId", b->statsSession); SetString(env, o, "attemptId", b->statsAttempt);
    SetNumber(env, o, "sequence", b->statsSeq);
    SetNumber(env, o, "tunBytesIn", sample.tunBytesIn); SetNumber(env, o, "tunBytesOut", sample.tunBytesOut);
    SetNumber(env, o, "tunPacketsIn", sample.tunPacketsIn); SetNumber(env, o, "tunPacketsOut", sample.tunPacketsOut);
    SetNumber(env, o, "bytesIn", sample.bytesIn); SetNumber(env, o, "bytesOut", sample.bytesOut);
    SetNumber(env, o, "packetsIn", sample.packetsIn); SetNumber(env, o, "packetsOut", sample.packetsOut);
    SetNumber(env, o, "rateIn", sample.rateIn); SetNumber(env, o, "rateOut", sample.rateOut);
    SetNumber(env, o, "connectedDuration", sample.connectedDuration);
    napi_set_named_property(env, o, "connectionInfo", ConnectionObject(env, sample.connInfo)); return o;
}
struct PromiseContext { std::shared_ptr<TunOperation> operation; bool success; std::string engine; };
static napi_value TunResolved(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value arg; void *data;
    napi_get_cb_info(env, info, &argc, &arg, nullptr, &data);
    auto context = static_cast<PromiseContext *>(data);
    int fd = -1;
    bool ok = context->success;
    if (ok && context->operation->kind == "create") ok = argc && napi_get_value_int32(env, arg, &fd) == napi_ok && fd >= 0;
    if (g_bridge && g_bridge->env == env && !g_bridge->closing &&
        g_bridge->runtime->snapshot().engine == context->engine) g_bridge->received(context->operation, ok, fd);
    else if (fd >= 0) ::close(fd);
    return nullptr;
}
static void FinalizePromise(napi_env, void *data, void *) { delete static_cast<PromiseContext *>(data); }
static void InvokeTun(napi_env env, const std::shared_ptr<TunOperation> &op) {
    auto b = g_bridge;
    if (!b || b->closing || !b->provider) { if (b) b->received(op, false, -1); return; }
    const char *method = op->kind == "prepare" ? "prepare" : op->kind == "create" ? "create" : op->kind == "destroy" ? "destroy" : "release";
    napi_value provider, fn, promise;
    auto arg = Object(env);
    SetString(env, arg, "engineInstanceId", b->runtime->snapshot().engine);
    SetString(env, arg, "sessionId", op->work->session); SetString(env, arg, "attemptId", op->work->attempt);
    SetString(env, arg, "tunId", op->tunId);
    if (op->kind == "create") napi_set_named_property(env, arg, "config", CreateTunConfigObject(env, op->config));
    napi_get_reference_value(env, b->provider, &provider); napi_get_named_property(env, provider, method, &fn);
    if (napi_call_function(env, provider, fn, 1, &arg, &promise) != napi_ok) {
        ClearException(env); b->received(op, false, -1); return;
    }
    napi_value then; napi_valuetype type;
    if (napi_get_named_property(env, promise, "then", &then) != napi_ok || napi_typeof(env, then, &type) != napi_ok || type != napi_function) {
        ClearException(env); b->received(op, false, -1); return;
    }
    napi_value callbacks[2];
    for (int i = 0; i < 2; ++i) {
        auto ctx = new PromiseContext{op, i == 0, b->runtime->snapshot().engine};
        napi_create_function(env, "tunResult", NAPI_AUTO_LENGTH, TunResolved, ctx, &callbacks[i]);
        napi_add_finalizer(env, callbacks[i], ctx, FinalizePromise, nullptr, nullptr);
    }
    napi_value ignored;
    if (napi_call_function(env, promise, then, 2, callbacks, &ignored) != napi_ok) { ClearException(env); b->received(op, false, -1); }
}
static void Dispatch(napi_env env, napi_value, void *, void *) {
    auto b = g_bridge;
    if (!env || !b || b->closing) return;
    std::deque<std::shared_ptr<TunOperation>> tasks;
    bool statsDirty;
    { std::lock_guard<std::mutex> lock(b->mutex); tasks.swap(b->tasks); statsDirty = b->statsDirty; b->statsDirty = false; }
    for (auto &op : tasks) InvokeTun(env, op);
    auto s = b->runtime->snapshot();
    if (b->observer && s.version != b->notifiedVersion) { b->notifiedVersion = s.version; b->call(b->observer, "onStateChange", SnapshotObject(env, s)); }
    if (statsDirty && b->observer) b->call(b->observer, "onStats", StatsObject(env));
    if (b->shutdownDeferred && s.appliedCommandSeq >= b->shutdownSeq && (s.phase == "faulted" || (s.phase == "idle" && s.resourcesReleased))) {
        if (s.phase == "faulted") {
            napi_value error; napi_create_error(env, JsString(env, "SHUTDOWN_INCOMPLETE"), JsString(env, s.error), &error);
            napi_reject_deferred(env, b->shutdownDeferred, error);
        } else {
            if (b->observer) napi_delete_reference(env, b->observer);
            if (b->provider) napi_delete_reference(env, b->provider);
            b->observer = b->provider = nullptr;
            napi_value value; napi_get_undefined(env, &value);
            napi_resolve_deferred(env, b->shutdownDeferred, value);
        }
        b->shutdownDeferred = nullptr;
        napi_delete_reference(env, b->shutdownPromise); b->shutdownPromise = nullptr;
    }
}
static napi_value Receipt(napi_env env, const ovpn_runtime::Outcome &r) {
    auto o = Object(env); SetString(env, o, "commandId", r.commandId); SetString(env, o, "targetSessionId", r.sessionId);
    SetString(env, o, "status", r.status); SetNumber(env, o, "acceptedSeq", r.acceptedSeq); return o;
}
static napi_value ConnectCommand(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value req; napi_get_cb_info(env, info, &argc, &req, nullptr, nullptr);
    if (!argc || !g_bridge->provider) { napi_throw_error(env, "PROVIDER_MISSING", "TUN provider is required"); return nullptr; }
    ovpn_runtime::Request r;
    r.requestId = Field(env, req, "requestId"); r.profileId = Field(env, req, "profileId");
    r.revision = Field(env, req, "profileRevision"); r.profile = Field(env, req, "profileText");
    r.username = Field(env, req, "username"); r.password = Field(env, req, "password");
    r.privateKeyPassword = Field(env, req, "privateKeyPassword");
    r.ipv6 = BoolField(env, req, "isIPv6Accepted"); r.legacy = BoolField(env, req, "enableNonPreferredDCAlgorithms");
    try { return Receipt(env, g_bridge->runtime->connect(std::move(r))); }
    catch (const std::exception &e) { napi_throw_error(env, "REQUEST_REJECTED", e.what()); return nullptr; }
}
static napi_value DisconnectCommand(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value req; napi_get_cb_info(env, info, &argc, &req, nullptr, nullptr);
    if (!argc) { napi_throw_error(env, "INVALID_REQUEST", "requestId required"); return nullptr; }
    try { return Receipt(env, g_bridge->runtime->disconnect(Field(env, req, "requestId"), Field(env, req, "sessionId"))); }
    catch (const std::exception &e) { napi_throw_error(env, "REQUEST_REJECTED", e.what()); return nullptr; }
}
static napi_value GetState(napi_env env, napi_callback_info) { return SnapshotObject(env, g_bridge->runtime->snapshot()); }
static napi_value GetStats(napi_env env, napi_callback_info) { return StatsObject(env); }
static int ProcEntries(const char *path, bool accountForDirectoryFd) {
    DIR *directory = opendir(path);
    if (!directory) return -1;
    int count = 0;
    while (auto entry = readdir(directory)) if (entry->d_name[0] != '.') ++count;
    closedir(directory);
    return count - (accountForDirectoryFd ? 1 : 0);
}
static napi_value GetDiagnostics(napi_env env, napi_callback_info) {
    auto b = g_bridge; auto o = Object(env);
    const auto state = b->runtime->snapshot();
    SetString(env, o, "engineInstanceId", state.engine);
    SetNumber(env, o, "fdCount", ProcEntries("/proc/self/fd", true));
    SetNumber(env, o, "threadCount", ProcEntries("/proc/self/task", false));
    std::lock_guard<std::mutex> lock(b->mutex);
    SetNumber(env, o, "pendingTunOperations", std::count_if(b->operations.begin(), b->operations.end(), [](const auto &op) { return !op->done; }));
    SetNumber(env, o, "trackedAttempts", b->tunIds.size());
    return o;
}
static napi_value SetObserver(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value obj; napi_get_cb_info(env, info, &argc, &obj, nullptr, nullptr);
    if (g_bridge->observer) napi_delete_reference(env, g_bridge->observer);
    g_bridge->observer = nullptr; napi_valuetype type;
    if (argc && napi_typeof(env, obj, &type) == napi_ok && type == napi_object) napi_create_reference(env, obj, 1, &g_bridge->observer);
    g_bridge->notifiedVersion = UINT64_MAX; g_bridge->notify(); return nullptr;
}
static napi_value SetProvider(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]{}; napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    napi_value obj = args[0];
    napi_valuetype type;
    if (!argc || napi_typeof(env, obj, &type) != napi_ok || type != napi_object) {
        napi_throw_type_error(env, "INVALID_PROVIDER", "TUN provider required"); return nullptr;
    }
    for (const char *method : {"prepare", "create", "destroy", "release"}) {
        napi_value fn;
        if (napi_get_named_property(env, obj, method, &fn) != napi_ok || napi_typeof(env, fn, &type) != napi_ok || type != napi_function) {
            ClearException(env); napi_throw_type_error(env, "INVALID_PROVIDER", "TUN provider methods required"); return nullptr;
        }
    }
    auto s = g_bridge->runtime->snapshot();
    if (!s.acceptingCommands || (s.phase != "idle" && s.phase != "initializing") || (!s.resourcesReleased && s.phase != "initializing")) { napi_throw_error(env, "PROVIDER_BUSY", "Cannot replace active provider"); return nullptr; }
    if (g_bridge->provider) napi_delete_reference(env, g_bridge->provider);
    napi_create_reference(env, obj, 1, &g_bridge->provider);
    // No platform resources have been requested by this Runtime. prepare() reconciles the prior owner before execution.
    g_bridge->runtime->ready(argc > 1 && BoolField(env, args[1], "requireReconciliation")); return nullptr;
}
static napi_value ProvideCredentials(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value req; napi_get_cb_info(env, info, &argc, &req, nullptr, nullptr);
    if (!argc || !g_bridge->runtime->credentials(Field(env, req, "sessionId"), Field(env, req, "challengeId"), Field(env, req, "response"))) {
        napi_throw_error(env, "STALE_CHALLENGE", "Challenge is no longer current"); return nullptr;
    }
    return nullptr;
}
static napi_value ShutdownCommand(napi_env env, napi_callback_info info) {
    auto b = g_bridge;
    if (b->shutdownPromise) { napi_value p; napi_get_reference_value(env, b->shutdownPromise, &p); return p; }
    auto baseline = g_bridge->runtime->snapshot();
    if (!baseline.baselineKnown && baseline.phase == "initializing") {
        napi_throw_error(env, "BASELINE_UNCONFIRMED", "Platform baseline requires user reconciliation"); return nullptr;
    }
    size_t argc = 1; napi_value req; napi_get_cb_info(env, info, &argc, &req, nullptr, nullptr);
    if (!argc) { napi_throw_type_error(env, "INVALID_REQUEST", "requestId required"); return nullptr; }
    try { b->shutdownSeq = b->runtime->disconnect(Field(env, req, "requestId"), "", true).acceptedSeq; }
    catch (const std::exception &e) { napi_throw_error(env, "REQUEST_REJECTED", e.what()); return nullptr; }
    napi_value promise; napi_create_promise(env, &b->shutdownDeferred, &promise);
    napi_create_reference(env, promise, 1, &b->shutdownPromise); b->notify(); return promise;
}
static napi_value RetryCleanup(napi_env, napi_callback_info) { g_bridge->runtime->retryCleanup(); return nullptr; }
static napi_value NotifyTunLost(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value req; napi_get_cb_info(env, info, &argc, &req, nullptr, nullptr);
    if (argc) g_bridge->runtime->lost(Field(env, req, "sessionId")); return nullptr;
}
static napi_value GetOutcome(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value id; napi_get_cb_info(env, info, &argc, &id, nullptr, nullptr);
    return Receipt(env, g_bridge->runtime->outcome(argc ? NapiGetString(env, id) : ""));
}
static napi_value Capabilities(napi_env env, napi_callback_info) {
    auto o = Object(env); SetNumber(env, o, "apiVersion", 2); SetString(env, o, "coreVersion", "3.11.7");
    SetString(env, o, "buildId", "session-runtime-v2");
    SetBool(env, o, "externalPki", false); SetBool(env, o, "dco", false);
    SetBool(env, o, "systemProxy", false); SetBool(env, o, "encryptedDns", false);
    return o;
}
static void CleanupNative(napi_async_cleanup_hook_handle handle, void *data) {
    auto b = static_cast<NativeBridge *>(data); b->closing = true;
    // Do not join on the ArkTS thread: Core teardown and pending Provider promises must be cancellable without JS.
    std::thread([b, handle] {
        b->runtime->shutdown();
        napi_release_threadsafe_function(b->wake, napi_tsfn_abort);
        napi_remove_async_cleanup_hook(handle);
    }).detach(); // only the cleanup hook owns this bounded reaper; it does not detach a Core worker
}
static void FinalizeBridge(napi_env env, void *data, void *) {
    auto b = static_cast<NativeBridge *>(data);
    if (b->observer) napi_delete_reference(env, b->observer);
    if (b->provider) napi_delete_reference(env, b->provider);
    if (b->shutdownPromise) napi_delete_reference(env, b->shutdownPromise);
    if (g_bridge == b) g_bridge = nullptr;
    delete b;
}
static void InstallRuntime(napi_env env) {
    auto b = new NativeBridge(env); g_bridge = b;
    napi_value resource = JsString(env, "OvpnRuntime");
    napi_create_threadsafe_function(env, nullptr, nullptr, resource, 1, 1, b, FinalizeBridge, nullptr, Dispatch, &b->wake);
    napi_unref_threadsafe_function(env, b->wake);
    b->start(); napi_add_async_cleanup_hook(env, CleanupNative, b, nullptr);
}
