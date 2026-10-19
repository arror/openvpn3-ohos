// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

namespace ovpn_runtime {
using Clock = std::chrono::steady_clock;
struct Request {
    std::string requestId, profileId, revision, profile;
    std::string username, password, privateKeyPassword, response, cookie;
    bool ipv6 = false, legacy = false, responseProvided = false;
    std::string challengeKind;
};
struct Outcome { std::string commandId, sessionId, status; uint64_t acceptedSeq = 0; };
struct Connection {
    bool defined = false;
    std::string user, serverHost, serverPort, serverProto, serverIp, vpnIp4, vpnIp6, vpnMtu, gw4, gw6, clientIp, tunName;
};
struct Snapshot {
    Connection connectionInfo;
    std::string engine, phase = "initializing", session, profileId, revision, target;
    std::string attempt, error, challengeId, prompt, challengeKind;
    uint64_t challengeDeadlineMs = 0;
    bool baselineKnown = false;
    bool echo = false, resourcesReleased = false, workerExited = true, acceptingCommands = true;
    bool tunReleased = false, bindingReleased = false, pendingSettled = true;
    uint64_t version = 0, appliedCommandSeq = 0, connectionEpoch = 0;
};
struct Work {
    const std::string session, attempt;
    Request request;
    std::atomic<bool> cancelled{false}, terminal{false};
    std::mutex stopMutex;
    std::function<void()> stop;
    explicit Work(std::string s, std::string a, Request r)
        : session(std::move(s)), attempt(std::move(a)), request(std::move(r)) {}
    void cancel() {
        cancelled.store(true);
        std::function<void()> fn;
        { std::lock_guard<std::mutex> lock(stopMutex); fn = stop; }
        if (fn) fn();
    }
    void installStop(std::function<void()> fn) {
        { std::lock_guard<std::mutex> lock(stopMutex); stop = std::move(fn); }
        if (cancelled.load()) cancel();
    }
};
// Single writer: only the driver mutates Snapshot. Core and platform callbacks enqueue facts.
class Runtime {
public:
    struct Hooks {
        std::function<std::string(std::shared_ptr<Work>)> run;
        std::function<void(std::shared_ptr<Work>, std::function<void(bool)>)> release;
        std::function<void(const Snapshot &)> changed;
        std::function<std::string(const Request &, const std::string &)> digest;
        bool strictIds = false;
    };
    explicit Runtime(Hooks h, std::chrono::milliseconds deadline = std::chrono::seconds(15),
                     std::chrono::milliseconds credentialsDeadline = std::chrono::minutes(2))
        : hooks(std::move(h)), cleanupDeadline(deadline), credentialsTimeout(credentialsDeadline) {
        callbackGate->owner = this;
        state.engine = std::to_string(Clock::now().time_since_epoch().count());
        driver = std::thread([this] { loop(); });
    }
    ~Runtime() { shutdown(); }
    Snapshot snapshot() const { std::lock_guard<std::mutex> lock(mutex); return state; }
    void ready(bool requireReconciliation = false) { post([this, requireReconciliation] {
        if (providerReady) return;
        providerReady = true;
        state.baselineKnown = !requireReconciliation;
        state.resourcesReleased = state.tunReleased = state.bindingReleased = !requireReconciliation;
        setPhase(requireReconciliation ? "initializing" : "idle");
    }); }
    Outcome connect(Request request) {
        if (request.requestId.empty() || request.profile.empty() || request.profile.size() > 1024 * 1024)
            throw std::runtime_error("INVALID_REQUEST");
        std::lock_guard<std::mutex> lock(mutex);
        const auto hash = fingerprint(request, "connect");
        auto known = commands.find(request.requestId);
        if (known != commands.end()) {
            if (fingerprints.at(request.requestId) != hash) throw std::runtime_error("REQUEST_ID_CONFLICT");
            return known->second;
        }
        if (closing || !state.acceptingCommands || state.phase == "faulted") throw std::runtime_error("RUNTIME_UNAVAILABLE");
        admit(request.requestId);
        const std::string session = state.engine + ":" + std::to_string(++serial);
        Outcome receipt{request.requestId, session, "accepted", serial};
        remember(receipt, hash);
        // The admission fence prevents a queued CONNECTED from reviving the previous target.
        desired = session;
        if (work) work->cancelled.store(true);
        queue.push_back([this, r = std::move(request), receipt]() mutable {
            if (desired != receipt.sessionId) { finish(receipt.commandId, "superseded"); return; }
            pending = std::make_shared<Work>(receipt.sessionId, "", std::move(r));
            state.target = receipt.sessionId;
            state.appliedCommandSeq = receipt.acceptedSeq;
            finish(receipt.commandId, "applied");
            if (work) stopCurrent(); else startPending();
        });
        cv.notify_one();
        return receipt;
    }
    Outcome disconnect(const std::string &id, const std::string &session = "", bool drain = false) {
        std::lock_guard<std::mutex> lock(mutex);
        Request signature; signature.profile = session;
        const auto hash = fingerprint(signature, drain ? "shutdown" : "disconnect");
        auto known = commands.find(id);
        if (known != commands.end()) {
            if (fingerprints.at(id) != hash) throw std::runtime_error("REQUEST_ID_CONFLICT");
            return known->second;
        }
        if (closing) throw std::runtime_error("RUNTIME_UNAVAILABLE");
        admit(id, true);
        if (drain) { state.acceptingCommands = false; publish(); }
        Outcome receipt{id, session, "accepted", ++serial}; remember(receipt, hash);
        if (!session.empty() && desired != session) { finish(id, "noop"); return receipt; }
        desired.clear();
        if (work) work->cancelled.store(true);
        queue.push_back([this, id, receipt] {
            pending.reset(); challengeWork.reset(); resumeResponse.clear(); resumeRequested = false;
            state.target.clear(); state.challengeId.clear(); state.prompt.clear();
            if (work) stopCurrent(); else { state.error.clear(); setPhase(state.baselineKnown ? "idle" : "initializing"); }
            state.appliedCommandSeq = receipt.acceptedSeq;
            finish(id, "applied");
        });
        cv.notify_one(); return receipt;
    }
    void retryCleanup() { post([this] {
        if (state.phase == "faulted" && work && workerDone) { releasing = false; stopDeadline = Clock::time_point::max(); beginRelease(); }
    }); }
    Outcome outcome(const std::string &id) const {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = commands.find(id);
        return it == commands.end() ? Outcome{id, "", "expired"} : it->second;
    }
    void fact(const std::shared_ptr<Work> &w, const std::string &name,
              std::string prompt = "", bool echo = false, Connection connection = {}) {
        if (name == "CHALLENGE") w->terminal.store(true);
        post([this, w, name, prompt = std::move(prompt), echo, connection = std::move(connection)] {
            if (work != w || w->cancelled || desired != w->session || (w->terminal && name != "CHALLENGE")) return;
            if (name == "PLATFORM_READY") { state.baselineKnown = true; publish(); }
            else if (name == "CONNECTED") { ++state.connectionEpoch; state.connectionInfo = connection; state.error.clear(); setPhase("connected"); }
            else if (name == "RECONNECTING" || name == "DISCONNECTED") setPhase("reconnecting");
            else if (name == "CONNECTING") setPhase("connecting");
            else if (name == "CHALLENGE") {
                challengeWork = w;
                state.challengeId = w->attempt + ":challenge"; state.prompt = prompt; state.echo = echo;
                state.challengeKind = w->request.challengeKind.empty() ? "dynamic" : w->request.challengeKind;
                state.challengeDeadlineMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() + credentialsTimeout.count();
                state.phase = "awaitingCredentials"; challengeDeadline = Clock::now() + credentialsTimeout; publish();
            }
        });
    }
    void failed(const std::shared_ptr<Work> &w, const std::string &code) {
        w->terminal.store(true);
        post([this, w, code] {
            if (work != w || w->cancelled || desired != w->session) return;
            state.error = code; desired.clear(); pending.reset(); stopCurrent();
        });
    }
    void lost(const std::string &session) { post([this, session] {
        if (work && work->session == session) { state.error = "TUN_LOST"; desired.clear(); pending.reset(); stopCurrent(); }
    }); }
    bool credentials(const std::string &session, const std::string &challenge, const std::string &response) {
        std::lock_guard<std::mutex> lock(mutex);
        if (state.phase != "awaitingCredentials" || state.session != session ||
            state.challengeId != challenge || submittedChallenge == challenge || desired != session || response.size() > 4096) return false;
        submittedChallenge = challenge;
        queue.push_back([this, session, challenge, response] {
            if (state.challengeId != challenge || desired != session) return;
            resumeResponse = response; resumeRequested = true; state.challengeId.clear(); state.prompt.clear();
            if (workerDone && !work) resumeChallenge();
            else if (work) {
                std::function<void()> stop;
                { std::lock_guard<std::mutex> lock(work->stopMutex); stop = work->stop; }
                if (stop) outbound.push_back(std::move(stop));
            }
        });
        cv.notify_one(); return true;
    }
    void shutdown() {
        { std::lock_guard<std::mutex> lock(mutex);
          if (closing) return;
          closing = true; desired.clear(); if (work) work->cancelled.store(true);
          queue.push_back([this] {
              pending.reset(); challengeWork.reset();
              if (work) { auto w = work; outbound.push_back([w] { w->cancel(); }); }
              if (workerDone) { work.reset(); releasing = false; }
          }); }
        cv.notify_one();
        if (driver.joinable()) driver.join();
        std::lock_guard<std::mutex> gateLock(callbackGate->mutex); callbackGate->owner = nullptr;
    }
private:
    struct CallbackGate { std::mutex mutex; Runtime *owner = nullptr; };
    std::shared_ptr<CallbackGate> callbackGate = std::make_shared<CallbackGate>();
    std::deque<std::function<void()>> outbound;
    Hooks hooks;
    std::chrono::milliseconds cleanupDeadline, credentialsTimeout;
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::function<void()>> queue;
    std::unordered_map<std::string, Outcome> commands;
    std::unordered_map<std::string, std::string> fingerprints;
    uint64_t highWater = 0;
    std::deque<std::string> order;
    Snapshot state;
    std::string desired, resumeResponse, submittedChallenge;
    bool resumeRequested = false;
    std::shared_ptr<Work> work, pending, challengeWork;
    std::thread driver, worker;
    bool providerReady = false;
    bool closing = false, workerDone = false, releasing = false;
    uint64_t serial = 0, attempts = 0, releaseGeneration = 0;
    Clock::time_point stopDeadline = Clock::time_point::max(), challengeDeadline = Clock::time_point::max();
    std::string fingerprint(const Request &r, const std::string &kind) const {
        if (hooks.digest) return hooks.digest(r, kind);
        // Host-test fallback only; Native supplies a per-engine HMAC key.
        std::string encoded;
        for (const auto &field : {kind, r.profileId, r.revision, r.profile, r.username, r.password,
             r.privateKeyPassword, r.response, r.cookie}) encoded += std::to_string(field.size()) + ":" + field;
        encoded += r.ipv6 ? "1" : "0"; encoded += r.legacy ? "1" : "0";
        return std::to_string(std::hash<std::string>{}(encoded));
    }
    void admit(const std::string &id, bool control = false) {
        if (queue.size() >= (control ? 512 : 256)) throw std::runtime_error("COMMAND_QUEUE_FULL");
        if (!hooks.strictIds) { if (id.empty()) throw std::runtime_error("INVALID_REQUEST_ID"); return; }
        const auto prefix = state.engine + ":";
        if (id.compare(0, prefix.size(), prefix) != 0 || id.size() == prefix.size()) throw std::runtime_error("STALE_CLIENT_EPOCH");
        uint64_t seq = 0;
        for (size_t i = prefix.size(); i < id.size(); ++i) {
            auto c = id[i];
            if (c < '0' || c > '9' || seq > (std::numeric_limits<uint64_t>::max() - (c - '0')) / 10)
                throw std::runtime_error("INVALID_REQUEST_ID");
            seq = seq * 10 + (c - '0');
        }
        if (seq <= highWater) throw std::runtime_error("REQUEST_EXPIRED");
        highWater = seq;
    }
    void prune() {
        for (auto it = order.begin(); commands.size() > 256 && it != order.end();) {
            const auto &o = commands.at(*it);
            if (o.status == "accepted" || (!o.sessionId.empty() && o.sessionId == desired)) { ++it; continue; }
            fingerprints.erase(*it); commands.erase(*it); it = order.erase(it);
        }
    }
    void remember(const Outcome &o, const std::string &hash) {
        commands[o.commandId] = o; fingerprints[o.commandId] = hash; order.push_back(o.commandId); prune();
    }
    void finish(const std::string &id, const std::string &status) { commands.at(id).status = status; prune(); }
    void post(std::function<void()> fn) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push_back(std::move(fn)); cv.notify_one();
    }
    void publish() { ++state.version; }
    void setPhase(const std::string &s) {
        state.phase = s;
        if (s != "connected") state.connectionInfo = {};
        if (s == "idle" || s == "initializing") {
            state.session.clear(); state.attempt.clear(); state.target.clear();
            state.profileId.clear(); state.revision.clear();
            state.challengeId.clear(); state.prompt.clear(); state.challengeKind.clear();
            state.echo = false; state.challengeDeadlineMs = 0;
            submittedChallenge.clear(); challengeDeadline = Clock::time_point::max();
        }
        publish();
    }
    void startPending() {
        if (!pending || pending->session != desired || closing || state.phase == "faulted") return;
        auto p = pending; pending.reset();
        work = std::make_shared<Work>(p->session, p->session + ":" + std::to_string(++attempts), std::move(p->request));
        workerDone = false; releasing = false;
        state.session = work->session; state.attempt = work->attempt;
        state.profileId = work->request.profileId; state.revision = work->request.revision;
        state.target.clear(); state.error.clear(); state.challengeId.clear(); state.prompt.clear();
        state.resourcesReleased = state.workerExited = state.tunReleased = state.bindingReleased = state.pendingSettled = false;
        setPhase("preparing");
        auto w = work;
        worker = std::thread([this, w] {
            std::string error;
            try { error = hooks.run(w); } catch (...) { error = "CORE_FAILED"; }
            w->installStop({});
            post([this, w, error] {
                if (work != w) return;
                workerDone = true; state.workerExited = true;
                if (!error.empty() && !w->cancelled && challengeWork != w) state.error = error;
                beginRelease();
            });
        });
    }
    void stopCurrent() {
        if (!work) return;
        { auto w = work; w->cancelled.store(true); outbound.push_back([w] { w->cancel(); }); }
        state.challengeId.clear(); state.prompt.clear(); challengeWork.reset(); resumeResponse.clear(); resumeRequested = false;
        setPhase("stopping");
        if (stopDeadline == Clock::time_point::max()) stopDeadline = Clock::now() + cleanupDeadline;
        if (workerDone && !releasing) beginRelease();
    }
    void beginRelease() {
        if (releasing || !work) return;
        if (worker.joinable()) worker.join(); // completion was posted after run + client destruction
        if (challengeWork != work) work->request = Request{};
        if (closing) { work.reset(); return; }
        releasing = true;
        if (state.challengeId.empty()) setPhase("stopping");
        if (stopDeadline == Clock::time_point::max()) stopDeadline = Clock::now() + cleanupDeadline;
        auto w = work;
        const auto generation = ++releaseGeneration;
        auto gate = callbackGate;
        auto once = std::make_shared<std::atomic<bool>>(false);
        outbound.push_back([this, w, gate, once, generation] {
            auto complete = [gate, w, once, generation](bool ok) {
                if (once->exchange(true)) return;
                std::lock_guard<std::mutex> lock(gate->mutex);
                auto owner = gate->owner;
                if (owner) owner->post([owner, w, ok, generation] { owner->released(w, generation, ok); });
            };
            try { hooks.release(w, complete); } catch (...) { complete(false); }
        });
    }
    void released(const std::shared_ptr<Work> &w, uint64_t generation, bool ok) {
        if (work != w || generation != releaseGeneration) return;
        releasing = false; stopDeadline = Clock::time_point::max();
        if (!ok && !closing) { state.error = "CLEANUP_FAILED"; setPhase("faulted"); return; }
        state.resourcesReleased = state.tunReleased = state.bindingReleased = state.baselineKnown;
        state.pendingSettled = true;
        if (desired != w->session || w->cancelled) challengeWork.reset();
        work.reset();
        if (challengeWork && desired == challengeWork->session) {
            setPhase("awaitingCredentials"); if (resumeRequested) resumeChallenge();
        } else { state.session.clear(); state.attempt.clear(); setPhase(state.baselineKnown ? "idle" : "initializing"); startPending(); }
    }
    void resumeChallenge() {
        if (!challengeWork || !resumeRequested) return;
        auto w = challengeWork; challengeWork.reset();
        if (w->request.challengeKind == "privateKey") w->request.privateKeyPassword = std::move(resumeResponse);
        else { w->request.response = std::move(resumeResponse); w->request.responseProvided = true; }
        resumeResponse.clear(); resumeRequested = false;
        pending = std::move(w); state.challengeId.clear(); startPending();
    }
    void loop() {
        std::unique_lock<std::mutex> lock(mutex);
        uint64_t notified = 0;
        for (;;) {
            cv.wait_for(lock, std::chrono::milliseconds(25), [this] { return !queue.empty(); });
            while (!queue.empty()) { auto fn = std::move(queue.front()); queue.pop_front(); fn(); }
            if (work && Clock::now() > stopDeadline && state.phase != "faulted") {
                state.error = "CLEANUP_TIMEOUT"; pending.reset(); desired.clear(); setPhase("faulted");
            }
            if (!state.challengeId.empty() && Clock::now() > challengeDeadline) {
                state.challengeId.clear(); state.prompt.clear(); state.error = "CHALLENGE_EXPIRED";
                desired.clear(); challengeWork.reset(); if (work) stopCurrent(); else setPhase("idle");
            }
            // User/Core/platform hooks may complete synchronously or reenter queries.
            // Invoke them outside the state lock; all resulting facts return through post().
            while (!outbound.empty()) {
                auto action = std::move(outbound.front()); outbound.pop_front();
                lock.unlock(); action(); lock.lock();
            }
            if (state.version != notified) {
                auto copy = state; notified = state.version;
                lock.unlock(); if (hooks.changed) hooks.changed(copy); lock.lock();
            }
            if (closing && !work && queue.empty()) break;
        }
    }
};
} // namespace ovpn_runtime
