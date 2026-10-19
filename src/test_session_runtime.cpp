// SPDX-License-Identifier: MPL-2.0
// Stateful regression tests: actual Runtime scheduling with a controllable Core and TUN provider.
#include "runtime/session_runtime.hpp"
#include <cassert>
#include <iostream>
#include <future>
#include <vector>
using namespace ovpn_runtime;
static void until(const std::function<bool()> &predicate) {
    const auto end = Clock::now() + std::chrono::seconds(3);
    while (!predicate()) { assert(Clock::now() < end); std::this_thread::sleep_for(std::chrono::milliseconds(2)); }
}
static Request request(const std::string &id) { Request r; r.requestId = id; r.profileId = id; r.profile = "client\nremote localhost 1194"; return r; }
int main() {
    Runtime *ptr = nullptr;
    std::mutex mutex;
    std::function<void(bool)> release;
    std::shared_ptr<Work> current;
    int executions = 0;
    Runtime rt({[&](std::shared_ptr<Work> w) {
        { std::lock_guard<std::mutex> lock(mutex); current = w; ++executions; }
        ptr->fact(w, "CONNECTING"); ptr->fact(w, "CONNECTED");
        while (!w->cancelled) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ptr->fact(w, "CONNECTED"); // intentionally late success after cancellation
        return std::string();
    }, [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
        std::lock_guard<std::mutex> lock(mutex); release = std::move(done);
    }, {}}, std::chrono::milliseconds(80));
    ptr = &rt; rt.ready(); until([&] { return rt.snapshot().phase == "idle"; });
    auto a = rt.connect(request("A"));
    until([&] { return rt.snapshot().phase == "connected"; });
    assert(rt.connect(request("A")).sessionId == a.sessionId);
    auto b = rt.connect(request("B")); auto c = rt.connect(request("C"));
    until([&] { return rt.snapshot().phase == "faulted"; });
    assert(!rt.snapshot().resourcesReleased);
    assert(executions == 1); // never start B/C over an unconfirmed TUN
    bool rejected = false;
    try { rt.connect(request("D")); } catch (...) { rejected = true; }
    assert(rejected);
    std::function<void(bool)> ack;
    { std::lock_guard<std::mutex> lock(mutex); ack = std::move(release); }
    assert(ack); ack(true);
    until([&] { return rt.snapshot().phase == "idle"; });
    auto e = rt.connect(request("E")); until([&] { return rt.snapshot().phase == "connected"; });
    rt.disconnect("old-cancel", a.sessionId);
    assert(rt.outcome("old-cancel").status == "noop");
    assert(rt.snapshot().session == e.sessionId);
    rt.disconnect("stop-E");
    until([&] { std::lock_guard<std::mutex> lock(mutex); return !!release; });
    { std::lock_guard<std::mutex> lock(mutex); ack = std::move(release); }
    ack(true); until([&] { return rt.snapshot().phase == "idle"; });
    assert(rt.snapshot().resourcesReleased && rt.snapshot().workerExited);
    rt.shutdown();

    // Challenge survives worker teardown, but an old response cannot target a different session.
    Runtime *challengeRuntime = nullptr;
    std::vector<std::future<void>> completions;
    Runtime challenge({[&](std::shared_ptr<Work> w) {
        if (w->request.response.empty()) {
            challengeRuntime->fact(w, "CHALLENGE", "code", false);
            challengeRuntime->fact(w, "CONNECTED"); // late success must not replace a pending challenge
        }
        else { challengeRuntime->fact(w, "CONNECTED"); while (!w->cancelled) std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
        return std::string();
    }, [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
        completions.push_back(std::async(std::launch::async, [done] { done(true); }));
    }, {}});
    challengeRuntime = &challenge; challenge.ready();
    auto q = challenge.connect(request("Q"));
    until([&] { return challenge.snapshot().phase == "awaitingCredentials" && challenge.snapshot().resourcesReleased; });
    auto snapshot = challenge.snapshot();
    assert(!challenge.credentials("wrong", snapshot.challengeId, "123"));
    assert(challenge.credentials(q.sessionId, snapshot.challengeId, "123"));
    until([&] { return challenge.snapshot().phase == "connected"; });
    assert(!challenge.credentials(q.sessionId, snapshot.challengeId, "123"));
    challenge.disconnect("stop-Q"); until([&] { return challenge.snapshot().phase == "idle"; });
    challenge.shutdown();
    for (auto &completion : completions) completion.get();
    // A terminal Core event closes success acceptance before the worker exits.
    Runtime *fatalRuntime = nullptr;
    std::future<void> fatalCleanup;
    Runtime fatal({[&](std::shared_ptr<Work> w) {
        fatalRuntime->fact(w, "CONNECTED");
        fatalRuntime->failed(w, "AUTH_FAILED");
        fatalRuntime->fact(w, "CONNECTED");
        while (!w->cancelled) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return std::string("AUTH_FAILED");
    }, [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
        fatalCleanup = std::async(std::launch::async, [done] { done(true); });
    }, {}});
    fatalRuntime = &fatal; fatal.ready(); fatal.connect(request("fatal"));
    until([&] { const auto s = fatal.snapshot(); return s.phase == "idle" && s.error == "AUTH_FAILED"; });
    assert(fatal.snapshot().resourcesReleased);
    fatal.shutdown(); fatalCleanup.get();

    // Production command IDs reject replay even after the result leaves the window.
    std::vector<std::future<void>> acknowledgements;
    Runtime ledger({[](std::shared_ptr<Work>) { return std::string("CONFIG_INVALID"); },
        [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
            acknowledgements.push_back(std::async(std::launch::async, [done] { done(true); }));
        }, {}, {}, true});
    ledger.ready(); until([&] { return ledger.snapshot().phase == "idle"; });
    const auto epoch = ledger.snapshot().engine;
    auto original = request(epoch + ":1");
    const auto accepted = ledger.connect(original);
    until([&] { return ledger.snapshot().phase == "idle" && ledger.snapshot().error == "CONFIG_INVALID"; });
    assert(ledger.connect(original).sessionId == accepted.sessionId);
    auto conflicting = original; conflicting.password = "different";
    bool conflict = false;
    try { ledger.connect(conflicting); } catch (const std::exception &e) { conflict = std::string(e.what()) == "REQUEST_ID_CONFLICT"; }
    assert(conflict);
    for (unsigned i = 2; i <= 270; ++i) {
        ledger.disconnect(epoch + ":" + std::to_string(i));
        until([&] { return ledger.snapshot().appliedCommandSeq == i; });
    }
    assert(ledger.outcome(original.requestId).status == "expired");
    bool expired = false, stale = false;
    try { ledger.connect(original); } catch (const std::exception &e) { expired = std::string(e.what()) == "REQUEST_EXPIRED"; }
    try { ledger.disconnect("old-epoch:271"); } catch (const std::exception &e) { stale = std::string(e.what()) == "STALE_CLIENT_EPOCH"; }
    assert(expired && stale);
    ledger.shutdown();
    for (auto &completion : acknowledgements) completion.get();
    // Unclean previous engines remain unknown until platform reconciliation succeeds.
    Runtime *recoveryRuntime = nullptr;
    Runtime recovering({[&](std::shared_ptr<Work> w) {
        if (w->request.profileId == "invalid") return std::string("CONFIG_INVALID");
        recoveryRuntime->fact(w, "PLATFORM_READY");
        return std::string("AUTH_FAILED");
    }, [](std::shared_ptr<Work>, std::function<void(bool)> done) { done(true); }, {}});
    recoveryRuntime = &recovering; recovering.ready(true); recovering.connect(request("invalid"));
    until([&] { return recovering.snapshot().phase == "initializing" && recovering.snapshot().error == "CONFIG_INVALID"; });
    assert(!recovering.snapshot().baselineKnown && !recovering.snapshot().resourcesReleased);
    recovering.disconnect("cancel-recovery");
    until([&] { return recovering.outcome("cancel-recovery").status == "applied"; });
    assert(recovering.snapshot().phase == "initializing");
    recovering.connect(request("valid"));
    until([&] { return recovering.snapshot().phase == "idle" && recovering.snapshot().error == "AUTH_FAILED"; });
    assert(recovering.snapshot().baselineKnown && recovering.snapshot().resourcesReleased);
    recovering.shutdown();

    // Platform callbacks can complete inline, query state, and arrive after destruction.
    std::function<void(bool)> delayed;
    {
        Runtime *inlineRuntime = nullptr;
        Runtime synchronous({[](std::shared_ptr<Work>) { return std::string("CONFIG_INVALID"); },
            [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
                assert(inlineRuntime->snapshot().workerExited);
                delayed = done; done(true); done(false); // first completion is authoritative
            }, {}});
        inlineRuntime = &synchronous; synchronous.ready(); synchronous.connect(request("inline"));
        until([&] { return synchronous.snapshot().phase == "idle" && synchronous.snapshot().error == "CONFIG_INVALID"; });
    }
    delayed(false); // retained platform callback must not access a destroyed Runtime
    // A never-ACKed release must not disable the cleanup action forever. Each
    // retry is a new attempt; old success/failure may not settle the new attempt.
    Runtime *retryRuntime = nullptr;
    std::mutex retryMutex;
    std::vector<std::function<void(bool)>> retryCallbacks;
    Runtime retrying({[&](std::shared_ptr<Work> w) {
        retryRuntime->fact(w, "CONNECTED");
        while (!w->cancelled) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return std::string();
    }, [&](std::shared_ptr<Work>, std::function<void(bool)> done) {
        std::lock_guard<std::mutex> lock(retryMutex); retryCallbacks.push_back(done);
    }, {}}, std::chrono::milliseconds(40));
    retryRuntime = &retrying; retrying.ready();
    retrying.connect(request("retry-session"));
    until([&] { return retrying.snapshot().phase == "connected"; });
    retrying.disconnect("retry-stop");
    until([&] { return retrying.snapshot().phase == "faulted"; });
    retrying.retryCleanup();
    until([&] { std::lock_guard<std::mutex> lock(retryMutex); return retryCallbacks.size() == 2; });
    std::function<void(bool)> firstRelease, secondRelease;
    { std::lock_guard<std::mutex> lock(retryMutex); firstRelease = retryCallbacks[0]; secondRelease = retryCallbacks[1]; }
    firstRelease(true); // resource ACK from the timed-out generation
    until([&] { return retrying.snapshot().phase == "faulted"; });
    assert(!retrying.snapshot().resourcesReleased);
    secondRelease(false);
    until([&] { return retrying.snapshot().error == "CLEANUP_FAILED"; });
    retrying.retryCleanup();
    until([&] { std::lock_guard<std::mutex> lock(retryMutex); return retryCallbacks.size() == 3; });
    std::function<void(bool)> finalRelease;
    { std::lock_guard<std::mutex> lock(retryMutex); finalRelease = retryCallbacks[2]; }
    finalRelease(true);
    until([&] { return retrying.snapshot().phase == "idle"; });
    retrying.connect(request("after-cleanup-retry"));
    until([&] { return retrying.snapshot().phase == "connected"; });
    firstRelease(false); secondRelease(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    assert(retrying.snapshot().phase == "connected");
    retrying.disconnect("stop-after-retry");
    until([&] { std::lock_guard<std::mutex> lock(retryMutex); return retryCallbacks.size() == 4; });
    { std::lock_guard<std::mutex> lock(retryMutex); finalRelease = retryCallbacks[3]; }
    finalRelease(true); until([&] { return retrying.snapshot().phase == "idle"; });
    retrying.shutdown();

    // Cancelled/expired credential prompts must use the same empty idle snapshot
    // as normal disconnect, including after the Core worker has already exited.
    for (const auto &kind : {"dynamic", "static", "privateKey"}) {
        for (bool expire : {false, true}) {
            Runtime *credentialRuntime = nullptr;
            Runtime credential({[&](std::shared_ptr<Work> w) {
                w->request.challengeKind = kind;
                credentialRuntime->fact(w, "CHALLENGE", "prompt", true);
                return std::string();
            }, [](std::shared_ptr<Work>, std::function<void(bool)> done) { done(true); }, {}},
                std::chrono::milliseconds(80), expire ? std::chrono::milliseconds(40) : std::chrono::seconds(2));
            credentialRuntime = &credential; credential.ready();
            credential.connect(request(std::string(kind) + (expire ? "-expired" : "-cancelled")));
            until([&] { const auto s = credential.snapshot(); return s.phase == "awaitingCredentials" && s.resourcesReleased; });
            auto old = credential.snapshot();
            if (!expire) credential.disconnect("cancel-credentials");
            until([&] { return credential.snapshot().phase == "idle"; });
            const auto idle = credential.snapshot();
            assert(idle.session.empty() && idle.attempt.empty() && idle.target.empty());
            assert(idle.profileId.empty() && idle.revision.empty());
            assert(idle.challengeId.empty() && idle.prompt.empty() && idle.challengeKind.empty());
            assert(!idle.echo && idle.challengeDeadlineMs == 0 && idle.resourcesReleased);
            assert(!credential.credentials(old.session, old.challengeId, "late-response"));
            if (expire) assert(idle.error == "CHALLENGE_EXPIRED");
            credential.shutdown();
        }
    }
    std::cout << "Session runtime regressions passed: fences, resource barrier, timeout, idempotence, scoped stop, late success, challenge, shutdown, replay window, content conflicts, terminal event fence, cleanup retry generations, stale cleanup ACK, cancelled/expired credential snapshots\n";
}
