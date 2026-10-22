//    OpenVPN 3 for HarmonyOS - NAPI Interface Layer
//
//    Exposes OpenVPN 3 client API to ArkTS via Node-API (NAPI).
//
//    API v2 admits commands immediately; subscribe/query authoritative snapshots.
//    Install a TunProvider and Observer before OvpnConnect(request).
//    Native runs OpenVPN on its own worker; the VPN extension owns only TUN.
//
// SPDX-License-Identifier: MPL-2.0

// Keep the external GPL LZO library out of the application. OpenVPN's own
// MPL-licensed LZO decoder supplies receive-only compatibility.
#if defined(HAVE_LZO)
#error "External LZO is unsupported; use the built-in receive-only LZO decoder"
#endif

// ─── OpenVPN 3 pre-definitions ─────────────────────────────────────────────
#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#ifndef USE_ASIO
#define USE_ASIO
#endif
#ifndef USE_OPENSSL
#define USE_OPENSSL
#endif
#ifndef HAVE_LZ4
#define HAVE_LZ4
#endif
#ifndef USE_TUN_BUILDER
#define USE_TUN_BUILDER
#endif
#ifndef OPENVPN_FORCE_TUN_NULL
#define OPENVPN_FORCE_TUN_NULL
#endif
#ifndef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_USE_LOG_BASE_SIMPLE
#endif

// ─── HiLog setup ───────────────────────────────────────────────────────────
#include <hilog/log.h>

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x0750
#define LOG_TAG    "OVPN"

// ─── Redirect OpenVPN 3 OPENVPN_LOG to HiLog ──────────────────────────────
#include <sstream>
#include "core/session_trace.hpp"

namespace openvpn {
namespace OHOS {
class OVPN_HLog {
  public:
    OVPN_HLog() = default;
    ~OVPN_HLog() {
        std::string msg = ss_.str();
        if (!msg.empty() && msg.back() == '\n') msg.pop_back();
        if (!msg.empty()) {
            SafeCoreLog(msg);
        }
    }
    template <typename T>
    OVPN_HLog &operator<<(const T &val) { ss_ << val; return *this; }
    OVPN_HLog &operator<<(std::ostream &(*pf)(std::ostream &)) { ss_ << pf; return *this; }
  private:
    std::ostringstream ss_;
};
} // namespace OHOS
} // namespace openvpn

#define OPENVPN_LOG_STREAM openvpn::OHOS::OVPN_HLog()

// ─── Include the OpenVPN 3 core ─────────────────────────────────────────────
#include <client/ovpncli.cpp>

// ─── Profile model for the visual editor (parse/build, no NAPI deps) ───────
#include "ovpn_profile_model.hpp"
#include "runtime/session_runtime.hpp"


// ─── NAPI headers ──────────────────────────────────────────────────────────
#include <node_api.h>
#include <napi/native_api.h>

#include <string>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <thread>
#include <atomic>
#include <vector>
#include <csignal>
#include <cstring>
#include <pthread.h>
#include <condition_variable>

// ============================================================================
//  VpnConfig model — mirrors HarmonyOS vpnExtension.VpnConfig
//  (NetAddress, LinkAddress, RouteInfo mirror connection.* system types)
// ============================================================================

struct NetAddress {
    std::string address;
    int family = 1;     // 1=IPv4, 2=IPv6
};

struct LinkAddress {
    NetAddress address;
    int prefixLength = 24;
};

struct RouteInfo {
    LinkAddress destination;
    NetAddress gateway;
    std::string interfaceName = "vpn-tun";  // system default VPN NIC name
    bool hasGateway = true;
    bool isDefaultRoute = true;
    bool isExcludedRoute = false;  // API 20+：原生排除路由（网段不进隧道）
};

struct VpnConfig {
    std::vector<LinkAddress> addresses;
    std::vector<RouteInfo> routes;
    std::vector<std::string> dnsAddresses;
    std::vector<std::string> searchDomains;
    // 本应用自屏蔽：包名列表内的应用自身流量不进 VPN 隧道。OpenVPN 隧道 socket 创建于
    // 主进程（core 已从 vpn 扩展进程迁出，见 docs/move-core-to-main-process.md D2/D3），
    // protect() 只作用于调用方进程 fd table，故不再使用 protectProcessNet/per-socket
    // protect，改为把本包名加黑名单，从系统路由层面免除流量回环。
    std::vector<std::string> blockedApplications = {"com.arror.ovpn"};
    int mtu = 1400;
    bool isIPv4Accepted = true;
    bool isIPv6Accepted = false;
};

// ============================================================================
//  Event data
// ============================================================================

struct EventData {
    std::string name;
    std::string info;
    bool error = false;
};

using OvpnConnectionInfo = ovpn_runtime::Connection;

struct StatsData {
    long long tunBytesIn = 0, tunBytesOut = 0, tunPacketsIn = 0, tunPacketsOut = 0;
    long long bytesIn = 0;
    long long bytesOut = 0;
    long long packetsIn = 0;
    long long packetsOut = 0;
    long long rateIn = 0;
    long long rateOut = 0;
    long long connectedDuration = 0;
    OvpnConnectionInfo connInfo;
};

static napi_value CreateNetAddress(napi_env env, const NetAddress &addr) {
    napi_value obj;
    napi_create_object(env, &obj);
    napi_value ip;
    napi_create_string_utf8(env, addr.address.c_str(), NAPI_AUTO_LENGTH, &ip);
    napi_set_named_property(env, obj, "address", ip);
    napi_value fam;
    napi_create_int32(env, addr.family, &fam);
    napi_set_named_property(env, obj, "family", fam);
    return obj;
}

static napi_value CreateLinkAddress(napi_env env, const LinkAddress &la) {
    napi_value obj;
    napi_create_object(env, &obj);
    napi_value addr = CreateNetAddress(env, la.address);
    napi_set_named_property(env, obj, "address", addr);
    napi_value prefix;
    napi_create_int32(env, la.prefixLength, &prefix);
    napi_set_named_property(env, obj, "prefixLength", prefix);
    return obj;
}

static napi_value CreateRouteInfo(napi_env env, const RouteInfo &ri) {
    napi_value obj;
    napi_create_object(env, &obj);
    napi_value dest = CreateLinkAddress(env, ri.destination);
    napi_set_named_property(env, obj, "destination", dest);
    napi_value gw = CreateNetAddress(env, ri.gateway);
    napi_set_named_property(env, obj, "gateway", gw);
    // interface — empty string means system default (VPN virtual NIC)
    napi_value iface;
    napi_create_string_utf8(env, "", 0, &iface);
    napi_set_named_property(env, obj, "interface", iface);
    napi_value hg;
    napi_get_boolean(env, ri.hasGateway, &hg);
    napi_set_named_property(env, obj, "hasGateway", hg);
    napi_value dr;
    napi_get_boolean(env, ri.isDefaultRoute, &dr);
    napi_set_named_property(env, obj, "isDefaultRoute", dr);
    napi_value ex;
    napi_get_boolean(env, ri.isExcludedRoute, &ex);
    napi_set_named_property(env, obj, "isExcludedRoute", ex);
    return obj;
}

static napi_value CreateTunConfigObject(napi_env env, const VpnConfig &cfg) {
    napi_value config;
    napi_create_object(env, &config);

    // addresses
    napi_value addresses;
    napi_create_array_with_length(env, cfg.addresses.size(), &addresses);
    for (size_t i = 0; i < cfg.addresses.size(); i++) {
        napi_set_element(env, addresses, i, CreateLinkAddress(env, cfg.addresses[i]));
    }
    napi_set_named_property(env, config, "addresses", addresses);

    // routes
    napi_value routes;
    napi_create_array_with_length(env, cfg.routes.size(), &routes);
    for (size_t i = 0; i < cfg.routes.size(); i++) {
        napi_set_element(env, routes, i, CreateRouteInfo(env, cfg.routes[i]));
    }
    napi_set_named_property(env, config, "routes", routes);

    // dnsAddresses
    napi_value dns;
    napi_create_array_with_length(env, cfg.dnsAddresses.size(), &dns);
    for (size_t i = 0; i < cfg.dnsAddresses.size(); i++) {
        napi_value s;
        napi_create_string_utf8(env, cfg.dnsAddresses[i].c_str(), NAPI_AUTO_LENGTH, &s);
        napi_set_element(env, dns, i, s);
    }
    napi_set_named_property(env, config, "dnsAddresses", dns);

    // searchDomains
    napi_value search;
    napi_create_array_with_length(env, cfg.searchDomains.size(), &search);
    for (size_t i = 0; i < cfg.searchDomains.size(); i++) {
        napi_value s;
        napi_create_string_utf8(env, cfg.searchDomains[i].c_str(), NAPI_AUTO_LENGTH, &s);
        napi_set_element(env, search, i, s);
    }
    napi_set_named_property(env, config, "searchDomains", search);

    // blockedApplications — 本应用自屏蔽，防隧道流量回环（见 VpnConfig 注释）
    napi_value blocked;
    napi_create_array_with_length(env, cfg.blockedApplications.size(), &blocked);
    for (size_t i = 0; i < cfg.blockedApplications.size(); i++) {
        napi_value s;
        napi_create_string_utf8(env, cfg.blockedApplications[i].c_str(), NAPI_AUTO_LENGTH, &s);
        napi_set_element(env, blocked, i, s);
    }
    napi_set_named_property(env, config, "blockedApplications", blocked);

    // mtu
    napi_value mtu;
    napi_create_int32(env, cfg.mtu, &mtu);
    napi_set_named_property(env, config, "mtu", mtu);

    // isIPv4Accepted / isIPv6Accepted
    napi_value v4;
    napi_get_boolean(env, cfg.isIPv4Accepted, &v4);
    napi_set_named_property(env, config, "isIPv4Accepted", v4);
    napi_value v6;
    napi_get_boolean(env, cfg.isIPv6Accepted, &v6);
    napi_set_named_property(env, config, "isIPv6Accepted", v6);

    return config;
}

static std::string NapiGetString(napi_env env, napi_value val, size_t max_len = 0) {
    size_t len = 0;
    if (napi_get_value_string_utf8(env, val, nullptr, 0, &len) != napi_ok) return "";
    if (max_len > 0 && len > max_len) {
        napi_throw_range_error(env, "INPUT_TOO_LARGE", "Input exceeds size limit"); return "";
    }
    std::vector<char> buffer(len + 1);
    napi_get_value_string_utf8(env, val, buffer.data(), buffer.size(), &len);
    return std::string(buffer.data(), len);
}


#include "napi/session_bridge.inc"
#include "core/session_client.inc"
static napi_value EvalMetadata(napi_env env, const openvpn::ClientAPI::EvalConfig &ev) {
    napi_value result;
    napi_create_object(env, &result);

    napi_value val;
    napi_create_string_utf8(env, ev.profileName.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "profileName", val);

    napi_create_string_utf8(env, ev.friendlyName.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "friendlyName", val);

    napi_create_string_utf8(env, ev.remoteHost.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "remoteHost", val);

    napi_create_string_utf8(env, ev.remotePort.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "remotePort", val);

    napi_create_string_utf8(env, ev.remoteProto.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "remoteProto", val);

    napi_get_boolean(env, ev.autologin, &val);
    napi_set_named_property(env, result, "autologin", val);

    napi_get_boolean(env, ev.externalPki, &val);
    napi_set_named_property(env, result, "externalPki", val);

    napi_get_boolean(env, ev.privateKeyPasswordRequired, &val);
    napi_set_named_property(env, result, "privateKeyPasswordRequired", val);

    napi_get_boolean(env, ev.allowPasswordSave, &val);
    napi_set_named_property(env, result, "allowPasswordSave", val);

    return result;
}
struct EvalProfileWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string content;
    openvpn::ClientAPI::EvalConfig evaluated;
    bool failed = false;
};
static void ExecuteEvalProfile(napi_env, void *data) {
    auto w = static_cast<EvalProfileWork *>(data);
    try {
        OhosVpnClient client;
        openvpn::ClientAPI::Config config; config.content = w->content;
        w->evaluated = client.eval_config(config);
        w->failed = w->evaluated.error;
    } catch (...) { w->failed = true; }
    w->content.clear();
}
static void CompleteEvalProfile(napi_env env, napi_status status, void *data) {
    auto w = static_cast<EvalProfileWork *>(data);
    if (status != napi_ok || w->failed) {
        napi_value error; napi_create_error(env, JsString(env, "CONFIG_INVALID"), JsString(env, "OpenVPN profile validation failed"), &error);
        napi_reject_deferred(env, w->deferred, error);
    } else napi_resolve_deferred(env, w->deferred, EvalMetadata(env, w->evaluated));
    napi_delete_async_work(env, w->work); delete w;
}
static napi_value EvalProfile(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value content; napi_get_cb_info(env, info, &argc, &content, nullptr, nullptr);
    if (!argc) { napi_throw_type_error(env, nullptr, "Profile required"); return nullptr; }
    auto w = new EvalProfileWork;
    w->content = NapiGetString(env, content, 1024 * 1024);
    bool exception = false; napi_is_exception_pending(env, &exception);
    if (exception) { delete w; return nullptr; }
    napi_value promise; napi_create_promise(env, &w->deferred, &promise);
    napi_create_async_work(env, nullptr, JsString(env, "OvpnEvalProfile"), ExecuteEvalProfile, CompleteEvalProfile, w, &w->work);
    napi_queue_async_work(env, w->work); return promise;
}
static napi_value ArkTsOvpnEvalConfig(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value content; napi_get_cb_info(env, info, &argc, &content, nullptr, nullptr);
    if (!argc) { napi_throw_type_error(env, nullptr, "Profile required"); return nullptr; }
    OhosVpnClient client; openvpn::ClientAPI::Config config;
    config.content = NapiGetString(env, content, 1024 * 1024);
    auto evaluated = client.eval_config(config);
    if (evaluated.error) { napi_throw_error(env, "CONFIG_INVALID", "OpenVPN profile validation failed"); return nullptr; }
    return EvalMetadata(env, evaluated);
}

// ============================================================================
//  OvpnParseProfile / OvpnBuildProfile / OvpnMergeProfile — visual editor API
// ============================================================================
//
//  The profile text is the single source of truth. OvpnParseProfile extracts
//  a structured model (edited fields + verbatim passthrough of everything
//  else + diagnostics); OvpnBuildProfile re-serializes the model back to a
//  .ovpn text. OvpnMergeProfile inlines external file references
//  (`<ca> file` / `<<ca>`) before parsing.

// ─── NAPI field helpers ────────────────────────────────────────────────────

static void NapiSetStr(napi_env env, napi_value obj, const char *name, const std::string &v) {
    napi_value val;
    napi_create_string_utf8(env, v.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, obj, name, val);
}

static void NapiSetBool(napi_env env, napi_value obj, const char *name, bool v) {
    napi_value val;
    napi_get_boolean(env, v, &val);
    napi_set_named_property(env, obj, name, val);
}

static void NapiSetStrArray(napi_env env, napi_value obj, const char *name,
                            const std::vector<std::string> &list) {
    napi_value arr;
    napi_create_array_with_length(env, list.size(), &arr);
    for (size_t i = 0; i < list.size(); i++) {
        napi_value v;
        napi_create_string_utf8(env, list[i].c_str(), NAPI_AUTO_LENGTH, &v);
        napi_set_element(env, arr, i, v);
    }
    napi_set_named_property(env, obj, name, arr);
}

static std::string NapiGetStrField(napi_env env, napi_value obj, const char *name,
                                   const char *def = "") {
    napi_value v;
    if (napi_get_named_property(env, obj, name, &v) == napi_ok && v != nullptr) {
        napi_valuetype t = napi_undefined;
        napi_typeof(env, v, &t);
        if (t == napi_string)
            return NapiGetString(env, v);
    }
    return def;
}

static bool NapiGetBoolField(napi_env env, napi_value obj, const char *name, bool def = false) {
    napi_value v;
    if (napi_get_named_property(env, obj, name, &v) == napi_ok && v != nullptr) {
        napi_valuetype t = napi_undefined;
        napi_typeof(env, v, &t);
        if (t == napi_boolean) {
            bool b = def;
            napi_get_value_bool(env, v, &b);
            return b;
        }
    }
    return def;
}

static std::vector<std::string> NapiGetStrArrayField(napi_env env, napi_value obj, const char *name) {
    std::vector<std::string> out;
    napi_value arr;
    if (napi_get_named_property(env, obj, name, &arr) != napi_ok || arr == nullptr)
        return out;
    napi_valuetype t = napi_undefined;
    napi_typeof(env, arr, &t);
    if (t != napi_object)
        return out;
    uint32_t len = 0;
    napi_get_array_length(env, arr, &len);
    out.reserve(len);
    for (uint32_t i = 0; i < len; i++) {
        napi_value v;
        if (napi_get_element(env, arr, i, &v) == napi_ok && v != nullptr) {
            napi_valuetype vt = napi_undefined;
            napi_typeof(env, v, &vt);
            if (vt == napi_string)
                out.push_back(NapiGetString(env, v));
        }
    }
    return out;
}

// ─── Model ↔ NAPI object ───────────────────────────────────────────────────

static napi_value ProfileModelToNapi(napi_env env, const ovpn_profile::Model &m) {
    napi_value obj;
    napi_create_object(env, &obj);

    NapiSetBool(env, obj, "error", m.error);
    NapiSetStr(env, obj, "errorMessage", m.errorMessage);

    NapiSetStr(env, obj, "profileName", m.profileName);
    NapiSetStr(env, obj, "friendlyName", m.friendlyName);
    NapiSetStr(env, obj, "userlockedUsername", m.userlockedUsername);
    NapiSetStr(env, obj, "staticChallenge", m.staticChallenge);
    NapiSetBool(env, obj, "staticChallengeEcho", m.staticChallengeEcho);
    NapiSetBool(env, obj, "autologin", m.autologin);
    NapiSetBool(env, obj, "externalPki", m.externalPki);
    NapiSetBool(env, obj, "privateKeyPasswordRequired", m.privateKeyPasswordRequired);
    NapiSetBool(env, obj, "allowPasswordSave", m.allowPasswordSave);
    NapiSetStr(env, obj, "vpnCa", m.vpnCa);

    napi_value remotes;
    napi_create_array_with_length(env, m.remotes.size(), &remotes);
    for (size_t i = 0; i < m.remotes.size(); i++) {
        napi_value r;
        napi_create_object(env, &r);
        NapiSetStr(env, r, "host", m.remotes[i].host);
        NapiSetStr(env, r, "port", m.remotes[i].port);
        NapiSetStr(env, r, "proto", m.remotes[i].proto);
        napi_set_element(env, remotes, i, r);
    }
    napi_set_named_property(env, obj, "remotes", remotes);
    NapiSetBool(env, obj, "remoteRandom", m.remoteRandom);
    NapiSetStr(env, obj, "serverPollTimeout", m.serverPollTimeout);

    NapiSetBool(env, obj, "hasAuthUserPass", m.hasAuthUserPass);
    NapiSetStr(env, obj, "authUsername", m.authUsername);
    NapiSetStr(env, obj, "authPassword", m.authPassword);

    NapiSetStr(env, obj, "keyDirection", m.keyDirection);
    NapiSetStr(env, obj, "tlsType", m.tlsType);
    NapiSetStr(env, obj, "tlsKey", m.tlsKey);

    NapiSetStr(env, obj, "ca", m.ca);
    NapiSetStr(env, obj, "cert", m.cert);
    NapiSetStr(env, obj, "key", m.key);
    NapiSetStr(env, obj, "crl", m.crl);
    NapiSetStr(env, obj, "extraCerts", m.extraCerts);
    NapiSetStrArray(env, obj, "peerFingerprints", m.peerFingerprints);
    NapiSetStr(env, obj, "remoteCertTls", m.remoteCertTls);
    NapiSetStr(env, obj, "verifyX509Name", m.verifyX509Name);
    NapiSetStr(env, obj, "verifyX509Mode", m.verifyX509Mode);
    NapiSetStr(env, obj, "tlsVersionMin", m.tlsVersionMin);
    NapiSetBool(env, obj, "tlsVersionMinOrHighest", m.tlsVersionMinOrHighest);

    NapiSetStr(env, obj, "cipher", m.cipher);
    NapiSetStr(env, obj, "auth", m.auth);
    NapiSetBool(env, obj, "hasCompress", m.hasCompress);
    NapiSetStr(env, obj, "compress", m.compress);

    NapiSetStr(env, obj, "keepalivePing", m.keepalivePing);
    NapiSetStr(env, obj, "keepaliveTimeout", m.keepaliveTimeout);
    NapiSetStr(env, obj, "renegSec", m.renegSec);

    NapiSetBool(env, obj, "hasRedirectGateway", m.hasRedirectGateway);
    NapiSetStrArray(env, obj, "redirectGatewayFlags", m.redirectGatewayFlags);
    NapiSetBool(env, obj, "routeNopull", m.routeNopull);
    NapiSetBool(env, obj, "blockIpv6", m.blockIpv6);
    napi_value routes;
    napi_create_array_with_length(env, m.routes.size(), &routes);
    for (size_t i = 0; i < m.routes.size(); i++) {
        napi_value r;
        napi_create_object(env, &r);
        NapiSetStr(env, r, "network", m.routes[i].network);
        NapiSetStr(env, r, "netmask", m.routes[i].netmask);
        NapiSetStr(env, r, "gateway", m.routes[i].gateway);
        NapiSetStr(env, r, "metric", m.routes[i].metric);
        napi_set_element(env, routes, i, r);
    }
    napi_set_named_property(env, obj, "routes", routes);
    napi_value dhcps;
    napi_create_array_with_length(env, m.dhcpOptions.size(), &dhcps);
    for (size_t i = 0; i < m.dhcpOptions.size(); i++) {
        napi_value d;
        napi_create_object(env, &d);
        NapiSetStr(env, d, "type", m.dhcpOptions[i].type);
        NapiSetStr(env, d, "value", m.dhcpOptions[i].value);
        napi_set_element(env, dhcps, i, d);
    }
    napi_set_named_property(env, obj, "dhcpOptions", dhcps);

    NapiSetStrArray(env, obj, "extra", m.extra);
    NapiSetStrArray(env, obj, "extraKinds", m.extraKinds);
    NapiSetStrArray(env, obj, "unsupported", m.unsupported);
    NapiSetStrArray(env, obj, "ignored", m.ignored);

    return obj;
}

static void NapiToProfileModel(napi_env env, napi_value obj, ovpn_profile::Model &m) {
    m.error = NapiGetBoolField(env, obj, "error", false);
    m.errorMessage = NapiGetStrField(env, obj, "errorMessage");
    m.profileName = NapiGetStrField(env, obj, "profileName");
    m.friendlyName = NapiGetStrField(env, obj, "friendlyName");
    m.userlockedUsername = NapiGetStrField(env, obj, "userlockedUsername");
    m.staticChallenge = NapiGetStrField(env, obj, "staticChallenge");
    m.staticChallengeEcho = NapiGetBoolField(env, obj, "staticChallengeEcho", false);
    m.autologin = NapiGetBoolField(env, obj, "autologin", false);
    m.externalPki = NapiGetBoolField(env, obj, "externalPki", false);
    m.privateKeyPasswordRequired = NapiGetBoolField(env, obj, "privateKeyPasswordRequired", false);
    m.allowPasswordSave = NapiGetBoolField(env, obj, "allowPasswordSave", false);
    m.vpnCa = NapiGetStrField(env, obj, "vpnCa");

    // remotes
    {
        napi_value arr;
        if (napi_get_named_property(env, obj, "remotes", &arr) == napi_ok && arr != nullptr) {
            napi_valuetype t = napi_undefined;
            napi_typeof(env, arr, &t);
            if (t == napi_object) {
                uint32_t len = 0;
                napi_get_array_length(env, arr, &len);
                for (uint32_t i = 0; i < len; i++) {
                    napi_value r;
                    if (napi_get_element(env, arr, i, &r) != napi_ok || r == nullptr)
                        continue;
                    ovpn_profile::Remote remote;
                    remote.host = NapiGetStrField(env, r, "host");
                    if (remote.host.empty())
                        continue;
                    remote.port = NapiGetStrField(env, r, "port");
                    remote.proto = NapiGetStrField(env, r, "proto");
                    m.remotes.push_back(std::move(remote));
                }
            }
        }
    }
    m.remoteRandom = NapiGetBoolField(env, obj, "remoteRandom", false);
    m.serverPollTimeout = NapiGetStrField(env, obj, "serverPollTimeout");

    m.hasAuthUserPass = NapiGetBoolField(env, obj, "hasAuthUserPass", false);
    m.authUsername = NapiGetStrField(env, obj, "authUsername");
    m.authPassword = NapiGetStrField(env, obj, "authPassword");

    m.keyDirection = NapiGetStrField(env, obj, "keyDirection");
    m.tlsType = NapiGetStrField(env, obj, "tlsType");
    m.tlsKey = NapiGetStrField(env, obj, "tlsKey");

    m.ca = NapiGetStrField(env, obj, "ca");
    m.cert = NapiGetStrField(env, obj, "cert");
    m.key = NapiGetStrField(env, obj, "key");
    m.crl = NapiGetStrField(env, obj, "crl");
    m.extraCerts = NapiGetStrField(env, obj, "extraCerts");
    m.peerFingerprints = NapiGetStrArrayField(env, obj, "peerFingerprints");
    m.remoteCertTls = NapiGetStrField(env, obj, "remoteCertTls");
    m.verifyX509Name = NapiGetStrField(env, obj, "verifyX509Name");
    m.verifyX509Mode = NapiGetStrField(env, obj, "verifyX509Mode");
    m.tlsVersionMin = NapiGetStrField(env, obj, "tlsVersionMin");
    m.tlsVersionMinOrHighest = NapiGetBoolField(env, obj, "tlsVersionMinOrHighest", false);

    m.cipher = NapiGetStrField(env, obj, "cipher");
    m.auth = NapiGetStrField(env, obj, "auth");
    m.hasCompress = NapiGetBoolField(env, obj, "hasCompress", false);
    m.compress = NapiGetStrField(env, obj, "compress");

    m.keepalivePing = NapiGetStrField(env, obj, "keepalivePing");
    m.keepaliveTimeout = NapiGetStrField(env, obj, "keepaliveTimeout");
    m.renegSec = NapiGetStrField(env, obj, "renegSec");

    m.hasRedirectGateway = NapiGetBoolField(env, obj, "hasRedirectGateway", false);
    m.redirectGatewayFlags = NapiGetStrArrayField(env, obj, "redirectGatewayFlags");
    m.routeNopull = NapiGetBoolField(env, obj, "routeNopull", false);
    m.blockIpv6 = NapiGetBoolField(env, obj, "blockIpv6", false);
    {
        napi_value arr;
        if (napi_get_named_property(env, obj, "routes", &arr) == napi_ok && arr != nullptr) {
            napi_valuetype t = napi_undefined;
            napi_typeof(env, arr, &t);
            if (t == napi_object) {
                uint32_t len = 0;
                napi_get_array_length(env, arr, &len);
                for (uint32_t i = 0; i < len; i++) {
                    napi_value r;
                    if (napi_get_element(env, arr, i, &r) != napi_ok || r == nullptr)
                        continue;
                    ovpn_profile::Route route;
                    route.network = NapiGetStrField(env, r, "network");
                    if (route.network.empty())
                        continue;
                    route.netmask = NapiGetStrField(env, r, "netmask");
                    route.gateway = NapiGetStrField(env, r, "gateway");
                    route.metric = NapiGetStrField(env, r, "metric");
                    m.routes.push_back(std::move(route));
                }
            }
        }
        if (napi_get_named_property(env, obj, "dhcpOptions", &arr) == napi_ok && arr != nullptr) {
            napi_valuetype t = napi_undefined;
            napi_typeof(env, arr, &t);
            if (t == napi_object) {
                uint32_t len = 0;
                napi_get_array_length(env, arr, &len);
                for (uint32_t i = 0; i < len; i++) {
                    napi_value d;
                    if (napi_get_element(env, arr, i, &d) != napi_ok || d == nullptr)
                        continue;
                    ovpn_profile::DhcpOption opt;
                    opt.type = NapiGetStrField(env, d, "type");
                    if (opt.type.empty())
                        continue;
                    opt.value = NapiGetStrField(env, d, "value");
                    m.dhcpOptions.push_back(std::move(opt));
                }
            }
        }
    }

    m.extra = NapiGetStrArrayField(env, obj, "extra");
    m.extraKinds = NapiGetStrArrayField(env, obj, "extraKinds");
    m.unsupported = NapiGetStrArrayField(env, obj, "unsupported");
    m.ignored = NapiGetStrArrayField(env, obj, "ignored");
}

// ─── OvpnParseProfile(content): OvpnProfileModel ───────────────────────────

static napi_value ArkTsOvpnParseProfile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "Expected (content)");
        return nullptr;
    }

    std::string content = NapiGetString(env, args[0], 1024 * 1024);

    try {
        ovpn_profile::Model m = ovpn_profile::parse_profile(content);
        if (m.error) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_DOMAIN, LOG_TAG,
                         "OvpnParseProfile error: %{public}s", m.errorMessage.c_str());
            napi_throw_error(env, "OVPN_CONFIG_ERROR", m.errorMessage.c_str());
            return nullptr;
        }
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "OvpnParseProfile: profile=%{public}s remotes=%{public}zu extra=%{public}zu "
                     "unsupported=%{public}zu ignored=%{public}zu",
                     m.profileName.c_str(), m.remotes.size(), m.extra.size(),
                     m.unsupported.size(), m.ignored.size());
        return ProfileModelToNapi(env, m);
    } catch (const std::exception &e) {
        napi_throw_error(env, "OVPN_CONFIG_ERROR", e.what());
        return nullptr;
    }
}

// ─── OvpnBuildProfile(model): string ───────────────────────────────────────

static napi_value ArkTsOvpnBuildProfile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "Expected (model)");
        return nullptr;
    }
    napi_valuetype t = napi_undefined;
    napi_typeof(env, args[0], &t);
    if (t != napi_object) {
        napi_throw_type_error(env, nullptr, "model must be an object");
        return nullptr;
    }

    try {
        ovpn_profile::Model m;
        NapiToProfileModel(env, args[0], m);
        std::string content = ovpn_profile::build_profile(m);

        // Post-build validation: the generated profile must parse cleanly.
        ovpn_profile::Model check = ovpn_profile::parse_profile(content);
        if (check.error) {
            napi_throw_error(env, "OVPN_BUILD_ERROR",
                             ("built profile failed validation: " + check.errorMessage).c_str());
            return nullptr;
        }

        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "OvpnBuildProfile: %{public}zu bytes, remotes=%{public}zu",
                     content.size(), m.remotes.size());
        napi_value result;
        napi_create_string_utf8(env, content.c_str(), NAPI_AUTO_LENGTH, &result);
        return result;
    } catch (const std::exception &e) {
        napi_throw_error(env, "OVPN_BUILD_ERROR", e.what());
        return nullptr;
    }
}

// ─── OvpnMergeProfile(content): {status, basename, profileContent, errorText} ─

static napi_value ArkTsOvpnMergeProfile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "Expected (content)");
        return nullptr;
    }

    std::string content = NapiGetString(env, args[0], 1024 * 1024);

    try {
        auto helper = std::make_shared<openvpn::ClientAPI::OpenVPNClientHelper>();
        openvpn::ClientAPI::MergeConfig mc = helper->merge_config_string(content);

        napi_value obj;
        napi_create_object(env, &obj);
        NapiSetStr(env, obj, "status", mc.status);
        NapiSetStr(env, obj, "basename", mc.basename);
        NapiSetStr(env, obj, "profileContent", mc.profileContent);
        NapiSetStr(env, obj, "errorText", mc.errorText);

        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "OvpnMergeProfile: status=%{public}s basename=%{public}s refs=%{public}zu",
                     mc.status.c_str(), mc.basename.c_str(), mc.refPathList.size());
        return obj;
    } catch (const std::exception &e) {
        napi_throw_error(env, "OVPN_MERGE_ERROR", e.what());
        return nullptr;
    }
}

static napi_value ArkTsOvpnParseDynamicChallenge(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "Expected (cookie)");
        return nullptr;
    }

    std::string cookie = NapiGetString(env, args[0], 8192);

    openvpn::ClientAPI::DynamicChallenge dc;
    if (!openvpn::ClientAPI::OpenVPNClientHelper::parse_dynamic_challenge(cookie, dc)) {
        napi_throw_error(env, "OVPN_CHALLENGE_ERROR", "malformed dynamic challenge cookie");
        return nullptr;
    }

    napi_value result;
    napi_create_object(env, &result);
    napi_value val;
    napi_create_string_utf8(env, dc.challenge.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "challenge", val);
    napi_get_boolean(env, dc.echo, &val);
    napi_set_named_property(env, result, "echo", val);
    napi_get_boolean(env, dc.responseRequired, &val);
    napi_set_named_property(env, result, "responseRequired", val);
    napi_create_string_utf8(env, dc.stateID.c_str(), NAPI_AUTO_LENGTH, &val);
    napi_set_named_property(env, result, "stateID", val);
    return result;
}

#include "napi/certificate_bridge.inc"

static napi_value ModuleInit(napi_env env, napi_value exports) {
    if (g_bridge) { napi_throw_error(env, "ENV_ALREADY_BOUND", "Runtime belongs to the application environment"); return nullptr; }
    InstallRuntime(env);
    napi_property_descriptor desc[] = {
        {"OvpnImportCertificates", nullptr, ImportCertificates, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGeneratePrivateKeyPassword", nullptr, GeneratePrivateKeyPassword, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnConnect", nullptr, ConnectCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnDisconnect", nullptr, DisconnectCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGetState", nullptr, GetState, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGetStats", nullptr, GetStats, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGetDiagnostics", nullptr, GetDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGetCapabilities", nullptr, Capabilities, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnSetObserver", nullptr, SetObserver, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnSetTunProvider", nullptr, SetProvider, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnNotifyTunEvent", nullptr, NotifyTunLost, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnShutdown", nullptr, ShutdownCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnRetryCleanup", nullptr, RetryCleanup, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnGetCommandOutcome", nullptr, GetOutcome, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnProvideCreds", nullptr, ProvideCredentials, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnEvalProfile", nullptr, EvalProfile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnEvalConfig", nullptr, ArkTsOvpnEvalConfig, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnParseProfile", nullptr, ArkTsOvpnParseProfile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnBuildProfile", nullptr, ArkTsOvpnBuildProfile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnMergeProfile", nullptr, ArkTsOvpnMergeProfile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"OvpnParseDynamicChallenge", nullptr, ArkTsOvpnParseDynamicChallenge, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
NAPI_MODULE(ovpn, ModuleInit)
