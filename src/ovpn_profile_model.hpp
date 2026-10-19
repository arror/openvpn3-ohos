// SPDX-License-Identifier: MPL-2.0
//    OpenVPN 3 for HarmonyOS - Profile Model (parse / build)
//
//    Structured view over an OpenVPN client profile (.ovpn text) for the
//    visual editor.  The profile text is the single source of truth:
//
//      parse_profile(content)  → Model   (extraction; keeps unsupported
//                                         directives verbatim in `extra`)
//      build_profile(Model)    → content (deterministic re-serialization;
//                                         `extra` is written back untouched)
//
//    Modeled directives are exactly those the visual editor edits; everything
//    else round-trips through `extra`.  Diagnostics (unsupported/ignored)
//    mirror openvpn/client/cliopt.hpp handle_unused_options() so the editor
//    can warn about directives that the core would reject or ignore.
//
//    Header-only; requires the OpenVPN 3 core headers (include after the
//    usual openvpn pre-definitions).  No NAPI dependencies → unit-testable
//    on a host toolchain (see test_profile_model.cpp).
//
// SPDX-License-Identifier: MPL-2.0

#ifndef OVPN_PROFILE_MODEL_HPP
#define OVPN_PROFILE_MODEL_HPP

#include <string>
#include <vector>
#include <set>
#include <algorithm>

#include <openvpn/common/options.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/client/cliopthelper.hpp>

namespace ovpn_profile {

using openvpn::Option;
using openvpn::OptionList;
using openvpn::ParseClientConfig;

// ─── helper: trim ASCII whitespace ─────────────────────────────────────────
inline std::string trim_copy(const std::string &s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

struct Remote
{
    std::string host;
    std::string port;
    std::string proto;
};

struct Route
{
    std::string network;
    std::string netmask;
    std::string gateway;
    std::string metric;
};

struct DhcpOption
{
    std::string type;  // DNS / DNS6 / DOMAIN / DOMAIN-SEARCH / ...
    std::string value;
};

struct Model
{
    // ── parse status ──
    bool error = false;
    std::string errorMessage;

    // ── meta (from ClientAPI::EvalConfig / ParseClientConfig) ──
    std::string profileName;
    std::string friendlyName;
    std::string userlockedUsername;
    std::string staticChallenge;
    bool staticChallengeEcho = false;
    bool autologin = false;
    bool externalPki = false;
    bool privateKeyPasswordRequired = false;
    bool allowPasswordSave = false;
    std::string vpnCa; // raw CA PEM as written in the profile ("" if absent)

    // ── connection ──
    std::vector<Remote> remotes;
    bool remoteRandom = false;
    std::string serverPollTimeout; // "" if unset

    // ── credentials embedded in the profile (<auth-user-pass>) ──
    bool hasAuthUserPass = false;
    std::string authUsername;
    std::string authPassword;

    // ── TLS control channel ──
    std::string keyDirection; // "", "0", "1"
    std::string tlsType;      // "", "tls-auth", "tls-crypt", "tls-crypt-v2"
    std::string tlsKey;       // inline key block content ("" if absent)

    // ── PKI ──
    std::string ca;         // inline PEM content ("" if absent)
    std::string cert;       // inline PEM content
    std::string key;        // inline PEM content
    std::string crl;        // inline PEM content
    std::string extraCerts; // inline PEM content
    std::vector<std::string> peerFingerprints;
    std::string remoteCertTls;    // "", "client", "server"
    std::string verifyX509Name;   // "" if unset
    std::string verifyX509Mode;   // "" = default ("subject")
    std::string tlsVersionMin;    // "", "1.0".."1.3"
    bool tlsVersionMinOrHighest = false;

    // ── data channel ──
    std::string cipher; // "" if unset
    std::string auth;   // "" if unset
    bool hasCompress = false;
    std::string compress; // "" = bare `compress` directive; "lzo" is emitted
    // as the legacy `comp-lzo` directive on rebuild — modern `compress lzo`
    // in the options string is rejected by older OpenVPN 2.x servers

    // ── session ──
    std::string keepalivePing;    // "" if unset
    std::string keepaliveTimeout; // "" if unset
    std::string renegSec;         // "" if unset

    // ── routes / DNS ──
    bool hasRedirectGateway = false;
    std::vector<std::string> redirectGatewayFlags;
    bool routeNopull = false;
    bool blockIpv6 = false;
    std::vector<Route> routes;
    std::vector<DhcpOption> dhcpOptions;

    // ── passthrough: directives not modeled above, preserved verbatim ──
    // single-line directives as "name p1 p2 ...", inline blocks as
    // "<name>\n<content></name>\n"
    std::vector<std::string> extra;
    // per-entry classification parallel to extra: "ok" (consumed by core),
    // "ignored" (core ignores with a warning; dropped on rebuild),
    // "ignored-silent" (no-op, retained), "unknown" (unrecognized),
    // "fatal" (known but unsupported → connect-time error)
    std::vector<std::string> extraKinds;

    // ── diagnostics (deduplicated directive names) ──
    std::vector<std::string> unsupported; // fatal at connect time
    std::vector<std::string> ignored;     // ignored with warning at connect
};

// ─── helper: does the option parameter look like inline PEM content? ───────
inline bool is_inline_content(const Option &o, const size_t idx)
{
    if (o.size() <= idx)
        return false;
    const std::string &v = o.ref(idx);
    return v.find('\n') != std::string::npos
           || v.rfind("-----BEGIN ", 0) == 0;
}

// ─── helper: extract user/password from <auth-user-pass> ───────────────────
inline void extract_auth_user_pass(const Option &o, std::string &user, std::string &pass)
{
    if (o.size() >= 3) // directive form: auth-user-pass user pass
    {
        user = o.ref(1);
        pass = o.ref(2);
    }
    else if (o.size() == 2 && is_inline_content(o, 1)) // inline block, never a credentials-file path
    {
        const std::string &content = o.ref(1);
        size_t p1 = content.find('\n');
        if (p1 == std::string::npos)
        {
            user = trim_copy(content);
            return;
        }
        user = trim_copy(content.substr(0, p1));
        size_t p2 = content.find('\n', p1 + 1);
        pass = trim_copy(p2 == std::string::npos
                                ? content.substr(p1 + 1)
                                : content.substr(p1 + 1, p2 - p1 - 1));
    }
}

// ─── directive classification (mirrors cliopt.hpp handle_unused_options) ───

// Directives the core consumes but the editor does not model: they pass
// through `extra` unchanged and must NOT trigger diagnostics.
inline const std::set<std::string> &supported_passthrough_directives()
{
    static const std::set<std::string> s = {
        "dev-type",
        "connection", "http-proxy", "http-proxy-option", "http-proxy-user-pass",
        "remote-random-hostname", "remote-cache-lifetime", "float", "inactive",
        "tls-cipher", "tls-ciphersuites", "tls-groups", "tls-cert-profile",
        "ns-cert-type", "remote-cert-ku", "remote-cert-eku", "tls-auth-digest",
        "auth-nocache", "push-peer-info", "client-cert-not-required",
        "allow-password-save", "ignore-unknown-option", "setenv",
        "block-outside-dns", "block-ipv4", "redirect-private", "route-ipv6",
        "route-metric", "tun-mtu", "tun-mtu-max", "mssfix", "mssfix-ctrl",
        "pull-filter", "static-challenge",
    };
    return s;
}

// Core: silently ignored (cliopt.hpp settings_ignoreSilently)
inline const std::set<std::string> &core_ignore_silently()
{
    static const std::set<std::string> s = {
        "ecdh-curve", "fast-io", "max-routes", "mute-replay-warnings",
        "nobind", "prng", "rcvbuf", "replay-persist", "script-security",
        "sndbuf", "tmp-dir", "tun-ipv6", "txqueuelen", "verb",
    };
    return s;
}

// Core: ignored with warning (cliopt.hpp settings_ignoreWithWarning)
inline const std::set<std::string> &core_ignore_with_warning()
{
    static const std::set<std::string> s = {
        "allow-compression", "allow-recursive-routing", "auth-retry",
        "compat-mode", "connect-retry", "connect-retry-max", "connect-timeout",
        "data-ciphers", "data-ciphers-fallback", "disable-dco", "disable-occ",
        "engine", "explicit-exit-notify", "group", "ifconfig-nowarn",
        "ip-win32", "link-mtu", "machine-readable-output", "mark", "mute",
        "ncp-ciphers", "nice", "opt-verify", "passtos", "persist-key",
        "persist-tun", "preresolve", "providers", "remap-usr1", "reneg-bytes",
        "reneg-pkts", "replay-window", "resolv-retry", "route-method",
        "route-delay", "show-net-up", "socket-flags", "suppress-timestamps",
        "tcp-nodelay", "tls-version-max", "tun-mtu-extra", "udp-mtu", "user",
    };
    return s;
}

// Core: features not implemented but safe to ignore
inline const std::set<std::string> &core_not_implemented_warn()
{
    static const std::set<std::string> s = {
        "allow-pull-fqdn", "bind", "local", "lport", "mlock", "mtu-disc",
        "mtu-test", "persist-local-ip", "persist-remote-ip", "shaper",
        "tls-exit",
    };
    return s;
}

// Core: script/plugin support missing
inline const std::set<std::string> &core_script_plugin()
{
    static const std::set<std::string> s = {
        "down", "down-pre", "ifconfig-noexec", "ipchange", "learn-address",
        "plugin", "route-noexec", "route-pre-down", "route-up", "setenv-safe",
        "tls-export-cert", "tls-verify", "up", "up-delay", "x509-track",
    };
    return s;
}

// Core: fatal groups
inline const std::set<std::string> &core_server_only()
{
    static const std::set<std::string> s = {
        "auth-gen-token", "auth-gen-token-secret", "auth-user-pass-optional",
        "auth-user-pass-verify", "bcast-buffers", "ccd-exclusive",
        "client-config-dir", "client-connect", "client-disconnect",
        "client-to-client", "connect-freq", "dh", "disable",
        "duplicate-cn", "hash-size", "ifconfig-ipv6-pool", "ifconfig-pool",
        "ifconfig-pool-persist", "ifconfig-push", "ifconfig-push-constraint",
        "iroute", "iroute-ipv6", "max-clients", "max-routes-per-client",
        "push", "push-remove", "push-reset", "server", "server-bridge",
        "server-ipv6", "stale-routes-check", "tls-crypt-v2-verify",
        "username-as-common-name", "verify-client-cert", "vlan-accept",
        "vlan-pvid", "vlan-tagging",
    };
    return s;
}

inline const std::set<std::string> &core_push_only()
{
    static const std::set<std::string> s = {
        "auth-token", "auth-token-user", "echo", "parameter", "ping",
        "ping-exit", "key-derivation", "peer-id", "protocol-flags",
        "ifconfig", "ifconfig-ipv6", "topology", "route-gateway",
    };
    return s;
}

inline const std::set<std::string> &core_standalone()
{
    static const std::set<std::string> s = {
        "genkey", "mktun", "rmtun", "show-ciphers", "show-curves",
        "show-digests", "show-engines", "show-groups", "show-tls",
        "test-crypto",
    };
    return s;
}

inline const std::set<std::string> &core_removed()
{
    static const std::set<std::string> s = {
        "mtu-dynamic", "no-replay", "no-name-remapping", "compat-names",
        "ncp-disable", "no-iv",
    };
    return s;
}

inline const std::set<std::string> &core_not_implemented_fatal()
{
    static const std::set<std::string> s = {
        "askpass", "capath", "cd", "chroot", "client-nat", "cryptoapicert",
        "daemon", "errors-to-stderr", "gremlin", "lladdr", "log",
        "log-append", "management", "memstats", "msg-channel",
        "ping-timer-rem", "single-session", "socks-proxy", "status",
        "status-version", "syslog", "tls-server", "verify-hash", "win-sys",
        "writepid", "x509-username-field", "pkcs12",
    };
    return s;
}

namespace detail {

inline bool is_fatal_directive(const std::string &name)
{
    if (name.rfind("management", 0) == 0)
        return true;
    return core_server_only().count(name) || core_push_only().count(name)
        || core_standalone().count(name) || core_removed().count(name)
        || core_not_implemented_fatal().count(name);
}

inline bool is_warn_directive(const std::string &name)
{
    return core_ignore_with_warning().count(name)
        || core_not_implemented_warn().count(name)
        || core_script_plugin().count(name);
}

// Directives the core explicitly ignores with a warning: they have no
// effect, so build_profile() drops them instead of writing them back.
inline bool is_ignored_directive(const std::string &name)
{
    return is_warn_directive(name);
}

// Render one option back to profile text. Inline blocks (multiline param)
// are wrapped in <name>...</name>; single-line directives joined by spaces.
inline std::string render_option(const Option &o)
{
    if (o.size() == 0)
        return "";
    const std::string &name = o.ref(0);
    if (o.size() == 2 && o.ref(1).find('\n') != std::string::npos)
    {
        std::string content = o.ref(1);
        if (content.empty() || content.back() != '\n')
            content += '\n';
        return "<" + name + ">\n" + content + "</" + name + ">\n";
    }
    std::string line = name;
    for (size_t i = 1; i < o.size(); ++i)
    {
        line += " ";
        line += o.ref(i);
    }
    line += "\n";
    return line;
}

inline void add_unique(std::vector<std::string> &v, const std::string &s)
{
    if (std::find(v.begin(), v.end(), s) == v.end())
        v.push_back(s);
}

} // namespace detail

// ─── parse_profile ─────────────────────────────────────────────────────────

inline Model parse_profile(const std::string &content)
{
    Model m;

    OptionList options;
    ParseClientConfig pcc = ParseClientConfig::parse(content, nullptr, options);

    if (pcc.error())
    {
        m.error = true;
        m.errorMessage = pcc.message();
        return m;
    }

    // meta
    m.profileName = pcc.profileName();
    m.friendlyName = pcc.friendlyName();
    m.userlockedUsername = pcc.userlockedUsername();
    m.staticChallenge = pcc.staticChallenge();
    m.staticChallengeEcho = pcc.staticChallengeEcho();
    m.autologin = pcc.autologin();
    m.externalPki = pcc.externalPki();
    m.privateKeyPasswordRequired = pcc.privateKeyPasswordRequired();
    m.allowPasswordSave = pcc.allowPasswordSave();
    m.vpnCa = pcc.vpnCa();

    // connection: enumerate `remote` directives, apply top-level port/proto
    {
        std::string default_port, default_proto;
        const Option *dp = options.get_ptr("port");
        if (dp && dp->size() >= 2)
            default_port = dp->ref(1);
        const Option *dpr = options.get_ptr("proto");
        if (dpr && dpr->size() >= 2)
            default_proto = dpr->ref(1);

        const OptionList::IndexList *idx = options.get_index_ptr("remote");
        if (idx)
        {
            for (auto i : *idx)
            {
                const Option &o = options[i];
                Remote r;
                r.host = o.get_optional(1, 256);
                r.port = o.get_optional(2, 16);
                r.proto = o.get_optional(3, 32);
                if (r.host.empty())
                    continue;
                if (r.port.empty())
                    r.port = default_port;
                if (r.proto.empty())
                    r.proto = default_proto;
                m.remotes.push_back(std::move(r));
            }
        }
    }
    m.remoteRandom = options.exists("remote-random");
    {
        const Option *o = options.get_ptr("server-poll-timeout");
        if (o)
            m.serverPollTimeout = o->get_optional(1, 16);
    }

    // credentials embedded in profile
    {
        const OptionList::IndexList *idx = options.get_index_ptr("auth-user-pass");
        if (idx && !idx->empty())
        {
            const Option &o = options[idx->back()];
            std::string user, pass;
            extract_auth_user_pass(o, user, pass);
            if (!user.empty() || !pass.empty())
            {
                m.hasAuthUserPass = true;
                m.authUsername = user;
                m.authPassword = pass;
            }
        }
    }

    // TLS control channel
    {
        const Option *o = options.get_ptr("key-direction");
        if (o)
            m.keyDirection = o->get_optional(1, 8);
    }
    {
        const char *types[] = {"tls-auth", "tls-crypt", "tls-crypt-v2"};
        for (const char *t : types)
        {
            const OptionList::IndexList *idx = options.get_index_ptr(t);
            if (!idx)
                continue;
            for (auto i : *idx)
            {
                const Option &o = options[i];
                if (is_inline_content(o, 1))
                {
                    m.tlsType = t;
                    m.tlsKey = o.ref(1);
                    break;
                }
                // file-reference form stays in `extra` (merge_profile should
                // have inlined it beforehand)
            }
            if (!m.tlsType.empty())
                break;
        }
    }

    // PKI blocks
    {
        struct PkiBlock
        {
            const char *name;
            std::string *dst;
        };
        PkiBlock blocks[] = {
            {"ca", &m.ca},     {"cert", &m.cert}, {"key", &m.key},
            {"crl-verify", &m.crl}, {"extra-certs", &m.extraCerts},
        };
        for (auto &b : blocks)
        {
            const OptionList::IndexList *idx = options.get_index_ptr(b.name);
            if (!idx)
                continue;
            for (auto i : *idx)
            {
                const Option &o = options[i];
                if (is_inline_content(o, 1))
                {
                    *b.dst = o.ref(1);
                    break;
                }
            }
        }
        const OptionList::IndexList *pfi = options.get_index_ptr("peer-fingerprint");
        if (pfi)
        {
            for (auto i : *pfi)
            {
                const Option &o = options[i];
                for (size_t k = 1; k < o.size(); ++k)
                    m.peerFingerprints.push_back(o.ref(k));
            }
        }
    }
    {
        const Option *o = options.get_ptr("remote-cert-tls");
        if (o)
            m.remoteCertTls = o->get_optional(1, 16);
        o = options.get_ptr("verify-x509-name");
        if (o)
        {
            m.verifyX509Name = o->get_optional(1, 256);
            m.verifyX509Mode = o->get_optional(2, 32);
        }
        o = options.get_ptr("tls-version-min");
        if (o)
        {
            m.tlsVersionMin = o->get_optional(1, 8);
            m.tlsVersionMinOrHighest = (o->get_optional(2, 16) == "or-highest");
        }
    }

    // data channel
    {
        const Option *o = options.get_ptr("cipher");
        if (o)
            m.cipher = o->get_optional(1, 128);
        o = options.get_ptr("auth");
        if (o)
            m.auth = o->get_optional(1, 128);
        o = options.get_ptr("compress");
        if (o)
        {
            m.hasCompress = true;
            m.compress = o->get_optional(1, 128);
        }
        o = options.get_ptr("comp-lzo");
        if (o)
        {
            m.hasCompress = true;
            m.compress = "lzo";
        }
    }

    // session
    {
        const Option *o = options.get_ptr("keepalive");
        if (o && o->size() <= 3)
        {
            m.keepalivePing = o->get_optional(1, 16);
            m.keepaliveTimeout = o->get_optional(2, 16);
        }
        else if (!o)
        {
            const Option *p = options.get_ptr("ping");
            const Option *pr = options.get_ptr("ping-restart");
            if (p && pr)
            {
                m.keepalivePing = p->get_optional(1, 16);
                m.keepaliveTimeout = pr->get_optional(1, 16);
            }
        }
        o = options.get_ptr("reneg-sec");
        if (o)
            m.renegSec = o->get_optional(1, 16);
    }

    // routes / DNS
    {
        const OptionList::IndexList *idx = options.get_index_ptr("redirect-gateway");
        if (idx && !idx->empty())
        {
            m.hasRedirectGateway = true;
            for (auto i : *idx)
            {
                const Option &o = options[i];
                for (size_t k = 1; k < o.size(); ++k)
                    detail::add_unique(m.redirectGatewayFlags, o.ref(k));
            }
        }
        m.routeNopull = options.exists("route-nopull");
        m.blockIpv6 = options.exists("block-ipv6");

        idx = options.get_index_ptr("route");
        if (idx)
        {
            for (auto i : *idx)
            {
                const Option &o = options[i];
                Route r;
                r.network = o.get_optional(1, 64);
                if (r.network.empty())
                    continue;
                r.netmask = o.get_optional(2, 64);
                r.gateway = o.get_optional(3, 64);
                r.metric = o.get_optional(4, 16);
                m.routes.push_back(std::move(r));
            }
        }

        idx = options.get_index_ptr("dhcp-option");
        if (idx)
        {
            for (auto i : *idx)
            {
                const Option &o = options[i];
                DhcpOption d;
                d.type = o.get_optional(1, 64);
                if (d.type.empty())
                    continue;
                d.value = o.get_optional(2, 256);
                m.dhcpOptions.push_back(std::move(d));
            }
        }
    }

    // passthrough + diagnostics
    //
    // An option is "consumed" (absent from `extra`) only when its value was
    // actually captured into the model. Inline blocks (<ca> etc.) whose
    // content is not inline PEM stay in `extra` so nothing is lost — they
    // must be resolved by merge_profile() beforehand.
    {
        const bool keepalive_from_ping_pingrestart =
            !m.keepaliveTimeout.empty()
            && !options.exists("keepalive");

        for (const auto &o : options)
        {
            const std::string &name = o.ref(0);
            if (o.size() == 0 || name.empty())
                continue;
            const bool block = is_inline_content(o, 1);

            // AS metadata options ("PROFILE", "HOST_LIST", ...) derive from
            // comments and are dropped on rebuild
            if (o.meta() && !block)
                continue;

            bool consumed = false;
            if (block)
            {
                consumed = (name == "auth-user-pass" && m.hasAuthUserPass)
                    || (!m.tlsType.empty() && name == m.tlsType)
                    || (name == "ca" && !m.ca.empty())
                    || (name == "cert" && !m.cert.empty())
                    || (name == "key" && !m.key.empty())
                    || (name == "crl-verify" && !m.crl.empty())
                    || (name == "extra-certs" && !m.extraCerts.empty());
            }
            else
            {
                consumed = name == "remote" || name == "port" || name == "proto"
                    || name == "remote-random" || name == "server-poll-timeout"
                    || name == "client" || name == "dev"
                    || name == "key-direction" || name == "remote-cert-tls"
                    || name == "verify-x509-name" || name == "tls-version-min"
                    || name == "cipher" || name == "auth" || name == "compress"
                    || name == "comp-lzo" || name == "reneg-sec"
                    || name == "route-nopull" || name == "block-ipv6"
                    || name == "redirect-gateway" || name == "route"
                    || name == "dhcp-option" || name == "peer-fingerprint"
                    || name == "keepalive"
                    || (name == "auth-user-pass" && m.hasAuthUserPass)
                    || ((name == "ping" || name == "ping-restart")
                        && keepalive_from_ping_pingrestart);
            }
            if (consumed)
                continue;

            m.extra.push_back(detail::render_option(o));

            // diagnostics — mirror cliopt.hpp handle_unused_options()
            if (detail::is_fatal_directive(name))
            {
                detail::add_unique(m.unsupported, name);
                m.extraKinds.push_back("fatal");
            }
            else if (detail::is_warn_directive(name))
            {
                detail::add_unique(m.ignored, name);
                m.extraKinds.push_back("ignored");
            }
            else if (core_ignore_silently().count(name))
            {
                // Preserve these options on rebuild, but report their actual no-op status.
                m.extraKinds.push_back("ignored-silent");
            }
            // Bare auth-user-pass requests credentials from the application.
            // Preserve it without diagnosing an unsupported directive. File
            // references still require merge/extraction and are not exempted.
            else if ((name == "auth-user-pass" && o.size() == 1)
                     || supported_passthrough_directives().count(name))
            {
                // preserved verbatim, no warning
                m.extraKinds.push_back("ok");
            }
            else
            {
                // unrecognized by the core → connect-time fatal
                detail::add_unique(m.unsupported, name);
                m.extraKinds.push_back("unknown");
            }
        }
    }

    return m;
}

// ─── build_profile ─────────────────────────────────────────────────────────

namespace detail {

inline void append_if_set(std::string &out, const std::string &directive, const std::string &value)
{
    if (!value.empty())
    {
        out += directive;
        out += " ";
        out += value;
        out += "\n";
    }
}

inline void append_block(std::string &out, const std::string &name, const std::string &content)
{
    if (content.empty())
        return;
    out += "<" + name + ">\n";
    out += content;
    if (content.back() != '\n')
        out += "\n";
    out += "</" + name + ">\n";
}

} // namespace detail

// Throws std::runtime_error when the model cannot produce a usable profile.
inline std::string build_profile(const Model &m)
{
    if (m.error)
        throw std::runtime_error("model has a parse error: " + m.errorMessage);

    const bool has_connection_block = std::any_of(
        m.extra.begin(), m.extra.end(),
        [](const std::string &e)
        { return e.rfind("<connection>\n", 0) == 0; });

    if (m.remotes.empty() && !has_connection_block)
        throw std::runtime_error("no remote endpoint defined");

    std::string out;
    out += "client\n";
    out += "dev tun\n";

    if (m.remoteRandom)
        out += "remote-random\n";
    for (const auto &r : m.remotes)
    {
        out += "remote " + r.host;
        if (!r.port.empty() || !r.proto.empty())
            out += " " + (r.port.empty() ? std::string("1194") : r.port);
        if (!r.proto.empty())
            out += " " + r.proto;
        out += "\n";
    }
    detail::append_if_set(out, "server-poll-timeout", m.serverPollTimeout);

    if (m.hasAuthUserPass && (!m.authUsername.empty() || !m.authPassword.empty()))
    {
        out += "<auth-user-pass>\n" + m.authUsername + "\n" + m.authPassword + "\n</auth-user-pass>\n";
    }

    detail::append_if_set(out, "cipher", m.cipher);
    detail::append_if_set(out, "auth", m.auth);
    if (m.hasCompress)
    {
        if (m.compress.empty())
            out += "compress\n";
        else if (m.compress == "lzo")
            out += "comp-lzo\n";
        else
            out += "compress " + m.compress + "\n";
    }

    if (!m.keepalivePing.empty() && !m.keepaliveTimeout.empty())
        out += "keepalive " + m.keepalivePing + " " + m.keepaliveTimeout + "\n";
    detail::append_if_set(out, "reneg-sec", m.renegSec);

    detail::append_if_set(out, "key-direction", m.keyDirection);
    if (!m.tlsType.empty() && !m.tlsKey.empty())
        detail::append_block(out, m.tlsType, m.tlsKey);

    detail::append_block(out, "ca", m.ca);
    detail::append_block(out, "cert", m.cert);
    detail::append_block(out, "key", m.key);
    detail::append_block(out, "extra-certs", m.extraCerts);
    detail::append_block(out, "crl-verify", m.crl);
    for (const auto &fp : m.peerFingerprints)
        detail::append_if_set(out, "peer-fingerprint", fp);

    detail::append_if_set(out, "remote-cert-tls", m.remoteCertTls);
    if (!m.verifyX509Name.empty())
    {
        out += "verify-x509-name " + m.verifyX509Name;
        if (!m.verifyX509Mode.empty())
            out += " " + m.verifyX509Mode;
        out += "\n";
    }
    if (!m.tlsVersionMin.empty())
    {
        out += "tls-version-min " + m.tlsVersionMin;
        if (m.tlsVersionMinOrHighest)
            out += " or-highest";
        out += "\n";
    }

    if (m.hasRedirectGateway)
    {
        out += "redirect-gateway";
        for (const auto &f : m.redirectGatewayFlags)
            out += " " + f;
        out += "\n";
    }
    if (m.routeNopull)
        out += "route-nopull\n";
    if (m.blockIpv6)
        out += "block-ipv6\n";
    for (const auto &d : m.dhcpOptions)
    {
        if (!d.type.empty())
        {
            out += "dhcp-option " + d.type;
            if (!d.value.empty())
                out += " " + d.value;
            out += "\n";
        }
    }
    for (const auto &r : m.routes)
    {
        if (r.network.empty())
            continue;
        out += "route " + r.network;
        if (!r.netmask.empty())
            out += " " + r.netmask;
        if (!r.gateway.empty())
            out += " " + r.gateway;
        if (!r.metric.empty())
            out += " " + r.metric;
        out += "\n";
    }

    for (const auto &e : m.extra)
    {
        // ignored-class directives have no effect on the core — drop them
        // instead of writing them back (see extraKinds/"ignored")
        const auto first = e.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        const auto directive = e.substr(first);
        std::string name;
        if (directive.rfind("<", 0) == 0)
        {
            const size_t gt = directive.find('>');
            name = (gt == std::string::npos) ? "" : directive.substr(1, gt - 1);
        }
        else
            name = directive.substr(0, directive.find_first_of(" \t\r\n"));
        if (detail::is_ignored_directive(name))
            continue;
        out += e;
        // Editor-created rows need a separator even when they carry no trailing newline.
        if (e.back() != '\n') out += "\n";
    }

    return out;
}

} // namespace ovpn_profile

#endif // OVPN_PROFILE_MODEL_HPP
