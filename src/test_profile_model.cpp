//    Host-side sanity test for ovpn_profile_model.hpp (parse/build round-trip).
//
//    Build & run (macOS/Linux host, NOT the OHOS target):
//      clang++ -std=c++17 src/test_profile_model.cpp -o /tmp/test_pm \
//        -I deps/openvpn3-release-3.11.7 -I deps/asio/src/asio/include \
//        -I $(brew --prefix openssl)/include \
//        -L $(brew --prefix openssl)/lib -lcrypto -lssl
//      /tmp/test_pm
//
// SPDX-License-Identifier: MPL-2.0

// Guarded so the file compiles both standalone and under scripts/test-host.sh,
// which passes the same -D flags on the command line.
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

#include <client/ovpncli.cpp>
#include "ovpn_profile_model.hpp"
#include "core/profile_credentials.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>

static int g_failures = 0;

#define CHECK(cond)                                                            \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            std::cerr << "FAIL " << __LINE__ << ": " #cond << std::endl;       \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

static std::string make_hex_key()
{
    // OpenVPN static key format: BEGIN/END markers + 16 lines x 32 hex chars
    std::string key = "-----BEGIN OpenVPN Static key V1-----\n";
    for (int line = 0; line < 16; ++line)
    {
        for (int i = 0; i < 32; ++i)
            key += "0123456789abcdef"[(line * 32 + i) % 16];
        key += "\n";
    }
    key += "-----END OpenVPN Static key V1-----\n";
    return key;
}

static std::string full_profile()
{
    return std::string(R"(# a comment
client
dev tun
remote vpn.example.com 1194 udp
remote 10.0.0.1 443 tcp
remote backup.example.com
port 1195
remote-random
server-poll-timeout 15
cipher AES-256-GCM
auth SHA256
compress lz4
keepalive 10 60
reneg-sec 7200
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIICaDCCAdCgAwIBAgIUfakeCA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIICaDCCAdCgAwIBAgIUfakeCERT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqfakeKEY
-----END PRIVATE KEY-----
</key>
<tls-auth>
)" + make_hex_key() + R"(
</tls-auth>
remote-cert-tls client
verify-x509-name vpn.example.com name
tls-version-min 1.2
redirect-gateway def1 block-local
route 10.8.0.0 255.255.255.0
route 192.168.5.0 255.255.255.0 net_gateway
dhcp-option DNS 8.8.8.8
dhcp-option DNS 1.1.1.1
dhcp-option DOMAIN corp.example.com
route-nopull
data-ciphers AES-256-GCM:AES-128-GCM
connect-retry 3
verb 3
some-totally-unknown-directive foo
)");
}

int main()
{
    // Only parsed directive names suppress application authentication. Mentioning
    // an option in comments, a parameter or inline data must not change autologin.
    const std::string authBase = "client\ndev tun\nremote 127.0.0.1 1194 udp\n";
    for (const std::string &mention : {"# auth-user-pass\n", "; auth-user-pass\n", "setenv hint auth-user-pass\n", "<opaque>\nauth-user-pass\n</opaque>\n"}) {
        const auto original = authBase + mention;
        const auto prepared = ovpn_adapter::withApplicationAuth(original, true);
        const auto options = openvpn::OptionList::parse_from_config_static(prepared, nullptr);
        CHECK(options.exists("auth-user-pass"));
        CHECK(options.get_index_ptr("auth-user-pass")->size() == 1);
        CHECK(prepared.compare(0, original.size(), original) == 0);
        CHECK(ovpn_adapter::withApplicationAuth(original, false) == original);
    }
    for (const std::string &directive : {"auth-user-pass\n", "auth-user-pass credentials.txt\n", "<auth-user-pass>\nuser\npassword\n</auth-user-pass>\n"}) {
        const auto original = authBase + directive;
        CHECK(ovpn_adapter::withApplicationAuth(original, true) == original);
    }
    CHECK(!ovpn_profile::parse_profile(ovpn_adapter::withApplicationAuth(authBase + "# auth-user-pass\n", true)).autologin);
    CHECK(ovpn_profile::parse_profile(ovpn_adapter::withApplicationAuth(authBase + "# auth-user-pass\n", false)).autologin);
    const std::string FULL = full_profile();

    // ── 1. parse the full profile ────────────────────────────────────────
    ovpn_profile::Model m = ovpn_profile::parse_profile(FULL);
    CHECK(!m.error);
    if (m.error)
    {
        std::cerr << "parse error: " << m.errorMessage << std::endl;
        return 1;
    }

    CHECK(m.remotes.size() == 3);
    CHECK(m.remotes[0].host == "vpn.example.com" && m.remotes[0].port == "1194"
          && m.remotes[0].proto == "udp");
    CHECK(m.remotes[1].proto == "tcp");
    // top-level `port 1195` applies to the third remote without explicit port
    CHECK(m.remotes[2].port == "1195");
    CHECK(m.remoteRandom);
    CHECK(m.serverPollTimeout == "15");
    CHECK(m.cipher == "AES-256-GCM");
    CHECK(m.auth == "SHA256");
    CHECK(m.hasCompress && m.compress == "lz4");
    CHECK(m.keepalivePing == "10" && m.keepaliveTimeout == "60");
    CHECK(m.renegSec == "7200");
    CHECK(m.keyDirection == "1");
    CHECK(m.tlsType == "tls-auth" && m.tlsKey.find("BEGIN OpenVPN Static key V1") != std::string::npos);
    CHECK(m.ca.find("fakeCA") != std::string::npos);
    CHECK(m.cert.find("fakeCERT") != std::string::npos);
    CHECK(m.key.find("fakeKEY") != std::string::npos);
    CHECK(m.remoteCertTls == "client");
    CHECK(m.verifyX509Name == "vpn.example.com" && m.verifyX509Mode == "name");
    CHECK(m.tlsVersionMin == "1.2" && !m.tlsVersionMinOrHighest);
    CHECK(m.hasRedirectGateway);
    CHECK(m.redirectGatewayFlags.size() == 2);
    CHECK(m.routeNopull);
    CHECK(m.routes.size() == 2);
    CHECK(m.routes[1].gateway == "net_gateway");
    CHECK(m.dhcpOptions.size() == 3);

    // diagnostics: data-ciphers/connect-retry → ignored,
    // unknown directive → unsupported, verb → silent
    bool has_dc = false, has_cr = false, has_unknown = false;
    for (auto &s : m.ignored)
    {
        has_dc |= (s == "data-ciphers");
        has_cr |= (s == "connect-retry");
    }
    CHECK(has_dc && has_cr);
    for (auto &s : m.unsupported)
        has_unknown |= (s == "some-totally-unknown-directive");
    CHECK(has_unknown);
    bool has_verb_unsupported = false, has_verb_ignored = false;
    for (auto &s : m.unsupported)
        has_verb_unsupported |= (s == "verb");
    for (auto &s : m.ignored)
        has_verb_ignored |= (s == "verb");
    CHECK(!has_verb_unsupported && !has_verb_ignored);
    // modeled directives must not appear in diagnostics
    for (auto &s : m.unsupported)
        CHECK(s != "cipher" && s != "tls-auth" && s != "route");

    // ── 2. build → re-parse: modeled fields must survive ─────────────────
    std::string out = ovpn_profile::build_profile(m);
    ovpn_profile::Model m2 = ovpn_profile::parse_profile(out);
    CHECK(!m2.error);
    CHECK(m2.remotes.size() == 3);
    CHECK(m2.remotes[0].host == "vpn.example.com" && m2.remotes[0].port == "1194"
          && m2.remotes[0].proto == "udp");
    CHECK(m2.remotes[2].port == "1195");
    CHECK(m2.remoteRandom && m2.serverPollTimeout == "15");
    CHECK(m2.cipher == "AES-256-GCM" && m2.auth == "SHA256");
    CHECK(m2.hasCompress && m2.compress == "lz4");
    CHECK(m2.keepalivePing == "10" && m2.keepaliveTimeout == "60");
    CHECK(m2.renegSec == "7200");
    CHECK(m2.keyDirection == "1");
    CHECK(m2.tlsType == "tls-auth" && m2.tlsKey == m.tlsKey);
    CHECK(m2.ca == m.ca && m2.cert == m.cert && m2.key == m.key);
    CHECK(m2.remoteCertTls == "client");
    CHECK(m2.verifyX509Name == "vpn.example.com" && m2.verifyX509Mode == "name");
    CHECK(m2.hasRedirectGateway && m2.redirectGatewayFlags.size() == 2);
    CHECK(m2.routeNopull);
    CHECK(m2.routes.size() == 2 && m2.routes[1].gateway == "net_gateway");
    CHECK(m2.dhcpOptions.size() == 3);
    // ignored-class directives (data-ciphers/connect-retry) are dropped on
    // rebuild; supported passthrough (verb) and unknown directives survive
    bool dc_pass = false, unk_pass = false, verb_pass = false;
    for (auto &e : m2.extra)
    {
        dc_pass |= (e.find("data-ciphers") == 0);
        unk_pass |= (e.find("some-totally-unknown-directive") == 0);
        verb_pass |= (e.find("verb 3") == 0);
    }
    CHECK(!dc_pass && unk_pass && verb_pass);
    CHECK(out.find("data-ciphers") == std::string::npos);
    CHECK(out.find("connect-retry") == std::string::npos);
    // extraKinds parallel to extra
    CHECK(m.extraKinds.size() == m.extra.size());
    for (size_t i = 0; i < m.extra.size(); ++i)
    {
        if (m.extra[i].find("some-totally-unknown-directive") == 0)
            CHECK(m.extraKinds[i] == "unknown");
        if (m.extra[i].find("verb 3") == 0)
            CHECK(m.extraKinds[i] == "ignored-silent");
        if (m.extra[i].find("data-ciphers") == 0)
            CHECK(m.extraKinds[i] == "ignored");
    }

    // diagnostics: rebuilt profile no longer contains ignored directives
    CHECK(m2.ignored.empty());
    CHECK(m2.unsupported.size() == 1 && m2.unsupported[0] == "some-totally-unknown-directive");

    // ── 3. idempotency: parse(build(parse(build(x)))) is a fixed point ───
    std::string out2 = ovpn_profile::build_profile(m2);
    ovpn_profile::Model m3 = ovpn_profile::parse_profile(out2);
    CHECK(!m3.error);
    std::string out3 = ovpn_profile::build_profile(m3);
    CHECK(out3 == out2);

    // ── 4. credentials via <auth-user-pass> block ────────────────────────
    const char *USERPASS_PROFILE = R"(
client
dev tun
remote vpn.upass.com 1194 udp
<auth-user-pass>
alice
secret123
</auth-user-pass>
)";
    ovpn_profile::Model mu = ovpn_profile::parse_profile(USERPASS_PROFILE);
    CHECK(!mu.error);
    CHECK(mu.hasAuthUserPass && mu.authUsername == "alice" && mu.authPassword == "secret123");
    std::string uout = ovpn_profile::build_profile(mu);
    ovpn_profile::Model mu2 = ovpn_profile::parse_profile(uout);
    CHECK(!mu2.error && mu2.hasAuthUserPass && mu2.authUsername == "alice"
          && mu2.authPassword == "secret123");

    // Bare user/password auth is supported by the application credential flow.
    // It must survive editing without a fatal warning or embedded credentials.
    const std::string bare_auth_profile =
        "client\ndev tun\nremote vpn.upass.com 1194 udp\nauth-user-pass\n";
    auto bare_auth = ovpn_profile::parse_profile(bare_auth_profile);
    CHECK(!bare_auth.error && !bare_auth.hasAuthUserPass);
    CHECK(bare_auth.unsupported.empty());
    CHECK(bare_auth.extra.size() == 1 && bare_auth.extra[0] == "auth-user-pass\n");
    CHECK(bare_auth.extraKinds.size() == 1 && bare_auth.extraKinds[0] == "ok");
    auto bare_auth_roundtrip = ovpn_profile::parse_profile(ovpn_profile::build_profile(bare_auth));
    CHECK(!bare_auth_roundtrip.error && bare_auth_roundtrip.unsupported.empty());
    CHECK(bare_auth_roundtrip.extra.size() == 1 && bare_auth_roundtrip.extra[0] == "auth-user-pass\n");

    auto auth_file = ovpn_profile::parse_profile(
        "client\ndev tun\nremote vpn.upass.com 1194 udp\nauth-user-pass /missing/credentials\n");
    CHECK(!auth_file.unsupported.empty());
    CHECK(!auth_file.hasAuthUserPass && auth_file.authUsername.empty());
    CHECK(auth_file.extra.size() == 1 && auth_file.extra[0] == "auth-user-pass /missing/credentials\n");

    // ── 5. file-reference forms ──────────────────────────────────────────
    // `ca /path/to/ca.crt` does not break parsing (SSL load failure is
    // swallowed by the core) and stays in extra so nothing is lost.
    const char *FILEREF_PROFILE = R"(
client
dev tun
remote r.example.com 1194 udp
ca /path/to/ca.crt
)";
    ovpn_profile::Model mf = ovpn_profile::parse_profile(FILEREF_PROFILE);
    CHECK(!mf.error);
    CHECK(mf.ca.empty());
    bool ca_ref = false;
    for (auto &e : mf.extra)
        ca_ref |= (e.find("ca /path/to/ca.crt") == 0);
    CHECK(ca_ref);
    std::string fout = ovpn_profile::build_profile(mf);
    CHECK(fout.find("ca /path/to/ca.crt") != std::string::npos);

    // but a file-referenced tls-auth key fails parsing (same as eval_config)
    // — such profiles must go through OvpnMergeProfile first
    const char *TLSAUTH_FILEREF = R"(
client
dev tun
remote r.example.com 1194 udp
tls-auth /path/to/ta.key 0
)";
    ovpn_profile::Model mf2 = ovpn_profile::parse_profile(TLSAUTH_FILEREF);
    CHECK(mf2.error && mf2.errorMessage.find("static_key_parse_error") != std::string::npos);

    // ── 6. minimal create-from-empty model ───────────────────────────────
    ovpn_profile::Model mm;
    mm.remotes.push_back({"my.vpn.net", "443", "tcp"});
    mm.cipher = "AES-128-GCM";
    std::string mout = ovpn_profile::build_profile(mm);
    CHECK(mout.find("client\ndev tun\nremote my.vpn.net 443 tcp\ncipher AES-128-GCM\n")
          == 0);
    ovpn_profile::Model mm2 = ovpn_profile::parse_profile(mout);
    CHECK(!mm2.error && mm2.remotes.size() == 1 && mm2.cipher == "AES-128-GCM");

    // An explicit transport still needs the positional default port.
    ovpn_profile::Model default_port;
    default_port.remotes.push_back({"my.vpn.net", "", "tcp"});
    const auto default_text = ovpn_profile::build_profile(default_port);
    CHECK(default_text.find("remote my.vpn.net 1194 tcp\n") != std::string::npos);
    const auto default_parsed = ovpn_profile::parse_profile(default_text);
    CHECK(!default_parsed.error && default_parsed.remotes[0].port == "1194" && default_parsed.remotes[0].proto == "tcp");

    default_port.extra = {"tun-mtu 1400", "  connect-retry 2", "verb 3"};
    const auto separated = ovpn_profile::build_profile(default_port);
    CHECK(separated.find("tun-mtu 1400\nverb 3\n") != std::string::npos);
    CHECK(separated.find("connect-retry") == std::string::npos);
    CHECK(!ovpn_profile::parse_profile(separated).error);

    // ── 7. build validation: no remote → throw ───────────────────────────
    try
    {
        ovpn_profile::Model bad;
        ovpn_profile::build_profile(bad);
        CHECK(false && "expected exception");
    }
    catch (const std::exception &e)
    {
        CHECK(std::string(e.what()).find("no remote") != std::string::npos);
    }

    // ── 7b. legacy comp-lzo is preserved verbatim on rebuild ─────────────
    const char *COMPLZO_PROFILE = R"(
client
dev tun
remote lzo.example.com 1194 udp
comp-lzo
)";
    ovpn_profile::Model ml = ovpn_profile::parse_profile(COMPLZO_PROFILE);
    CHECK(!ml.error);
    CHECK(ml.hasCompress && ml.compress == "lzo");
    CHECK(ml.extra.empty()); // comp-lzo 被模型消费，不得同时留在透传区
    std::string lout = ovpn_profile::build_profile(ml);
    CHECK(lout.find("comp-lzo\n") != std::string::npos);
    CHECK(lout.find("compress lzo") == std::string::npos);
    // 恰好一条 comp-lzo（不重复）
    size_t pos = 0; int cnt = 0;
    while ((pos = lout.find("comp-lzo", pos)) != std::string::npos) { cnt++; pos += 8; }
    CHECK(cnt == 1);
    // 现代写法 compress lzo 同样归一为 comp-lzo（老服务器兼容）
    ovpn_profile::Model ml2 = ovpn_profile::parse_profile(
        std::string("client\ndev tun\nremote a.b.c 1194 udp\ncompress lzo\n"));
    CHECK(!ml2.error && ml2.compress == "lzo");
    CHECK(ovpn_profile::build_profile(ml2).find("comp-lzo\n") != std::string::npos);
    // 修改压缩方式后按新指令输出
    ml.compress = "lz4";
    std::string lout2 = ovpn_profile::build_profile(ml);
    CHECK(lout2.find("compress lz4\n") != std::string::npos);

    // ── 8. diagnostics: fatal directives are surfaced ────────────────────
    const char *BAD_PROFILE = R"(
client
dev tun
remote x.example.com 1194 udp
socks-proxy 127.0.0.1 1080
ifconfig 10.1.0.2 255.255.255.0
fragment 1200
)";
    ovpn_profile::Model mb = ovpn_profile::parse_profile(BAD_PROFILE);
    CHECK(!mb.error);
    int fatal_hits = 0;
    for (auto &s : mb.unsupported)
        fatal_hits += (s == "socks-proxy") + (s == "ifconfig") + (s == "fragment");
    CHECK(fatal_hits == 3);

    if (g_failures == 0)
    {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    }
    std::cout << g_failures << " CHECK(s) FAILED" << std::endl;
    return 1;
}
