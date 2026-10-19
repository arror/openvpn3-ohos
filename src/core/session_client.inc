// SPDX-License-Identifier: MPL-2.0
// OpenVPN adapter, compiled exactly once with ovpncli.cpp.
#include "profile_credentials.hpp"
class OhosVpnClient : public openvpn::ClientAPI::OpenVPNClient {
    std::shared_ptr<RuntimeWork> work;
    std::shared_ptr<openvpn::Stop> stopSource;
    VpnConfig tun_config;
    NetAddress tun_gw4, tun_gw6;
    bool connected = false;
    std::string terminalCode;
    long long lastIn = 0, lastOut = 0, totalIn = 0, totalOut = 0;
    std::chrono::steady_clock::time_point connectedAt, lastTick;
public:
    OhosVpnClient() = default; // profile-only evaluation has no active runtime
    OhosVpnClient(std::shared_ptr<RuntimeWork> w, std::shared_ptr<openvpn::Stop> stop)
        : work(std::move(w)), stopSource(std::move(stop)) {}
    OvpnConnectionInfo currentConnection() {
        const auto ci = connection_info();
        return {ci.defined, ci.user, ci.serverHost, ci.serverPort, ci.serverProto, ci.serverIp,
            ci.vpnIp4, ci.vpnIp6, ci.vpnMtu, ci.gw4, ci.gw6, ci.clientIp, ci.tunName};
    }
    bool pause_on_connection_timeout() override { return false; }
    openvpn::Stop *get_async_stop() override { return stopSource.get(); }
    void log(const openvpn::ClientAPI::LogInfo &entry) override { SafeCoreLog(entry.text); }
    void event(const openvpn::ClientAPI::Event &e) override {
        if (!work || !g_bridge || g_bridge->closing) return;
        // name comes from Core's fixed event enum; info may contain credentials.
        CoreTrace(e.name.c_str());
        if (e.name == "DYNAMIC_CHALLENGE") {
            openvpn::ClientAPI::DynamicChallenge dc;
            if (openvpn::ClientAPI::OpenVPNClientHelper::parse_dynamic_challenge(e.info, dc)) {
                work->request.cookie = e.info;
                work->request.challengeKind = "dynamic";
                g_bridge->runtime->fact(work, "CHALLENGE", dc.challenge, dc.echo);
            } else terminalCode = "CHALLENGE_INVALID";
            stopSource->stop(); return;
        }
        if (e.name == "CONNECTED") { connected = true; connectedAt = std::chrono::steady_clock::now(); }
        if (e.name == "RECONNECTING" || e.name == "DISCONNECTED") connected = false;
        if (e.name == "CONNECTED" || e.name == "RECONNECTING" || e.name == "DISCONNECTED")
            g_bridge->runtime->fact(work, e.name, "", false, e.name == "CONNECTED" ? currentConnection() : OvpnConnectionInfo{});
        static const std::unordered_set<std::string> fatal = {"AUTH_FAILED", "NEED_CREDS", "CERT_VERIFY_FAIL", "CERT_AUTH_FAIL", "EPKI_ERROR", "TUN_SETUP_FAILED", "TUN_IFACE_CREATE", "TUN_HALT"};
        if (e.fatal || fatal.count(e.name)) {
            if (terminalCode.empty()) terminalCode = e.name;
            g_bridge->runtime->failed(work, terminalCode); stopSource->stop();
        }
    }
    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override {}
    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &r) override { r.error = true; r.errorText = "External PKI unavailable"; }
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &r) override { r.error = true; r.errorText = "External PKI unavailable"; }
    void clock_tick() override {
        if (!work || work->cancelled || !g_bridge || g_bridge->closing) return;
        auto now = std::chrono::steady_clock::now();
        auto ts = transport_stats(); auto tun = tun_stats();
        long long in = ts.bytesIn, out = ts.bytesOut;
        auto di = in >= lastIn ? in - lastIn : in;
        auto dout = out >= lastOut ? out - lastOut : out;
        totalIn += di; totalOut += dout; lastIn = in; lastOut = out;
        StatsData data;
        data.tunBytesIn = tun.bytesIn; data.tunBytesOut = tun.bytesOut;
        data.tunPacketsIn = tun.packetsIn; data.tunPacketsOut = tun.packetsOut;
        data.bytesIn = totalIn; data.bytesOut = totalOut;
        data.packetsIn = ts.packetsIn; data.packetsOut = ts.packetsOut;
        double seconds = lastTick.time_since_epoch().count() ? std::chrono::duration<double>(now - lastTick).count() : 0;
        data.rateIn = connected && seconds > 0 ? di / seconds : 0;
        data.rateOut = connected && seconds > 0 ? dout / seconds : 0; lastTick = now;
        if (connected) {
            data.connectedDuration = std::chrono::duration_cast<std::chrono::seconds>(now - connectedAt).count();
            data.connInfo = currentConnection();
        }
        g_bridge->updateStats(work, data);
    }
    std::string errorCode() const { return terminalCode; }
    int tun_builder_establish() override {
        if (!work || work->cancelled || !g_bridge || g_bridge->closing || !terminalCode.empty()) return -1;
        auto op = std::make_shared<TunOperation>(); op->work = work; op->kind = "create";
        op->tunId = g_bridge->newTunId(work); op->config = tun_config; op->config.isIPv6Accepted = work->request.ipv6;
        return g_bridge->wait(op, true);
    }
    void tun_builder_teardown(bool) override {
        if (!work || !g_bridge || g_bridge->closing) return;
        auto id = g_bridge->currentTunId(work); if (id.empty()) return;
        auto op = std::make_shared<TunOperation>(); op->work = work; op->kind = "destroy"; op->tunId = id;
        g_bridge->wait(op, false);
    }
    bool socket_protect(openvpn_io::detail::socket_type socket, std::string remote, bool ipv6) override {
        coreTraceSocket = socket;
        CoreTrace("SOCKET_PROTECT");
        return true;
    }

    // ─── TUN builder callbacks — collect server-pushed config ──────────
    bool tun_builder_new() override {
        tun_config = VpnConfig{};
        tun_gw4 = {}; tun_gw6 = {};
        return true;
    }

    bool unsupportedBuilderOption(const char *code) { if (terminalCode.empty()) terminalCode = code; return false; }
    bool tun_builder_set_layer(int layer) override { return layer == 3 || unsupportedBuilderOption("TUN_LAYER_UNSUPPORTED"); }

    bool tun_builder_set_remote_address(const std::string &address, bool ipv6) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "tun_builder_set_remote_address: %{public}s", address.c_str());
        return true;
    }

    bool tun_builder_add_address(const std::string &address, int prefix_length,
                                 const std::string &gateway, bool ipv6, bool net30) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "tun_builder_add_address: %{public}s/%{public}d gw=%{public}s",
                     address.c_str(), prefix_length, gateway.c_str());
        tun_config.addresses.push_back({
            .address = {.address = address, .family = ipv6 ? 2 : 1},
            .prefixLength = prefix_length,
        });
        (ipv6 ? tun_gw6 : tun_gw4) = {.address = gateway, .family = ipv6 ? 2 : 1};
        // HarmonyOS does not install the address subnet into the VPN policy
        // table when explicit routes are present. Add its actual prefix (not /24).
        std::array<unsigned char, 16> network{};
        const int width = ipv6 ? 128 : 32;
        if (prefix_length < 0 || prefix_length > width ||
            inet_pton(ipv6 ? AF_INET6 : AF_INET, address.c_str(), network.data()) != 1) return false;
        for (int bit = prefix_length; bit < width; ++bit) network[bit / 8] &= ~(1u << (7 - bit % 8));
        char subnet[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(ipv6 ? AF_INET6 : AF_INET, network.data(), subnet, sizeof(subnet))) return false;
        tun_config.routes.push_back({
            .destination = {.address = {.address = subnet, .family = ipv6 ? 2 : 1}, .prefixLength = prefix_length},
            .gateway = {}, .hasGateway = false, .isDefaultRoute = false,
        });
        if (prefix_length == width && !gateway.empty() && gateway != "0.0.0.0" && gateway != "::") {
            tun_config.routes.push_back({
                .destination = {.address = {.address = gateway, .family = ipv6 ? 2 : 1}, .prefixLength = width},
                .gateway = {}, .hasGateway = false, .isDefaultRoute = false,
            });
        }
        return true;
    }

    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "tun_builder_reroute_gw: ipv4=%{public}d ipv6=%{public}d flags=%{public}u",
                     ipv4, ipv6, flags);
        // def1：两条 /1 路由优先级高于系统默认路由且不依赖 metric（移动端最稳）；
        // bypass/block 类旗标由 core 转为 exclude_route 回调 → 原生排除路由
        if (ipv4) {
            tun_config.isIPv4Accepted = true;
            tun_config.routes.push_back({
                .destination = {.address = {.address = "0.0.0.0", .family = 1}, .prefixLength = 1},
                .gateway = tun_gw4,
                .hasGateway = true,
                .isDefaultRoute = true,
            });
            tun_config.routes.push_back({
                .destination = {.address = {.address = "128.0.0.0", .family = 1}, .prefixLength = 1},
                .gateway = tun_gw4,
                .hasGateway = true,
                .isDefaultRoute = true,
            });
        }
        if (ipv6) {
            tun_config.isIPv6Accepted = true;
            tun_config.routes.push_back({
                .destination = {.address = {.address = "::", .family = 2}, .prefixLength = 1},
                .gateway = tun_gw6,
                .hasGateway = true,
                .isDefaultRoute = true,
            });
            tun_config.routes.push_back({
                .destination = {.address = {.address = "8000::", .family = 2}, .prefixLength = 1},
                .gateway = tun_gw6,
                .hasGateway = true,
                .isDefaultRoute = true,
            });
        }
        return true;
    }

    bool tun_builder_add_route(const std::string &address, int prefix_length, int metric, bool ipv6) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "tun_builder_add_route: %{public}s/%{public}d", address.c_str(), prefix_length);
        tun_config.routes.push_back({
            .destination = {.address = {.address = address, .family = ipv6 ? 2 : 1}, .prefixLength = prefix_length},
            .gateway = ipv6 ? tun_gw6 : tun_gw4,
            .hasGateway = true,
            .isDefaultRoute = false,
        });
        return true;
    }

    // 原生排除路由（RouteInfo.isExcludedRoute，API 20+）：
    // 系统保证这些网段不经过隧道
    bool tun_builder_exclude_route(const std::string &address, int prefix_length, int metric, bool ipv6) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG,
                     "tun_builder_exclude_route: %{public}s/%{public}d",
                     address.c_str(), prefix_length);
        tun_config.routes.push_back({
            .destination = {.address = {.address = address, .family = ipv6 ? 2 : 1}, .prefixLength = prefix_length},
            .gateway = {},
            .hasGateway = false,
            .isDefaultRoute = false,
            .isExcludedRoute = true,
        });
        return true;
    }

    bool tun_builder_set_dns_options(const openvpn::DnsOptions &dns) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "tun_builder_set_dns_options");
        // VpnConfig exposes plain resolver addresses only. Do not silently strip
        // encrypted DNS, split resolver, DNSSEC, or custom-port requirements.
        for (const auto &pair : dns.servers) {
            const auto &server = pair.second;
            if (!server.domains.empty() || server.dnssec == openvpn::DnsServer::Security::Yes ||
                !server.sni.empty() || (server.transport != openvpn::DnsServer::Transport::Unset &&
                server.transport != openvpn::DnsServer::Transport::Plain)) return unsupportedBuilderOption("DNS_OPTIONS_UNSUPPORTED");
            for (const auto &address : server.addresses)
                if (address.port != 0 && address.port != 53) return unsupportedBuilderOption("DNS_OPTIONS_UNSUPPORTED");
        }
        for (const auto &v : dns.search_domains) {
            tun_config.searchDomains.push_back(v.domain);
        }
        for (const auto &pair : dns.servers) {
            for (const auto &v : pair.second.addresses) {
                tun_config.dnsAddresses.push_back(v.address);
            }
        }
        return true;
    }

    bool tun_builder_set_mtu(int mtu) override {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_DOMAIN, LOG_TAG, "tun_builder_set_mtu: %{public}d", mtu);
        tun_config.mtu = mtu;
        return true;
    }

    bool tun_builder_set_session_name(const std::string &name) override { return true; }
    bool tun_builder_set_route_metric_default(int metric) override { return true; }
    bool tun_builder_persist() override { return false; }
    void tun_builder_establish_lite() override {}

    bool tun_builder_add_proxy_bypass(const std::string &bypass_host) override { return unsupportedBuilderOption("SYSTEM_PROXY_UNSUPPORTED"); }
    bool tun_builder_set_proxy_auto_config_url(const std::string &url) override { return unsupportedBuilderOption("SYSTEM_PROXY_UNSUPPORTED"); }
    bool tun_builder_set_proxy_http(const std::string &host, int port) override { return unsupportedBuilderOption("SYSTEM_PROXY_UNSUPPORTED"); }
    bool tun_builder_set_proxy_https(const std::string &host, int port) override { return unsupportedBuilderOption("SYSTEM_PROXY_UNSUPPORTED"); }


};

static std::string RunCoreSession(std::shared_ptr<RuntimeWork> work) {
    if (!g_bridge || g_bridge->closing || work->cancelled) return "";
    CoreTraceScope trace(work->attempt);
    auto stop = std::make_shared<openvpn::Stop>();
    work->installStop([stop] { stop->stop(); });
    OhosVpnClient client(work, stop);
    openvpn::ClientAPI::Config config;
    config.content = ovpn_adapter::withApplicationAuth(work->request.profile,
        !work->request.username.empty() || !work->request.password.empty());
    config.privateKeyPassword = work->request.privateKeyPassword;
    config.enableNonPreferredDCAlgorithms = work->request.legacy;
    config.tunPersist = false; config.clockTickMS = 1000; config.allowLocalLanAccess = true;
    config.compressionMode = "asym";
    config.dhcpSearchDomainsAsSplitDomains = false;
    auto evaluated = client.eval_config(config);
    if (evaluated.error) return "CONFIG_INVALID";
    if (work->cancelled) return "";
    if (evaluated.privateKeyPasswordRequired && work->request.privateKeyPassword.empty()) {
        work->request.challengeKind = "privateKey";
        g_bridge->runtime->fact(work, "CHALLENGE", "请输入私钥密码", false);
        return "";
    }
    if (!evaluated.staticChallenge.empty() && work->request.cookie.empty() && !work->request.responseProvided) {
        work->request.challengeKind = "static";
        g_bridge->runtime->fact(work, "CHALLENGE", evaluated.staticChallenge, evaluated.staticChallengeEcho);
        return "";
    }
    auto prepare = std::make_shared<TunOperation>(); prepare->work = work; prepare->kind = "prepare";
    CoreTrace("PREPARE_START");
    g_bridge->wait(prepare, true);
    CoreTrace("PREPARE_DONE");
    if (work->cancelled || g_bridge->closing) return "";
    if (!prepare->ok) return "TUN_PREPARE_FAILED";
    g_bridge->runtime->fact(work, "PLATFORM_READY");
    openvpn::ClientAPI::ProvideCreds creds;
    creds.username = work->request.username; creds.password = work->request.password;
    creds.response = work->request.response; creds.dynamicChallengeCookie = work->request.cookie;
    auto credentialStatus = client.provide_creds(creds);
    if (credentialStatus.error) return "CREDENTIALS_INVALID";
    g_bridge->runtime->fact(work, "CONNECTING");
    if (work->cancelled) return "";
    CoreTrace(work->request.cookie.empty() ? "CONNECT_INITIAL" : "CONNECT_CHALLENGE_RESPONSE");
    auto result = client.connect(); // exactly one upstream execution; no outer retry loop
    CoreTrace("CONNECT_RETURNED");
    const auto finalStats = client.transport_stats();
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x0750, "OVPN_TRACE",
        "attempt=%{public}s tx=%{public}lld rx=%{public}lld",
        work->attempt.c_str(), static_cast<long long>(finalStats.bytesOut), static_cast<long long>(finalStats.bytesIn));
    for (int i = 0; i < client.stats_n(); ++i) {
        const auto name = client.stats_name(i);
        if (name != "NETWORK_SEND_ERROR" && name != "NETWORK_RECV_ERROR" &&
            name != "UDP_CONNECT_ERROR" && name != "SOCKET_PROTECT_ERROR" &&
            name != "N_RECONNECT" && name != "HANDSHAKE_TIMEOUT") continue;
        const auto value = client.stats_value(i);
        if (value) OH_LOG_Print(LOG_APP, LOG_INFO, 0x0750, "OVPN_TRACE",
            "attempt=%{public}s counter=%{public}s value=%{public}lld", work->attempt.c_str(), name.c_str(), value);
    }
    if (!client.errorCode().empty()) return client.errorCode();
    return result.error ? "CORE_CONNECTION_FAILED" : "";
}
