// SPDX-License-Identifier: MPL-2.0
//    Host-side tests for ovpn_route_emulate.hpp (exclude-route complement).
//
//    Build & run: see test_profile_model.cpp compile line, plus this file.

#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/route.hpp>

#include "ovpn_route_emulate.hpp"

#include <iostream>
#include <set>
#include <string>

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

using namespace openvpn;

static IP::RouteList to_routes(std::vector<std::string> cidrs)
{
    IP::RouteList out;
    for (const auto &c : cidrs)
    {
        const size_t slash = c.find('/');
        const std::string addr = (slash == std::string::npos) ? c : c.substr(0, slash);
        const int prefix = (slash == std::string::npos)
                               ? static_cast<int>(IP::Addr(addr).size())
                               : std::stoi(c.substr(slash + 1));
        out.emplace_back(IP::Addr(addr), prefix);
    }
    return out;
}

// 某安装块是否覆盖给定 /32 地址
static bool covers(const std::vector<ovpn_route_emulate::EmulatedRoute> &installed,
                   const std::string &ip)
{
    const IP::Addr a(ip);
    for (const auto &r : installed)
    {
        IP::Route net(IP::Addr(r.addr), r.prefix_len);
        if (net.contains(IP::Route(a, a.size())))
            return true;
    }
    return false;
}

int main()
{
    const auto V4 = IP::Addr::V4_MASK;

    // ── 1. redirect-gateway + 排除网段：补集覆盖除排除外的一切 ───────────
    {
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"0.0.0.0/0"}), to_routes({"10.99.0.0/16"}), V4);
        CHECK(!installed.empty());
        // 排除网段内不装
        CHECK(!covers(installed, "10.99.0.1"));
        CHECK(!covers(installed, "10.99.255.254"));
        // 排除网段外全装
        CHECK(covers(installed, "10.98.255.254"));
        CHECK(covers(installed, "10.100.0.1"));
        CHECK(covers(installed, "8.8.8.8"));
        CHECK(covers(installed, "192.168.1.1"));
        // 无排除重叠的块保持原有前缀（0.0.0.0/1、128.0.0.0/1 形态附近）
        bool has_wide = false;
        for (const auto &r : installed)
            if (r.prefix_len <= 1)
                has_wide = true;
        CHECK(has_wide);
    }

    // ── 2. 无排除路由：返回空（调用方走 def1 原路径，零行为变化） ────────
    {
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"0.0.0.0/0", "10.1.0.0/21"}), {}, V4);
        CHECK(installed.empty());
    }

    // ── 3. 具体路由内排除更具体子网 ───────────────────────────────────────
    {
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"10.1.0.0/21"}), to_routes({"10.1.2.0/24"}), V4);
        CHECK(!installed.empty());
        CHECK(!covers(installed, "10.1.2.1"));
        CHECK(covers(installed, "10.1.0.1"));
        CHECK(covers(installed, "10.1.1.255"));
        CHECK(covers(installed, "10.1.3.1"));
        // 排除块之外的相邻空间不被 include 覆盖 → 不安装
        CHECK(!covers(installed, "10.2.0.1"));
        CHECK(!covers(installed, "10.0.0.1"));
    }

    // ── 4. 排除路由比 include 更具体（/32 排除） ──────────────────────────
    {
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"0.0.0.0/0", "192.168.75.0/24"}),
            to_routes({"192.168.75.1/32"}), V4);
        CHECK(!covers(installed, "192.168.75.1"));
        CHECK(covers(installed, "192.168.75.2"));
        CHECK(covers(installed, "192.168.75.130"));
        CHECK(covers(installed, "8.8.8.8"));
    }

    // ── 5. include 不覆盖的空间不安装（没有 best include） ────────────────
    {
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"10.1.0.0/21"}), to_routes({"172.16.0.0/12"}), V4);
        // include 只有 10.1/21；172.16/12 与其无重叠 → 不影响安装集
        CHECK(!covers(installed, "172.16.1.1"));
        CHECK(covers(installed, "10.1.0.1"));
    }

    // ── 6. IPv6 排除 ──────────────────────────────────────────────────────
    {
        const auto V6 = IP::Addr::V6_MASK;
        auto installed = ovpn_route_emulate::emulate_exclude_routes(
            to_routes({"::/0"}), to_routes({"fc00::/8"}), V6);
        CHECK(!installed.empty());
        CHECK(!covers(installed, "fc00::1"));
        CHECK(covers(installed, "2001:db8::1"));
    }

    if (g_failures == 0)
    {
        std::cout << "ALL ROUTE EMULATE TESTS PASSED" << std::endl;
        return 0;
    }
    std::cout << g_failures << " CHECK(s) FAILED" << std::endl;
    return 1;
}
