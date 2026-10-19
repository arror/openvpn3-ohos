//    OpenVPN 3 for HarmonyOS - Exclude-route emulation
//
//    【备选方案，当前未启用】RouteInfo.isExcludedRoute（API 20+）已提供
//    原生排除路由（napi_init.cpp 直接使用）。本文件保留给运行在 API<20
//    系统上的场景：HarmonyOS vpnExtension.RouteInfo 只有"包含"方向的路由时，
//    服务器推送 net_gateway / bypass 类排除路由，复用 core 的
//    IP::AddressSpaceSplitter + core emulate() 相同的判定算法，把
//    include ∪ exclude 地址空间切成非重叠小块，剔除被排除部分后作为
//    包含路由安装——与 Android <13 的 EmulateExcludeRoute 同一算法。
//
//    纯函数、无 NAPI 依赖 → 可 host 测试（test_route_emulate.cpp）。
//
// SPDX-License-Identifier: MPL-2.0

#ifndef OVPN_ROUTE_EMULATE_HPP
#define OVPN_ROUTE_EMULATE_HPP

#include <string>
#include <vector>

#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/addr/addrspacesplit.hpp>

namespace ovpn_route_emulate {

/** 一条待安装的包含路由（establish 时转换为 HarmonyOS RouteInfo） */
struct EmulatedRoute
{
    std::string addr;
    int prefix_len;
    bool ipv6;
};

/**
 * 计算排除路由生效后的应安装路由集（补集模拟）。
 *
 * @param include  收集到的包含路由（tun_builder_add_route 的结果）；
 *                 redirect-gateway 时需由调用方加入 0.0.0.0/0（::/0）
 * @param exclude  收集到的排除路由（tun_builder_exclude_route 的结果）
 * @param vermask  参与计算的 IP 版本（IP::Addr::V4_MASK | V6_MASK）
 * @return         应安装的非重叠路由集；exclude 为空时返回空
 *                 （调用方此时走 def1 原路径，零行为变化）
 */
inline std::vector<EmulatedRoute> emulate_exclude_routes(
    const openvpn::IP::RouteList &include,
    const openvpn::IP::RouteList &exclude,
    const openvpn::IP::Addr::VersionMask vermask)
{
    using namespace openvpn;
    std::vector<EmulatedRoute> out;
    if (exclude.empty())
        return out;

    IP::RouteList rl;
    rl.reserve(include.size() + exclude.size());
    rl.insert(rl.end(), include.begin(), include.end());
    rl.insert(rl.end(), exclude.begin(), exclude.end());

    // 与 core EmulateExcludeRouteImpl::emulate 相同：
    // 把 include ∪ exclude 切成非重叠小块，逐块取最长匹配的 include，
    // 若某排除路由更具体则该块不安装
    for (const auto &r : IP::AddressSpaceSplitter(rl, vermask))
    {
        const IP::Route *best = nullptr;
        for (const auto &inc : include)
        {
            if (inc.contains(r))
            {
                if (!best || inc.prefix_len > best->prefix_len)
                    best = &inc;
            }
        }
        if (!best)
            continue; // 无 include 覆盖 → 不安装
        bool excluded = false;
        for (const auto &exc : exclude)
        {
            if (exc.contains(r) && exc.prefix_len > best->prefix_len)
            {
                excluded = true;
                break;
            }
        }
        if (!excluded)
            out.push_back({r.addr.to_string(), static_cast<int>(r.prefix_len),
                           r.addr.version() == IP::Addr::V6});
    }
    return out;
}

} // namespace ovpn_route_emulate

#endif // OVPN_ROUTE_EMULATE_HPP
