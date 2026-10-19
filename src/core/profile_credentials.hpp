// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <string>
#include <openvpn/common/options.hpp>

namespace ovpn_adapter {
// Parse directive names: comments, parameters and inline material are not options.
// Never insert application secrets into profile text.
inline std::string withApplicationAuth(std::string profile, bool hasCredentials) {
    if (!hasCredentials) return profile;
    try {
        const auto options = openvpn::OptionList::parse_from_config_static(profile, nullptr);
        if (!options.exists("auth-user-pass")) profile += "\nauth-user-pass\n";
    } catch (...) { /* eval_config reports the original malformed profile. */ }
    return profile;
}
}
