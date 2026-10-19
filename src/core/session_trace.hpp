// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <string>
#include <hilog/log.h>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Metadata only: never forward raw Core text, event info, profiles or credentials.
static thread_local std::string coreTraceAttempt;
static thread_local int coreTraceSocket = -1;
static void CoreTrace(const char *stage) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x0750, "OVPN_TRACE",
        "mono=%{public}lld attempt=%{public}s stage=%{public}s",
        static_cast<long long>(ms), coreTraceAttempt.c_str(), stage);
}
static void TraceSocketEndpoint() {
    sockaddr_in local{}, peer{}; socklen_t localSize = sizeof(local), peerSize = sizeof(peer);
    if (getsockname(coreTraceSocket, reinterpret_cast<sockaddr *>(&local), &localSize) != 0 ||
        getpeername(coreTraceSocket, reinterpret_cast<sockaddr *>(&peer), &peerSize) != 0 ||
        local.sin_family != AF_INET || peer.sin_family != AF_INET) return;
    char localIp[INET_ADDRSTRLEN]{}, peerIp[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &local.sin_addr, localIp, sizeof(localIp));
    inet_ntop(AF_INET, &peer.sin_addr, peerIp, sizeof(peerIp));
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x0750, "OVPN_TRACE",
        "attempt=%{public}s local=%{public}s:%{public}u peer=%{public}s:%{public}u",
        coreTraceAttempt.c_str(), localIp, ntohs(local.sin_port), peerIp, ntohs(peer.sin_port));
}
static void SafeCoreLog(const std::string &msg) {
    if (msg.rfind("UDP send exception:", 0) == 0 || msg.rfind("UDP recv error:", 0) == 0) {
        if (msg.find("Permission denied") != std::string::npos) CoreTrace("UDP_PERMISSION_DENIED");
        else if (msg.find("Network is unreachable") != std::string::npos) CoreTrace("UDP_NETWORK_UNREACHABLE");
        else if (msg.find("No route to host") != std::string::npos) CoreTrace("UDP_HOST_UNREACHABLE");
        else if (msg.find("Bad file descriptor") != std::string::npos) CoreTrace("UDP_BAD_FD");
        else if (msg.find("Connection refused") != std::string::npos) CoreTrace("UDP_CONNECTION_REFUSED");
        else CoreTrace("UDP_IO_ERROR");
        return;
    }
    // Only fixed labels leave this classifier. Do not log msg or any substring.
    if (msg.rfind("Server poll timeout, trying next remote entry...", 0) == 0) CoreTrace("SERVER_POLL_TIMEOUT");
    else if (msg.rfind("Contacting ", 0) == 0) CoreTrace("TRANSPORT_READY");
    else if (msg.rfind("Connecting to ", 0) == 0) { CoreTrace("SOCKET_CONNECTED"); TraceSocketEndpoint(); }
    else if (msg.rfind("SSL Handshake:", 0) == 0) CoreTrace("TLS_ESTABLISHED");
    else if (msg.rfind("Sending PUSH_REQUEST to server...", 0) == 0) CoreTrace("PUSH_REQUEST");
    else if (msg.rfind("Session invalidated:", 0) == 0) CoreTrace("SESSION_INVALIDATED");
}
struct CoreTraceScope {
    explicit CoreTraceScope(const std::string &attempt) { coreTraceAttempt = attempt; CoreTrace("WORKER_START"); }
    ~CoreTraceScope() { CoreTrace("WORKER_EXIT"); coreTraceAttempt.clear(); coreTraceSocket = -1; }
};
