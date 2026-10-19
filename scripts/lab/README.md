# Local OpenVPN interoperability lab (macOS / HarmonyOS API 24)

The application links OpenVPN **3 Core 3.11.7**, a client library. This lab uses
OpenVPN **Community 2.7.7** as its server. The version numbers do not need to match:
[OpenVPN 3's upstream README](https://github.com/OpenVPN/openvpn3#readme) explicitly
states that it implements a client, interoperates with OpenVPN 2.x, and does not
implement a server.

Requirements: Homebrew OpenVPN with `dev-node unix:` support, OpenSSL 3, Python 3,
DevEco Studio at `/Applications/DevEco-Studio.app`, and one connected API 24 device.
The computer and phone must be on the same LAN. The server does not require root
and does not modify the computer's system routing table.

Start the lab with a fresh private temporary directory and the computer's LAN IP:

```sh
python3 scripts/lab/server.py --host 192.168.31.100 --work /tmp/arkovpn-full-lab
```

A new directory receives disposable two-day CA/server/client keys, TLS keys,
profiles, and an authenticated control manifest. Existing directories reuse their
keys so an installed test HAP can reconnect after restarting the lab; use a fresh
directory after certificate expiry. Do not put the directory in Git.

Copy its `manifest.json` to
`ohos/entry/src/ohosTest/resources/rawfile/openvpn-lab.json` (Git-ignored), build the
native library, then build and update **both** the application and ohosTest HAPs.
`scripts/test-device-runtime.sh` performs the normal build/install and seven
lifecycle/storage regressions without clearing application data.

Run interoperability tests using `hdc shell`:

```sh
aa test -b com.arror.ovpn -m entry_test -s unittest OpenHarmonyTestRunner -s lab 1 -s timeout 60000
```

Add `-s class OpenVPNInterop#ipv6_tunnel` to select one case. The IPv6 case probes
both IPv4 and IPv6 TCP data. Add `-s stress 1 -s timeout 300000` to select the
100-connection test. Check the reported `Tests run / Failure / Error / Pass`
counts; `aa test` returning zero alone is insufficient.

The main application is deliberately excluded from the VPN. Data probes open
synthetic HTTP URLs in the phone browser, an application with another UID. The
user-mode server answers TCP and verifies the ACK of the HTTP response with a
fresh random nonce. No public Internet service is used. After the tests,
`python3 scripts/lab/cleanup_browser.py` closes only tabs matching the temporary
lab addresses and nonce format, then returns Home. Do not run another UI command
or start a new probe while that cleanup is running.

Fatal-owner testing is deliberately separate:

```sh
python3 scripts/lab/check_owner_crash.py --work /tmp/arkovpn-full-lab
```

It requires the lab and installed test HAP. The test process establishes a real
connection, completes a data probe, records its PID, extension PID and TUN, then
sends SIGSEGV to itself. The production application has no crash/kill API. The
host requires both old PIDs and `vpn-tun` to disappear, then verifies that a fresh
engine starts idle with resources released and no stale-session notice, before
accepting a new connect intent.
The crash phase's `App died` is expected, not a passing unit-test report.

Stop the server with Ctrl-C. Logs and temporary test credentials remain in the
private work directory for investigation and can be removed afterward. Production
HAPs must not contain `openvpn-lab.json`.

Coverage and remaining boundaries are recorded in
`ohos/docs/refactor-implementation-status.md`. These tests do not establish
compatibility with every OpenVPN configuration or server release.


## Real TOTP authentication

TOTP cases require PyOTP to generate independent client codes; the server-side
RFC 6238 verifier uses only the Python standard library. Install the generator
in a temporary virtual environment and run the server with that interpreter:

```sh
python3 -m venv /tmp/arkovpn-totp-venv
/tmp/arkovpn-totp-venv/bin/pip install pyotp==2.9.0
/tmp/arkovpn-totp-venv/bin/python scripts/lab/test_totp.py
/tmp/arkovpn-totp-venv/bin/python scripts/lab/server.py --host 192.168.31.100 --work /tmp/arkovpn-totp-lab
```

Copy the new manifest and rebuild/install both HAPs as above. Run the ten real
server/device cases:

```sh
aa test -b com.arror.ovpn -m entry_test -s unittest OpenHarmonyTestRunner -s totp 1 -s timeout 60000
```

The cases cover CRV1, SCRV1 and password+OTP with current, wrong and expired codes,
plus accepted-code replay. The normal lab baseline uses a two-second first-packet
wait. The earlier assumption that this timeout explained the authentication
fluctuation was not established by controlled tests; it is not an authentication
processing deadline. A fresh random account and secret are created on each
case activation. The verifier accepts six digits with a 30-second step and one
adjacent step in either direction, consumes each challenge once, and rejects a
previously accepted account/counter. Audit records contain verdicts/counters,
not OTPs, secrets or challenge cookies. This is a disposable verifier, not a
production identity service or a RADIUS deployment.

Run the actual production-screen input flow from the host:

```sh
python3 scripts/lab/check_totp_ui.py --work /tmp/arkovpn-totp-lab
```

The script seeds an isolated temporary profile through ohosTest, then launches
the production EntryAbility and uses HDC UITest to click and type into its real
controls. It checks empty-input submission, wrong-code rejection, correct-code
retry with tunnel traffic, real elapsed-time expiry beyond the tolerance window,
retry, and cancellation. Fixture cleanup verifies that the OTP was not persisted,
removes only its own profile and restores the previously selected profile. A
cleanup failure is reported as a failure. Local screenshots and verdict-only
results are stored in `<work>/ui-results`; no layout containing input text is kept.
The script must not run concurrently with another UI automation or probe cleanup.

The host vectors cover all SHA-1/SHA-256/SHA-512 examples and 64-bit timestamps in
[RFC 6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
[PyOTP](https://pyauth.github.io/pyotp/) supplies the independent generator.


## Handshake investigation

The earlier inference that a two-second timeout explained the TOTP fluctuation
was not confirmed. The baseline is restored to two seconds. This option only
controls the wait before the first server packet, not authentication processing.
The original cause remains open; see `ohos/docs/handshake-investigation.md`.

```sh
hdc shell aa test -b com.arror.ovpn -m entry_test -s unittest OpenHarmonyTestRunner -s handshake 1 -s timeout 180000
python3 scripts/lab/check_totp_ui.py --work /tmp/arkovpn-totp-lab --poll 2 --output compare-poll2
python3 scripts/lab/check_totp_ui.py --work /tmp/arkovpn-totp-lab --poll 15 --output compare-poll15
```

The diagnostic suite contains 13 cases: an unavailable loopback UDP endpoint;
three immediate-expiry attempts per timeout; elapsed expiry with phone HTTP
polling; elapsed expiry without phone HTTP polling; and a three-second server
authentication delay. Phone polling warms the link and is not an idle-network
control. The quiet cases use the server's one-shot remaining-duration value,
so phone clock skew cannot cause an early submission.

`--handshake-only` selects the shorter production-screen rejection flow.
`--output` names a private subdirectory under the lab work directory. Each run
captures fixed-label Core events, UI actions, server audit verdicts and server
UDP header metadata. Failure cleanup stops the connection before ending the
process so final transmit/receive and error counters are preserved. It never
keeps the entered OTP, raw Core messages, or raw UI layouts.

Adding `--udp-trace` when starting `server.py` inserts a disposable user-mode
UDP relay for the UI fixture. It records direction, size, opcode and timing,
not packet bodies. It does not change the client's published address/port, but
does change the server's internal receive path; it is not a substitute for
capturing a failure on the original direct path. All relay sockets/processes
are stopped with the active fixture.

## 真实压缩下行回归

现代 OpenVPN 2.7 会将 `allow-compression yes` 降为 asym，普通连通测试不能证明解压能力。压缩专项使用固定版本的独立 OpenVPN 2.6.14 测试服务端：

```sh
python3 scripts/lab/build_compression_server.py --work /tmp/arkovpn-compression-server
python3 scripts/lab/server.py --host <本机局域网地址> --work /tmp/arkovpn-compression-lab --compression-server /tmp/arkovpn-compression-server/openvpn-2.6.14/src/openvpn/openvpn
```

构建器校验归档 SHA256；只增加 macOS 无权限 socketpair TUN 适配，不修改上游压缩、TLS 或数据通道。该 GPL 服务端及 LZO 只运行在测试机器，不链接进 HarmonyOS 应用。

将临时 manifest 用于测试资源并构建 test HAP 后，用 `-s lab 1 -s compression 1` 运行压缩专项。测试后恢复原始测试资源，不把临时密钥或 token 入库。包含 LZO、LZ4 和 LZ4-v2 三项：服务端真实压缩大于 512 字节的 IP/TCP 数据，手机的外部浏览器通过应用 VPN 接收并 ACK；控制端要求日志中实际出现压缩缩小的记录，否则测试失败。每个 `.compression-proof.json` 记录压缩前后长度及 ACK 关联 nonce。

Host 正常回归使用独立工具预生成的真实压缩向量，**不链接 LZO**，覆盖 LZO/LZO-swap/LZ4/LZ4-v2、非对称上行、截断流和解压溢出。可选 `scripts/generate-compression-vectors.py` 仅重新生成测试数据时使用本机 Homebrew 的 LZO/LZ4；这不是生产或日常回归的依赖。
