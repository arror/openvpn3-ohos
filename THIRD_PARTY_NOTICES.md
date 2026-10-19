# 第三方组件与分发声明

## 本项目与许可选择

原生仓原创代码以 MPL-2.0 提供，全文见 `LICENSE`，覆盖范围见 `LICENSE_SCOPE.md`。独立 ArkTS 应用文件遵循应用仓声明，不因为链接 MPL 核心就自动开源；包含 MPL 代码的新文件和对 MPL 文件的修改仍受 MPL 约束。

OpenVPN 3 Core 3.11.7 上游提供 `MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception`；本应用选择 MPL-2.0，保留上游原始文件头及版权声明。

## 应用中的组件

| 组件 | 版本 | 本次使用许可 | 形式 |
|---|---|---|---|
| ArkOvpn 原生核心 | API v2 | MPL-2.0 | 运行时、NAPI、移植代码 |
| OpenVPN 3 Core | 3.11.7 | MPL-2.0 | 编译进 libovpn.so，包含内置 LZO 解压器 |
| OpenSSL | 3.5.0 | Apache-2.0 | 静态库；配置编译，未修改上游源码 |
| LZ4 | 1.10.0 | BSD-2-Clause | 静态库 |
| Asio | 1.24.0 | BSL-1.0 | 头文件 |
| LLVM libc++ 运行时 | 随 HarmonyOS SDK | Apache-2.0 WITH LLVM-exception | 静态 C++ 运行时及头文件 |

版权及许可全文见 `LICENSES/` 和应用内“开源许可”。组件数据以 `legal/components.json` 为准，通过 `scripts/sync-legal.py` 同步到应用离线资源。第三方文件各自保留原始声明，不重新许可为 MPL。

## LZO 接收兼容

正式构建不下载、编译或链接外部 `liblzo2`，也不定义 `HAVE_LZO`。客户端使用 OpenVPN Core 的 MPL 内置 `CompressLZOAsym`，保持 `compressionMode="asym"`：可解压接收的 LZO 数据，不主动压缩上行。

历史上链接列表存在未引用的 `liblzo2.a`，现已移除。外部 LZO 2.10 的许可是 **GPL-2.0-or-later**。是否开启实际压缩，不决定链接进产物的 GPL 库是否产生许可义务；MPL/GPL 的组合也不能笼统称为必然不兼容，须按所选版本、MPL §3.3 和各组件条款分析。本项目不通过纳入该库来实现兼容。

Host 固定向量和独立临时服务端的压缩测试可能使用外部 LZO/OpenVPN 2.x 生成压缩数据。它们只运行在测试端，不链接到 libovpn.so，也不随应用分发；保留其原许可，不把测试依赖写成产品依赖。独立测试服务端 OpenVPN 2.6.14 为 GPL-2.0-only，LZO 2.10 为 GPL-2.0-or-later，GPL v2 全文另见 `LICENSES/GPL-2.0-test-tools.txt`；该许可文件不表示应用包含 GPL LZO。

## 对应源码与获取方式

MPL §3.1–3.4 要求接收者可获取受覆盖源码（包括修改），知晓许可并保留声明；不是只公开上游网址或只提供二进制。建议每个应用版本保留固定的原生源码 tag、源码归档、上游版本和修改、构建说明与产物对应记录。独立应用无需因此全部公开。

指定源码仓库：**https://github.com/arror/openvpn3-ohos**。本地公开源码位于维护者指定的独立仓库，实际对外分发时需确保该地址提供对应版本的源码。联系：hallo.maqiang@icloud.com。添加许可证与配置地址不代表源码已经推送或可公开获取。

## 商标

OpenVPN 是 OpenVPN Inc. 的商标。本应用为独立实现，与 OpenVPN Inc. 无隶属或背书关系；开源许可不授予商标使用权。

## 官方依据

- OpenVPN 3.11.7：https://github.com/OpenVPN/openvpn3/blob/release/3.11.7/LICENSE.md
- MPL 原文：https://www.mozilla.org/en-US/MPL/2.0/
- MPL FAQ（文件边界及二次许可）：https://www.mozilla.org/en-US/MPL/2.0/FAQ/
- LLVM 许可：https://llvm.org/LICENSE.txt

此文件记录工程中的许可选择与提供方式，不代替具体分发场景的法律判断。
