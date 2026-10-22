# OpenVPN 3 for HarmonyOS

基于 OpenVPN 3 Core **3.11.7** 的 HarmonyOS 原生核心，通过 NAPI 向 ArkTS 提供连接、认证、配置解析和流量统计能力。

源码地址：https://github.com/arror/openvpn3-ohos

本仓库包含原生运行时、NAPI、构建与测试脚本、接口声明，以及获取固定版本上游源码的脚本。ArkTS 应用界面、账号、用户配置、测试密钥和预编译二进制不在本仓库中。本项目不提供 VPN 服务、账号或服务器。

## 运行架构

- **应用主进程**运行 OpenVPN Core、连接状态机及数据通道；以 `OvpnGetState()` / Observer 快照为权威状态。
- **VPN 扩展进程**只管理虚拟网卡及 fd，通过调用者提供的 `OvpnTunProvider` 和系统 IPC 交付 fd。
- 每次新建 fd 均须退出旧扩展并启动新扩展。调用系统 stop 后保留约 500ms 收敛窗口，并确认旧进程退出。
- 应用需要通过 `blockedApplications` 将自身加入 VPN 黑名单，让 Core 的底层 socket 走物理网络；不要在这个架构中依赖扩展进程的 `protect()` 保护主进程 socket。
- 清理独立于普通资源队列，重试真正发起新一轮释放；旧代次回调不能影响新清理。不能确认资源已退役时阻止下一次连接。

详见 [运行时与接入](docs/runtime-and-integration.md)、[API 声明](index.d.ts)。

## 依赖与许可

| 组件 | 版本 | 本仓库使用方式 |
|---|---|---|
| OpenVPN 3 Core | 3.11.7 | 构建时获取固定归档，选择 MPL-2.0 分支 |
| OpenSSL | 3.5.0 | 裁剪后静态链接，Apache-2.0 |
| LZ4 | 1.10.0 | 静态链接，BSD-2-Clause |
| Asio | 1.24.0 | 头文件，BSL-1.0 |
| LLVM libc++ | HarmonyOS SDK 提供 | 静态运行时，Apache-2.0 WITH LLVM-exception |

**产品不依赖外部 LZO 库。** LZO 下行解压使用 OpenVPN Core 的 MPL 内置实现，发送保持非对称模式（不主动压缩）。`HAVE_LZO` 受编译保护，构建后还会检查完整符号表。LZ4 同样保持仅接收压缩的策略。

原生原创代码采用 **MPL-2.0**，全文及范围见 [LICENSE](LICENSE)、[LICENSE_SCOPE.md](LICENSE_SCOPE.md)。上游源码保留各自原许可和版权行，未被重新许可。第三方清单见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，对应全文在 `LICENSES/`。独立应用文件不因调用本核心而自动采用 MPL。

## 目录

```text
src/                    NAPI、Core 适配、状态机及 C++ 回归
index.d.ts              API v2 的完整 ArkTS 类型声明
scripts/                依赖获取、交叉编译、Host 测试与许可检查
scripts/lab/            独立临时服务端；仅测试环境使用
third_party/            精确依赖来源、归档 SHA256 与上游许可声明
legal/                  组件许可清单及应用源码入口配置
LICENSES/               随项目提供的许可证全文
docs/                   架构、接入及源码提供说明
```

## 构建原生库

已验证环境：macOS arm64、DevEco Studio 的 HarmonyOS Native SDK、CMake、make。

首次获取及构建依赖：

```bash
bash scripts/00-fetch-deps.sh
source scripts/env.sh
bash scripts/04-build-all-deps.sh
bash scripts/build.sh
```

`env.sh` 根据脚本位置定位仓库，不要求特定目录。可通过 `TOOL_HOME`、`OHOS_NDK_HOME` 指定 SDK，通过 `PREFIX` 指定已有交叉编译依赖目录。Core 默认下载 OpenVPN 3.11.7 的固定发布归档并校验 SHA256，源码解压到被 Git 忽略的 `deps/`；也可通过 `OPENVPN3_SRC` 显式指定本地源码。使用其他上游版本须同时指定其归档 SHA256。

产物为 `build_napi/libovpn.so`。没有应用目录时只构建原生库，不会创建伪应用工程。接入外部应用可运行：

```bash
OHOS_APP_DIR=/absolute/path/to/app bash scripts/build.sh
```

仅复制原生库至 `entry/libs/arm64-v8a/`，以及 `index.d.ts` 至 `entry/src/main/ets/libovpn/`。原生库与接口声明必须一起更新。应用仍需自行实现 VPN 扩展与 TunProvider，不能仅复制库就完成系统 VPN 集成。

## 证书文件转换

`OvpnImportCertificates(files)` 在原生后台线程中批量识别并转换证书材料，和 VPN 会话生命周期分离。支持 X.509 PEM/DER、PKCS#7 PEM/DER、现代 PKCS#12/PFX、RSA PKCS#1 / EC SEC1 / PKCS#8 私钥与混合 PEM。格式由内容决定，返回证书指纹、CA 属性、公钥匹配标识、经过签名校验的签发关系和规范化 PEM。

加密私钥保持保护；PFX 提取的私钥输出为加密 PKCS#8，空密码包需要提供 `outputPassword`。输入需区分未提供密码与明确提供空密码。解锁失败、格式/算法不支持与资源超限分别返回错误码；整批失败时不返回部分材料。单文件最多 8 MiB、每批最多 8 个文件/16 MiB。转换模块不加载 legacy provider，不增加旧版 RC2 PFX 的额外兼容，也不改变 VPN 的 TLS 设置。证书包中的 CA 只是候选材料，应用必须让用户确认服务器信任。

类型和错误结果见 [index.d.ts](index.d.ts)，解析与密码保护回归见 [src/test_certificate_import.cpp](src/test_certificate_import.cpp)。可运行测试程序的 `--fixtures /temporary/directory` 生成测试专用材料；不要使用这些临时证书提供实际服务。应用应在主编辑页保存时将配置和私钥密码作为同一版本提交，密码不得写入配置或日志。

## Host 回归

```bash
brew install openssl@3 lz4 cmake
# Asio 可由 00-fetch-deps.sh 获取；或显式指定 ASIO_INCLUDE_DIR。
bash scripts/test-host.sh
```

包含五组 C++ 回归：配置解析与凭据指令、路由补集、会话状态机及清理恢复、真实压缩数据解压、证书格式识别与转换。生产与普通 Host 回归均不链接 `liblzo2`。

压缩向量由独立 LZO/LZ4 工具生成，固定数据已入库。回归覆盖 LZO、LZO-swap、LZ4、LZ4-v2，逐字节比较解压内容，并检查截断、解压溢出与非对称发送。仅重新生成向量时才需安装测试工具 LZO，见 `scripts/generate-compression-vectors.py`。

可选的 ArkTS 故障注入与资源测试要求外部应用源码和 Node/TypeScript：

```bash
ARKOVPN_APP_ROOT=/absolute/path/to/app NODE_BIN=node bash scripts/test-host.sh
```

未提供应用源码时，这些应用集成测试会明确跳过，不计作已通过。真实服务器、动态密码及真实压缩隧道验证须配合外部应用 test HAP，说明见 [测试实验室](scripts/lab/README.md)。

## 许可资源维护

```bash
python3 scripts/check-licenses.py
python3 scripts/sync-legal.py --app-root /absolute/path/to/app
python3 scripts/sync-legal.py --check --app-root /absolute/path/to/app
```

上述同步工具把组件清单、源码入口和许可证全文写入应用的 `rawfile/licenses/`，供应用离线展示。`legal/source.json` 指向本仓库；实际提供二进制时，应保留与该版本相对应的源码，而非只提供浮动分支。详见 [源码提供说明](docs/source-distribution.md)。

OpenVPN 是 OpenVPN Inc. 的商标；本项目独立维护，与其无隶属或背书关系。

本仓库采用轻量布局，不提交第三方源码树、依赖缓存或构建产物。OpenVPN 3.11.7 的对应上游源码可从 [固定版本归档](https://github.com/OpenVPN/openvpn3/archive/refs/tags/release/3.11.7.tar.gz) 获取；OpenSSL、LZ4、Asio 的获取脚本也校验对应归档 SHA256。来源及 SHA256 见 `third_party/DEPENDENCIES.json`。维护者仍应保持对应源码可获取，必要时提供归档镜像；本地上游修改须另行公开，不能仅引用原始上游。
