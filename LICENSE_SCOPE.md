# 许可范围

本原生仓的原创 `src/`、`scripts/`、`index.d.ts`、`CMakeLists.txt` 和相关构建配置以根目录 `LICENSE` 的 MPL-2.0 提供。源文件使用 `SPDX-License-Identifier: MPL-2.0` 标记；第三方文件遵守自身声明，不能替换其版权行和许可证。

`deps/` 中的上游源码分别遵循原许可证。OpenVPN 3 Core 选择 MPL-2.0 分支；其原始双许可声明保持不变。测试工具独立调用的 GPL 程序及库不属于应用依赖，不能拷贝或链接进应用。`scripts/lab/` 的自编工具按文件头许可，上游测试服务端下载到外部临时目录并遵守上游 GPL 许可。

独立的 `ohos/` 是应用仓，未因链接原生核心而自动采用 MPL；其许可范围见应用仓的 `LICENSE_SCOPE.md`。应用仓中的原生接口声明和复制的许可证仍遵循原有开源许可。

分发版本应提供与该版本对应的 MPL 源码，包括修改文件，以及明确的获取方式。源码地址由维护者指定为 https://github.com/arror/openvpn3-ohos。`legal/source.json` 保存该地址；修改后运行 `python3 scripts/sync-legal.py` 同步应用声明。本地准备与实际对外提供源码是不同步骤。
