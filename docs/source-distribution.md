# 原生源码与许可维护

## 范围

原生仓原创代码采用 MPL-2.0，根目录 `LICENSE` 为完整文本，`LICENSE_SCOPE.md` 定义边界。原生 C++、NAPI、接口声明及自编脚本带 SPDX 头。独立 ArkTS 应用采用独立范围声明；第三方资源和复制的原生接口各保留其许可。无需为了调用 MPL 核心而开放独立的整个应用。

OpenVPN 3 Core 3.11.7 保留原始双许可头，当前选择 MPL-2.0。第三方库不能统一改成 MPL。`legal/components.json` 是实际组件清单，包含 SDK 静态 C++ 运行时；许可全文在 `LICENSES/`。

## 本次交付

- 正式依赖与 Host 回归不再链接外部 liblzo2；编译保护禁止误启用 HAVE_LZO。
- 构建验证未剥离产物的完整符号表：必须有 Core 内置 LZO 解压器，不能有外部 LZO 符号。
- `scripts/check-licenses.py` 检查源文件许可头、产品依赖、应用声明资源的一致性。
- `scripts/sync-legal.py` 将清单、源码信息和许可全文同步到应用离线资源；`--check` 只检查不写入。
- 设置 → 法律信息 → 开源许可，支持逐项查看版权及全文；源代码入口提供原生源码地址和许可信息。

## 源码提供方式

每个实际分发版本保留对应的原生源码与固定版本标识，包含所有 MPL 修改、实际使用的 OpenVPN 上游源码/版本与补丁、接口、构建脚本和依赖信息。保留版权、许可头及第三方文本；不要只留下二进制、浮动分支或上游仓首页。无需提供签名私钥、凭据、用户配置或临时测试密钥。

维护者指定源码仓库为 `https://github.com/arror/openvpn3-ohos`；`legal/source.json` 已使用该确定地址，`placeholder=false`。本次整理本地源码，没有执行推送；对外分发前仍需确保对应源码在指定地址可获取。

## 官方依据

- OpenVPN 3.11.7 许可：https://github.com/OpenVPN/openvpn3/blob/release/3.11.7/LICENSE.md
- MPL §1.10、§3.1–3.4：https://www.mozilla.org/en-US/MPL/2.0/
- MPL FAQ Q8–Q14（源码提供、独立文件和 GPL 组合）：https://www.mozilla.org/en-US/MPL/2.0/FAQ/

GPL LZO 的义务不能用“不开启压缩”规避；MPL 与 GPL 也不是一概不兼容。当前应用通过完全不引入外部 LZO 来维持清晰的产品许可范围。独立测试端使用的 GPL 工具不进入应用产物。

仓库按维护者要求采用轻量布局：不提交第三方源码目录；提供固定上游版本、源码归档链接、SHA256、原始许可文本及全部本地移植源码。OpenVPN 源码归档：https://github.com/OpenVPN/openvpn3/archive/refs/tags/release/3.11.7.tar.gz 。维护者应保持该版本的源码获取方式有效；上游文件如有本地修改，须公开对应修改，而不是只给原版下载地址。
