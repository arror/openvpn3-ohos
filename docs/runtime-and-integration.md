# 运行时与接入

`index.d.ts` 是 API v2 的完整接口定义。应用需要 HarmonyOS 的 NetworkKit、IPCKit 和 Native SDK；本仓库不包含可直接安装的完整应用。

## 接入顺序

1. 在主进程导入 `libovpn.so`，调用 `OvpnGetCapabilities()` 核对 API 与 Core 版本。
2. 注册 `OvpnSetObserver` 与 `OvpnSetTunProvider`。Provider 实现 `prepare/create/destroy/release`，由应用负责 VPN 扩展启动、绑定与 IPC。
3. 用当前 `engineInstanceId` 构造不重复的命令 ID，调用 `OvpnConnect`；返回的是命令受理回执，不代表连接成功。
4. 观察状态快照：`connected` 才表示核心连接完成，资源进程的存在或 VPN 扩展启动不能代表网络已连接。
5. 收到 `awaitingCredentials` 时，按该 session / challenge 身份提供动态验证码、静态挑战或私钥口令；不要把上一次应答带入新挑战。
6. 断开时调用 `OvpnDisconnect`；只有回到 `idle` 且 `resourcesReleased=true`，才允许新连接。`faulted` 需使用真实清理重试，不能仅修改 UI 状态。

## fd 与进程规则

Provider 创建 fd 后交给 Native；fd 转移后不要在 Provider 再次关闭。旧回调返回的迟到 fd 必须关闭。每个新 fd 对应一个全新 VPN 扩展进程。停止不能排在挂起的 start/create/RPC 后；调用系统 stop 后等待约 500ms，并结合死亡通知确认退役。

清理超时不能当作已释放。未结束的启动或停止仍可能影响下一轮进程，必须保留屏障；迟到启动需补偿 stop。释放回调带代次，较早的 ACK 不能结算或放弃较新的释放请求。

## 路由与能力边界

Core 在主进程创建底层 socket，应用在系统 VPN 配置的 `blockedApplications` 中加入自身 bundle。扩展只负责虚拟网卡生命周期，不承担权威连接状态。运行中主进程退出后由系统及扩展 owner 死亡机制释放资源；重启核心为空闲，不恢复旧 connected。

压缩固定为 asym；内置 LZO 和 LZ4 可接收压缩数据，不主动压缩发送。产品无外部 LZO 链接。系统代理、加密 DNS、DCO 和外部 PKI 是否可用应以 `OvpnGetCapabilities()` 返回为准；不能以 OpenVPN 上游存在某选项推断本移植已经实现。

## 主要验证入口

- `scripts/test-host.sh`：四组 C++ 回归，外部应用存在时追加 ArkTS 故障注入。
- `scripts/check-no-external-lzo.py`：对未剥离 `.so` 检查 Core 解压器存在及外部 LZO 缺席。
- `scripts/lab/`：独立服务端，密钥和 manifest 写入调用者指定的临时目录；不属于正式运行依赖。
