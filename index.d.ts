// SPDX-License-Identifier: MPL-2.0
/** OpenVPN runtime API v2: admission receipts and authoritative Native snapshots. */
import { vpnExtension } from "@kit.NetworkKit";

/** Offline batch import. Input bytes are copied before asynchronous processing. No legacy provider is loaded. */
export interface OvpnCertificateInput {
  data: ArrayBuffer;
  password: string;
  passwordProvided: boolean;
  outputPassword: string;
}
export interface OvpnImportedCertificate {
  id: string; publicKeyId: string; name: string; issuer: string;
  validFrom: string; validTo: string; algorithm: string; pem: string;
  ca: boolean; expired: boolean; clientUsage: boolean; selfSigned: boolean; fileIndex: number; fileIndexes: number[]; issuerIds: string[];
}
export interface OvpnImportedPrivateKey {
  id: string; algorithm: string; pem: string; encrypted: boolean; fileIndex: number; fileIndexes: number[];
}
export interface OvpnCertificateImportResult {
  errorCode: string; fileIndex: number; unverifiedIntegrity: boolean;
  certificates: OvpnImportedCertificate[]; keys: OvpnImportedPrivateKey[];
}
export const OvpnImportCertificates: (files: OvpnCertificateInput[]) => Promise<OvpnCertificateImportResult>;
/** Independent 256-bit private DRBG password; throws when secure randomness is unavailable. Never log or display. */
export const OvpnGeneratePrivateKeyPassword: () => string;

/** VPN 事件 */
export interface OvpnEvent {
  /** 事件名称: "RESOLVE" | "WAIT" | "CONNECTING" | "CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "EXIT" | ... */
  name: string;
  /** 附加信息 */
  info: string;
  /** 是否为错误事件 */
  error: boolean;
}

/** 连接信息（CONNECTED 后才有值） */
export interface OvpnConnectionInfo {
  /** 是否已定义（已连接） */
  defined: boolean;
  /** 用户名 */
  user: string;
  /** 服务器域名 */
  serverHost: string;
  /** 服务器端口 */
  serverPort: string;
  /** 协议 (tcp/udp) */
  serverProto: string;
  /** 服务器 IP（解析后） */
  serverIp: string;
  /** VPN IPv4 地址 */
  vpnIp4: string;
  /** VPN IPv6 地址 */
  vpnIp6: string;
  /** VPN MTU */
  vpnMtu: string;
  /** IPv4 网关 */
  gw4: string;
  /** IPv6 网关 */
  gw6: string;
  /** 客户端真实 IP */
  clientIp: string;
  /** TUN 接口名 */
  tunName: string;
}

/** 流量统计 */
export interface OvpnStats {
  /** Plaintext TUN counters: In is received from VPN, Out is sent into VPN. */
  tunBytesIn: number; tunBytesOut: number; tunPacketsIn: number; tunPacketsOut: number;
  /** 接收字节数 */
  bytesIn: number;
  /** 发送字节数 */
  bytesOut: number;
  /** 接收数据包数 */
  packetsIn: number;
  /** 发送数据包数 */
  packetsOut: number;
  /** 下行速率 (bytes/s) */
  rateIn: number;
  /** 上行速率 (bytes/s) */
  rateOut: number;
  /** 连接持续时间（秒），未连接时为 0 */
  connectedDuration: number;
  /** 连接信息，未连接时 defined=false */
  connectionInfo: OvpnConnectionInfo;
}

// ─── Connect Options ──────────────────────────────────────

export type OvpnPhase = 'initializing' | 'idle' | 'preparing' | 'connecting' | 'awaitingCredentials' | 'connected' | 'reconnecting' | 'stopping' | 'faulted';
export interface OvpnCleanupStatus { workerExited: boolean; tunReleased: boolean; bindingReleased: boolean; pendingSettled: boolean; }
export interface OvpnChallengeView {
  challengeId: string; prompt: string; echo: boolean;
  kind: string; originAttemptId: string; connectionEpoch: number; deadline: number;
}
export interface OvpnSnapshot {
  engineInstanceId: string; version: number; appliedCommandSeq: number; connectionEpoch: number;
  phase: OvpnPhase; sessionId: string; attemptId: string; profileId: string; profileRevision: string;
  baselineKnown: boolean; acceptingCommands: boolean; targetSessionId: string; resourcesReleased: boolean; cleanup: OvpnCleanupStatus;
  connectionInfo: OvpnConnectionInfo; lastError: string; challenge: OvpnChallengeView | null;
}
export interface OvpnCommandReceipt { commandId: string; targetSessionId: string; status: string; acceptedSeq: number; }
export interface OvpnConnectRequest {
  requestId: string; profileId: string; profileRevision: string; profileText: string;
  username: string; password: string; privateKeyPassword: string;
  isIPv6Accepted: boolean; enableNonPreferredDCAlgorithms: boolean;
}
export interface OvpnStopRequest { requestId: string; sessionId?: string; }
export interface OvpnCredentialResponse { sessionId: string; challengeId: string; response: string; }
export interface OvpnTunRequest { engineInstanceId: string; sessionId: string; attemptId: string; tunId: string; config?: vpnExtension.VpnConfig; }
export interface OvpnTunProvider {
  prepare(request: OvpnTunRequest): Promise<void>;
  create(request: OvpnTunRequest): Promise<number>;
  destroy(request: OvpnTunRequest): Promise<void>;
  release(request: OvpnTunRequest): Promise<void>;
}
export interface OvpnObserver { onStateChange(snapshot: OvpnSnapshot): void; onStats(stats: OvpnRuntimeStats): void; }
export interface OvpnRuntimeStats extends OvpnStats { valid: boolean; engineInstanceId: string; connectionEpoch: number; sessionId: string; attemptId: string; sequence: number; }
export interface OvpnCapabilities { apiVersion: number; coreVersion: string; buildId: string; externalPki: boolean; dco: boolean; systemProxy: boolean; encryptedDns: boolean; }
export function OvpnConnect(request: OvpnConnectRequest): OvpnCommandReceipt;
export function OvpnDisconnect(request: OvpnStopRequest): OvpnCommandReceipt;
/** Close admission, stop and release all resources, then remove provider/observer. */
export function OvpnShutdown(request: OvpnStopRequest): Promise<void>;
export function OvpnGetState(): OvpnSnapshot;
export function OvpnGetStats(): OvpnRuntimeStats;
export interface OvpnRuntimeDiagnostics { engineInstanceId: string; fdCount: number; threadCount: number; pendingTunOperations: number; trackedAttempts: number; }
export function OvpnGetDiagnostics(): OvpnRuntimeDiagnostics;
export function OvpnGetCapabilities(): OvpnCapabilities;
export function OvpnGetCommandOutcome(commandId: string): OvpnCommandReceipt;
export function OvpnSetObserver(observer: OvpnObserver | null): void;
export function OvpnSetTunProvider(provider: OvpnTunProvider, options?: { requireReconciliation: boolean }): void;
export function OvpnNotifyTunEvent(report: { sessionId: string }): void;
export function OvpnRetryCleanup(): void;

// ─── Config Validation ──────────────────────────────────────

/** 配置文件元数据 */
export interface OvpnConfigMeta {
  /** 配置文件名 */
  profileName: string;
  /** 友好显示名 */
  friendlyName: string;
  /** 服务器地址 */
  remoteHost: string;
  /** 服务器端口 */
  remotePort: string;
  /** 协议 (tcp/udp) */
  remoteProto: string;
  /** 是否免密登录 */
  autologin: boolean;
  /** 是否使用外部 PKI */
  externalPki: boolean;
  /** 是否需要私钥密码 */
  privateKeyPasswordRequired: boolean;
  /** 是否允许保存密码 */
  allowPasswordSave: boolean;
}

/**
 * 验证配置文件并返回元数据（同步）。
 * 不建立连接，仅解析配置内容。
 *
 * @param config .ovpn 配置文件完整内容
 * @returns 配置元数据
 * @throws 配置无效时抛出异常，错误信息在 Error.message 中
 */
export function OvpnEvalConfig(config: string): OvpnConfigMeta;
/** Validate on a Native worker; does not start a VPN process. */
export function OvpnEvalProfile(config: string): Promise<OvpnConfigMeta>;

// ─── Visual Editor API ─────────────────────────────────────────────────────
//
// profile 文本是唯一事实源：OvpnParseProfile 抽取结构化模型（未识别的指令
// 原样保留在 extra 数组），OvpnBuildProfile 将模型重序列化为 .ovpn 文本。
// 编辑器只应展示/修改模型化字段；extra 透传内容不做解释。

/** remote 指令（连接端点） */
export interface OvpnProfileRemote {
  /** 服务器地址（域名或 IP） */
  host: string;
  /** 端口，缺省时 core 使用 1194 */
  port: string;
  /** 协议：'' (adaptive) | udp | udp4 | udp6 | tcp | tcp4 | tcp6 | tcp-client */
  proto: string;
}

/** route 指令 */
export interface OvpnProfileRoute {
  network: string;
  /** 掩码，'' = 缺省 255.255.255.255 */
  netmask: string;
  /** 网关，'' = vpn_gateway；可为 net_gateway 等关键字 */
  gateway: string;
  metric: string;
}

/** dhcp-option 指令（DNS / DNS6 / DOMAIN / DOMAIN-SEARCH / ...） */
export interface OvpnProfileDhcpOption {
  type: string;
  value: string;
}

/** profile 结构化模型 */
export interface OvpnProfileModel {
  /** 解析是否失败（正常返回时为 false；失败时直接抛异常） */
  error: boolean;
  errorMessage: string;

  // ── 元信息（只读） ──
  profileName: string;
  friendlyName: string;
  /** profile 锁定的用户名（'' 表示任意） */
  userlockedUsername: string;
  /** static-challenge 文本（'' 表示无） */
  staticChallenge: string;
  /** challenge 应答是否应回显 */
  staticChallengeEcho: boolean;
  /** 免密型（无 auth-user-pass） */
  autologin: boolean;
  externalPki: boolean;
  /** profile 内嵌加密私钥 */
  privateKeyPasswordRequired: boolean;
  allowPasswordSave: boolean;
  /** CA PEM 原文（'' 表示无，可能是 peer-fingerprint 模式） */
  vpnCa: string;

  // ── 连接 ──
  remotes: OvpnProfileRemote[];
  remoteRandom: boolean;
  /** '' = 未设置 */
  serverPollTimeout: string;

  // ── 内嵌凭据（<auth-user-pass> 块） ──
  hasAuthUserPass: boolean;
  authUsername: string;
  authPassword: string;

  // ── TLS 控制信道 ──
  /** '' = 未设置 | '0' | '1' */
  keyDirection: string;
  /** '' = 无 | 'tls-auth' | 'tls-crypt' | 'tls-crypt-v2'（三者互斥） */
  tlsType: string;
  /** 密钥块 PEM 内容（与 tlsType 对应；'' 表示文件引用形式，未内联） */
  tlsKey: string;

  // ── PKI（PEM 块内容，'' = 不存在；文件引用形式保留在 extra） ──
  ca: string;
  cert: string;
  key: string;
  crl: string;
  extraCerts: string;
  /** peer-fingerprint 列表（SHA256） */
  peerFingerprints: string[];
  /** '' = 未设置 | 'client' | 'server' */
  remoteCertTls: string;
  verifyX509Name: string;
  /** '' = 默认(subject) */
  verifyX509Mode: string;
  /** '' = 未设置 | '1.0'..'1.3'（注意：本项目 OpenSSL 裁剪后建议 ≥1.2） */
  tlsVersionMin: string;
  tlsVersionMinOrHighest: boolean;

  // ── 数据通道 ──
  /** '' = 未设置（NCP 协商）；可选值见 docs/openvpn3-config-options.md §1.5 */
  cipher: string;
  /** CBC 模式的 HMAC 摘要，'' = 未设置（默认 SHA1） */
  auth: string;
  hasCompress: boolean;
  /** '' = 裸 compress 指令；'' 与 hasCompress=false 都表示不压缩 */
  compress: string;

  // ── 会话 ──
  keepalivePing: string;
  keepaliveTimeout: string;
  /** '' = 未设置（默认 3600） */
  renegSec: string;

  // ── 路由 / DNS ──
  hasRedirectGateway: boolean;
  /** flags: local | autolocal | def1 | bypass-dhcp | bypass-dns | block-local */
  redirectGatewayFlags: string[];
  routeNopull: boolean;
  blockIpv6: boolean;
  routes: OvpnProfileRoute[];
  dhcpOptions: OvpnProfileDhcpOption[];

  /** 未建模指令的透传原文（单行指令或 <块>），构建时原样回写 */
  extra: string[];
  /** 与 extra 平行的分类："ok"（内核生效）| "ignored"（内核忽略，构建时不写入）| "fatal"（内核不支持）| "unknown"（未知指令）| "ignored-silent"（静默忽略但保留原文） */
  extraKinds: string[];
  /** 连接时会致命报错的指令名（含无法识别的指令） */
  unsupported: string[];
  /** 连接时会忽略并告警的指令名 */
  ignored: string[];
}

/** merge 结果 */
export interface OvpnMergeResult {
  /** ProfileMerge 状态字符串；合并成功时 profileContent 非空 */
  status: string;
  basename: string;
  /** 合并后的单文件 profile 内容（失败时为空） */
  profileContent: string;
  errorText: string;
}

/**
 * 解析 .ovpn 配置为结构化模型（同步，纯解析，无网络 IO）。
 * 未识别的指令不会报错，而是保留在 extra 中并在 unsupported/ignored 里给出诊断。
 *
 * @param config .ovpn 配置文件完整内容（含外链引用时请先 OvpnMergeProfile）
 * @returns 配置模型
 * @throws 配置无效时抛出异常
 */
export function OvpnParseProfile(config: string): OvpnProfileModel;

/**
 * 将模型重序列化为 .ovpn 文本（同步）。
 * extra 透传内容原样回写；构建后内部会重新 parse 校验。
 *
 * @param model 配置模型（通常来自 OvpnParseProfile，经表单修改）
 * @returns .ovpn 文本
 * @throws 缺少 remote 等致命问题时抛出异常
 */
export function OvpnBuildProfile(model: OvpnProfileModel): string;

/**
 * 合并配置中的外部文件引用为单文件 profile（同步）。
 * 导入 .ovpn 的第一步：若配置使用 `<ca> file` / `<<ca>` 语法，
 * 必须先用本函数内联，再交给 OvpnParseProfile / OvpnConnect。
 *
 * @param config .ovpn 配置文件完整内容
 * @returns 合并结果（profileContent 为合并后内容）
 */
export function OvpnMergeProfile(config: string): OvpnMergeResult;

/** 连接期凭据更新（用于动态挑战 / 认证失败重试） */
export interface OvpnCreds {
  username?: string;
  password?: string;
  privateKeyPassword?: string;
  /** static-challenge 应答 */
  challengeResponse?: string;
  /** 动态挑战 cookie（"DYNAMIC_CHALLENGE" 事件的 info） */
  dynamicChallengeCookie?: string;
}

/**
 * 受理当前 challenge 的临时应答。必须使用快照中的 sessionId/challengeId。
 * 旧 worker/TUN 清理完成后，同一 session 的下一 attempt 在 connect 前提供凭据。
 * 不持久化应答，不向 ArkTS 暴露服务器 challenge cookie。
 */
export function OvpnProvideCreds(response: OvpnCredentialResponse): void;

/** 动态挑战解析结果 */
export interface OvpnDynamicChallenge {
  /** 服务器给出的验证问题文本 */
  challenge: string;
  /** 应答是否应回显 */
  echo: boolean;
  /** 是否必须应答 */
  responseRequired: boolean;
  /** 状态 ID（原样回传即可） */
  stateID: string;
}

/**
 * 解析动态挑战 cookie（同步）。
 * @param cookie "DYNAMIC_CHALLENGE" 事件 info 字段的内容
 * @throws cookie 格式错误时抛出异常
 */
export function OvpnParseDynamicChallenge(cookie: string): OvpnDynamicChallenge;
