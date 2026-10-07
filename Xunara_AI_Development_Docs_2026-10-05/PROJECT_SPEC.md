# Xunara / 玄序 — Project Development Specification

## 1. 项目定位

Xunara（玄序）不是简单的 Headscale + WebUI，也不是 MirageServer 的重新包装。

目标是构建长期可扩展的 **Tailscale-compatible Control Plane / Digital Network Control Plane**：

> Identity + Network + Service + Application + Data Control Plane

核心原则：

1. 官方 Tailscale 客户端可以直接连接 Xunara。
2. Tailscale/Headscale 协议兼容性优先于平台功能。
3. Human Identity、Machine Identity、Service Identity 必须分离。
4. WebUI、Native Client、Zero Trust、SD-WAN、Remote、File Transfer 等能力建立在 Core 之上，而不是侵入 TS2021/Noise。
5. 持续跟进 Tailscale 官方与 Headscale upstream。
6. MirageServer 只作为功能与工程参考，不作为协议标准。

## 2. 官方客户端兼容

```text
Official Tailscale Client
        │
        ▼
Tailscale Compatibility Core
        │
        ▼
Tailnet State
   ┌────┴────┐
   │         │
 WebUI    Xunara Native Client
```

目标支持：

```bash
tailscale up --login-server=https://login.example.com
tailscale status
tailscale ping <node>
tailscale netcheck
tailscale set
tailscale down
```

不能为了 WebUI、Native Client、Funnel、第三方登录等功能随意修改 TS2021、Noise、MapRequest、NodeKey 等核心协议。

## 3. 协议边界

Compatibility Core 优先保持 upstream 行为：

```text
/key
/ts2021
/machine/register
/machine/map
/machine/set-dns
/machine/feature/query
```

平台能力使用：

```text
/api/v1/*
/api/v2/*
/api/platform/*
```

Native Client 使用独立协议，不侵入 TS2021。

## 4. 参考优先级

协议兼容性：

```text
Tailscale upstream
      ↓
Headscale upstream
      ↓
Xunara implementation
      ↓
MirageServer
```

产品功能：

```text
Xunara specification
      ↓
MirageServer
      ↓
Tailscale
      ↓
Headscale
```

Identity：

```text
MirageServer
Dex / go-oidc / oauth2 / WebAuthn
      ↓
Xunara Identity
```

MirageServer 必须经过安全审查后吸收，不能直接复制其缓存、Cookie 和身份模型。

## 5. 总体架构

```text
                         Xunara
                           │
             ┌─────────────┴─────────────┐
             │                           │
       Compatibility Core           Platform Core
             │                           │
       ┌─────┼─────┐             ┌───────┼────────┐
       │     │     │             │       │        │
     Noise  Map  Register      Identity Policy  Services
       │     │     │             │       │        │
       └─────┼─────┘             └───────┼────────┘
             │                           │
             └─────────────┬─────────────┘
                           │
                     Tailnet State
```

## 6. Identity 五层

```text
Human User
  ↓
External Identity
  ↓
Organization
  ↓
Device
  ↓
Machine Identity
```

另有 Service Identity。

## 7. Human Authentication

支持：

```text
Password
OIDC
OAuth2
WebAuthn
Passkey
QR Login
Device Code
External Identity Broker
```

接口：

```go
type IdentityProvider interface {
    ID() string
    Begin(context.Context, *AuthTransaction) (*AuthorizationRequest, error)
    Callback(context.Context, *AuthTransaction, *CallbackRequest) (*IdentityResult, error)
}
```

## 8. AuthTransaction

```go
type AuthTransaction struct {
    ID
    Provider
    State
    Nonce
    PKCE
    RedirectURI
    CreatedAt
    ExpiresAt
    BrowserSessionID
    RequestedAction
    MachineLoginID
}
```

要求：

- State 不可预测
- Nonce 必须验证
- PKCE 优先 S256
- 有过期时间
- 一次性消费
- 与 Browser Session 绑定
- 与 Machine Login 分离
- Redirect 必须 allowlist

## 9. External Identity

唯一键：

```text
(provider_id, subject)
```

不是 Email。

```sql
CREATE TABLE external_identities (
    id UUID PRIMARY KEY,
    provider_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id UUID NOT NULL,
    email TEXT,
    display_name TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE(provider_id, subject)
);
```

## 10. Session

```go
type Session struct {
    ID
    UserID
    OrganizationID
    AuthMethod
    CreatedAt
    ExpiresAt
    RevokedAt
    SecurityContext
}
```

不要依赖 server-local cache 作为长期 Session。

## 11. Device Authorization

```go
type DeviceAuthorization struct {
    ID
    MachineKey
    NodeKey
    UserID
    OrganizationID
    RequestedAt
    ExpiresAt
    ApprovedAt
    ApprovedBy
    State
    ClientMetadata
}
```

流程：

```text
Tailscale Client
      ↓
Machine Registration
      ↓
Device Authorization
      ↓
Browser Login
      ↓
User Approval
      ↓
Machine Authorized
```

## 12. Machine Identity

至少包含：

```text
MachineKey
NodeKey
Tenant / Organization
```

推荐：

```text
MachineKey
    ↓
candidate machines
    ↓
exact NodeKey
    ↓
Tenant boundary
    ↓
Node
```

即：

```text
MachineKey ∩ NodeKey ∩ Tenant
```

而不是简单：

```sql
machine_key = ? OR node_key = ?
```

## 13. Provider Adapter

```text
Identity
  ↓
Provider Registry
  ├── GoogleOIDC
  ├── MicrosoftOIDC
  ├── GitHubOIDC
  ├── GiteaOIDC
  ├── AppleOIDC
  ├── GenericOIDC
  ├── WeChat
  └── ExternalIdentityBroker
```

```go
type IdentityResult struct {
    Provider    string
    Subject     string
    Email       string
    DisplayName string
    Claims      map[string]any
}
```

## 14. OIDC 安全

必须验证：

```text
issuer
audience
signature
nonce
state
PKCE
exp
iat
redirect_uri
```

同时考虑：

- JWKS rotation
- clock skew
- authorization code replay
- state replay
- account linking
- tenant mapping

## 15. MirageServer 第三方登录

参考：

- `mirage-008/MirageServer`
- `MirageNetwork/MirageServer`

相关能力：

```text
Dex / OIDC
OAuth2
GitHub
Gitea
Microsoft
Google
Apple
Ali
WeChat Scan
Aggregator
WebAuthn
```

参考登录链：

```text
Browser
  ↓
/login
  ↓
stateCodeCache
  ↓
mirage-authstate2
  ↓
Dex / Aggregator / WXScan
  ↓
/a/oauth_response
  ↓
Identity
  ↓
User
  ↓
controlCode
  ↓
Web Session
```

值得学习的是：

```text
OAuth transaction ≠ Web session
```

Xunara 正式拆成：

```text
AuthTransaction
Session
DeviceAuthorization
```

不直接复制：

```text
stateCodeCache
controlCodeCache
mirage-authstate2
miragecontrol
Email identity
server-local session cache
```

## 16. External Identity Broker

Mirage Aggregator 在 Xunara 中统一抽象为：

```text
External Identity Broker
```

可以接：

```text
Dex
Keycloak
Authentik
Zitadel
Auth0
Cloudflare Access
Enterprise IdP
```

## 17. Xunara Trust

```text
Xunara Trust
│
├── Human Identity
│   ├── Local Account
│   ├── OIDC
│   ├── OAuth2
│   ├── WebAuthn
│   ├── Passkey
│   └── External Identity
│
├── Machine Identity
│   ├── MachineKey
│   ├── NodeKey
│   ├── Device Certificate
│   └── Key Rotation
│
├── Device Trust
│   ├── Device Approval
│   ├── Device Posture
│   ├── Device Revocation
│   └── Device Enrollment
│
├── Organization Identity
│   ├── Tenant
│   ├── Groups
│   ├── Roles
│   └── External Directory
│
└── Cryptographic Trust
    ├── PKI
    ├── CA
    ├── Certificates
    ├── Tailnet Lock
    └── Key Rotation
```

## 18. 推荐目录

```text
project/
├── cmd/
├── control/
│   ├── noise/
│   ├── register/
│   ├── poll/
│   ├── mapper/
│   ├── state/
│   ├── acl/
│   ├── dns/
│   ├── routes/
│   └── derp/
├── platform/
│   ├── organization/
│   ├── tenant/
│   ├── user/
│   ├── role/
│   ├── device/
│   ├── sharing/
│   ├── invitation/
│   ├── audit/
│   ├── credentials/
│   └── billing/
├── services/
│   ├── serve/
│   ├── funnel/
│   ├── ssh/
│   ├── files/
│   └── discovery/
├── client/
│   ├── protocol/
│   ├── daemon/
│   ├── cli/
│   ├── remote/
│   └── mesh/
├── api/
│   ├── v1/
│   ├── v2/
│   └── platform/
└── web/
```

## 19. 产品体系

| 产品 | 中文 | 英文 | 定位 |
|---|---|---|---|
| Xunara Core | 玄核 | Core | Control Plane |
| Xunara Control | 玄序 | Control | 控制面/API |
| Xunara Path | 玄途 | Path | 官方兼容客户端 |
| Xunara Agent | 玄使 | Agent | 自研客户端 |
| Xunara Veil | 玄幕 | Veil | Relay / DERP |
| Xunara Gate | 玄门 | Gate | Gateway |
| Xunara Atlas | 玄图 | Atlas | Service Discovery |
| Xunara Warden | 玄卫 | Warden | ACL / Zero Trust |
| Xunara Trust | 玄信 | Trust | Identity / PKI |
| Xunara Reach | 玄触 | Reach | Remote |
| Xunara Flux | 玄流 | Flux | File/Data Transfer |
| Xunara Realm | 玄域 | Realm | SD-WAN |
| Xunara Horizon | 玄穹 | Horizon | Exit / Egress |
| Xunara Beacon | 玄灯 | Beacon | Discovery |
| Xunara Loom | 玄织 | Loom | Automation |
| Xunara Pulse | 玄脉 | Pulse | Telemetry |
| Xunara Chronicle | 玄录 | Chronicle | Audit |
| Xunara Observatory | 玄鉴 | Observatory | Monitoring |
| Xunara Bastion | 玄垒 | Bastion | Edge Gateway |
| Xunara Forge | 玄铸 | Forge | Provisioning |

## 20. Web Console

P0：

- Machines
- Users
- DNS
- ACL / Grants
- Routes
- Exit Nodes
- Auth Keys

P1：

- Device/User Approval
- Sharing
- Audit Logs
- DERP Console
- OAuth/API Keys
- Organizations

P2：

- SSH Console
- Funnel / Serve
- Flow Logs
- Tailnet Lock
- Security Center

P3：

- Native Client
- Remote
- File Transfer
- Service Discovery
- Mesh Extensions

## 21. 最终认证链路

```text
Human Authentication
        ↓
Session / Authorization
        ↓
Device Approval
        ↓
Machine Identity
        ↓
Noise
        ↓
Node Identity
        ↓
Policy Engine
        ↓
Network / Service / Application / Data
```

核心定位：

> Identity + Network + Service + Application + Data Control Plane

## 22. Xunara Atlas — 服务发现（v1）

目标：尾网内的节点能把自己提供的服务（名称、协议、端口）发布到控制面，
其它节点与管理员能发现它；**访问控制仍由既有 ACL / grants 决定**——发现
不等于授权。

边界（v1 明确不做，避免被误当成代理层）：

- 不做代理、转发、VIP、负载均衡、健康检查与故障转移；
- 不新增官方客户端内层端点、不改 TS2021 / Noise / MapRequest / MapResponse
  的结构（AGENTS §4）；官方客户端经 MagicDNS 解析服务名后按既有 ACL 连接；
- 不做跨组织发现：服务在组织内可见（AGENTS §12）；
- 不把服务名当作身份：service ≠ user ≠ machine ≠ node（AGENTS §5）。

### 22.1 模型

```text
Service = (node_id, name, protocol, port, metadata?)
```

- `name`：DNS label（1–63 字节，`[a-z0-9-]`，首尾非 `-`），组织内唯一。
- `protocol`：`tcp` 或 `udp`。
- `port`：1–65535。
- `metadata`：可选 `map<string,string>`，供人/自动化读的说明字段（版本、区域
  等）；不承载 secret（AGENTS §8），审计与日志不写其值。

### 22.2 单一写入者与生命周期

- 只有节点自己可以写：经原生客户端协议 `/api/agent/v1/services`（agent token
  + machine key/node key 复述，与 `/heartbeat` 同一身份规则）。
- 发布是**整批替换**（声明式、幂等）：请求体列出该节点当前的全部服务；
  空数组表示撤销全部服务。
- 管理面永远只读（HTTP v2 / gRPC / Console / CLI），与设备姿态属性同一模式
  （AGENTS §10 的边界：节点行为数据由节点负责，管理员只观察）。
- 删除节点 → 服务级联删除；节点过期不自动删除服务（管理员仍能看到"过期
  节点持有某服务名"，便于排障；过期节点不参与 netmap）。

### 22.3 命名与 DNS

- 启用 `Domain` 时，每个服务在 MagicDNS 中产生 `<name>.<domain>.` 的 A/AAAA
  记录，指向发布节点的地址（经既有 `ExtraRecords` 机制）。
- 名字冲突 fail-closed：与任何节点 FQDN、既有 DNS 记录或其它节点的服务名
  冲突时，整个发布请求失败（409），不做静默覆盖。
- 关闭 `Domain` 时服务仍可发布与查询，只是没有 DNS 名称。

### 22.4 限制（fail-closed，整批原子）

| 项 | 上限 |
|---|---|
| 每节点服务数 | 32 |
| 组织内服务总数 | 512（每条服务都会变成每个 netmap 的 DNS 记录） |
| name | 63 字节，DNS label |
| port | 1–65535 |
| metadata 项数 | 16 |
| metadata 键 | ≤64 字节，可打印 ASCII 无空格 |
| metadata 值 | ≤256 字节，无控制字符 |
| metadata 总编码 | 2 KiB |
| 单次发布服务数 | 32 |

任一项非法 → 整批 400，不部分应用；服务名回显前净化。

### 22.5 管理面（只读）

```text
HTTP   GET  /api/v2/services             # read scope，cursor 分页，node/name 过滤
gRPC   PlatformService.ListServices      # 同规则、同值
CLI    xunara services list|show         # 直接读状态目录
Console  Machines 页 Services 计数 / Services 页
```

### 22.6 审计

```text
node.services_updated   # target=节点，detail=服务名列表（含协议/端口），无 metadata 值
```

### 22.7 后续（不在 v1）

- 按 ACL/grants 的可见性（当前与 MagicDNS 节点名一样全组织可见）；
- 服务就绪/健康状态与自动摘除；
- 跨组织服务共享（Sharing）；
- 与 `svc:`（Tailscale Services VIP）互通——需要上游控制面语义，不猜 API。
