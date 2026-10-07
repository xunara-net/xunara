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
