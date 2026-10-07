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
- 重复发布与已存集合相同的集合是 no-op：不写库、不追加审计、不唤醒 netmap
  （顺序无关，比较前做与写入相同的归一化）。客户端因此可以定期重发声明来
  修复丢失的控制面数据，而不产生写入与审计噪音。
- 管理面永远只读（HTTP v2 / gRPC / Console / CLI），与设备姿态属性同一模式
  （AGENTS §10 的边界：节点行为数据由节点负责，管理员只观察）。
- 节点本地的声明文件与运行中的 agent 不做跨进程加锁：`publish`/`clear`
  先经服务端确认，再更新文件；`run` 在下一次刷新重读文件。二者恰好并发的
  窗口（一次请求内）以最后一次写入为准，重跑命令即可收敛。
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
Agent  xunara-agent services publish|list|clear
                                         # 节点自身的声明（唯一写入者）；
                                         # run 定期重读 <state-dir>/services.json 重发
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

## 23. Xunara Atlas — 目录导入（v1，Consul）

目标：节点把本地服务目录里已注册的服务转换成 Atlas 声明并发布，不必手工维护
`services.json`。导入器**在节点侧运行**，因此不破坏 §22.2 的"节点是唯一写入者"
边界：控制面仍然只接受节点自己的声明，也永远拿不到目录凭据（AGENTS §8/§12）。

边界（v1 明确不做）：

- 只读节点本地 Consul agent 的 HTTP API（默认 `http://127.0.0.1:8500`；
  可用 `CONSUL_HTTP_ADDR` / `-consul-addr` 覆盖）。指向远端 agent 等于把
  那台机器的服务声明成本节点的服务，属于误用，文档明示。
- ACL token 只从环境变量 `CONSUL_HTTP_TOKEN` 读取，只出现在
  `X-Consul-Token` 请求头；绝不进 URL query、argv 或日志（AGENTS §8）。
- 只做"目录 → 声明"的单向转换；不做健康过滤、不做反向同步（Atlas 的发布
  不会写回 Consul）、不删除 Consul 中的任何东西。
- Kubernetes 不在 v1：把 Service 映射成"本节点提供"需要 EndpointSlice/Pod
  语义（ClusterIP 不是节点本地事实），先补 spec 再实现。

### 23.1 映射规则（fail-closed）

读取 `GET /v1/agent/services`（响应为 ID → `api.AgentService` 的 JSON 对象，
字段已对照 `hashicorp/consul` 的 `api/agent.go` 核实）。逐条映射：

| Consul | Atlas |
|---|---|
| `Service` | `name`，必须是合法 DNS label；非法不做重命名，跳过并告警 |
| `Tags` 含 `udp` | `protocol=udp`；否则 `tcp` |
| `Ports` 中 `Default=true` 的端口，否则 `Port` | `port`；0 或越界则跳过并告警 |
| `Meta` | `metadata`；不满足 §22.4 任一限制（键/值/条目数/编码大小）则跳过该服务并告警（不截断） |

跳过并告警（绝不猜测）：`Kind != ""`（Connect proxy 与各类 gateway 不是应用
服务）、`SocketPath != ""`（unix socket 不是 tcp/udp 端口）、`PeerName != ""`
（peering 引入的服务不是本节点事实）、`Service` 为空。

同名多注册（Consul 中同一 agent 可以有多个 ID 指向同一 `Service` 名）：
协议与端口一致则去重为一条；不一致视为歧义，**整个名字跳过**并告警。

### 23.2 限额与原子性

- 映射结果超过每节点 32 条 → 导入失败、不发布：发布是整批替换，截断等于把
  多余服务从注册表撤销（§22.2）。
- 发布仍走既有数据面，服务端执行 §22.4 的全部校验与冲突检查（名字冲突、
  组织限额等）；导入失败不改变已经发布的声明——`services.json` 只在服务端
  接受之后才更新。
- 告警只说明跳过了什么，不包含 `Meta` 的值（值可能被当作敏感信息写入日志）。

### 23.3 命令面

```text
xunara-agent services import -from consul [-consul-addr http://127.0.0.1:8500]
                             [-dry-run] [-state-dir d]
```

`-dry-run` 只把声明 JSON 打印到 stdout（可直接交给
`xunara-agent services publish -file`），不需要已注册的 agent；告警始终走
stderr，不进入声明。

## 24. Passkey / WebAuthn（v1）

目标：Human Identity 支持 passkey（WebAuthn）注册与登录。Passkey 只回答
"这是哪个用户"，永不授权机器（AGENTS §5）；ceremony 是独立对象，不复用
OAuth transaction / session / device authorization（AGENTS §10）。

边界（v1 明确不做）：

- 不做账号恢复：passkey 是附加登录方式，忘记 passkey 的用户仍走既有
  OIDC / 本地登录路径；passkey 与机器信任永远无关。
- 不做 attestation 策略（`PreferNoAttestation`）、AAGUID/厂商白名单、
  conditional UI（autofill）；登录页是显式按钮。
- passkey 的注册/删除由用户本人在 Console 完成，v1 没有管理员代操作。
- 登录 begin 端点不额外限速（与登录页同一入口，部署方在反向代理层限速）。

### 24.1 RP 配置（fail-closed）

`identity.NewPasskeyService` 启动时校验，配置错误 = 启动失败：

- `RPID`：裸域（无 scheme/port/path）；必须是域名而不是 IP 地址
  （浏览器拒绝 IP RP ID），`localhost` 允许（loopback 例外）。
- `Origins`：至少一个；必须 https（loopback 可 http）、host 是 RPID 或
  其子域、不得带 path/query/userinfo；内部按 `scheme://host` 规范化比较。
- `DisplayName` 缺省 = RPID；`UserVerification` 缺省 `required`；
  `Timeout` 缺省 60s 且 `Enforce: true`（服务端强制超时）。

未配置 = 功能关闭：`control.Config.Passkeys == nil` 时 passkey 端点返回
404、登录页不渲染按钮。部署侧（cmd/xunarad）在未显式配置时从 `-server-url`
推导 RPID=host、origin=ServerURL 且只接受"能通过 §24.1 校验"的组合，
推导失败只告警并关闭，不阻塞启动；显式配置错误则启动失败。

### 24.2 Ceremony：持久化、单次、浏览器绑定

- `PasskeyCeremony{ID, Kind(register|login), UserID, Session, BrowserSessionHash,
  CreatedAt, ExpiresAt, ConsumedAt}` 存 SQLite（`webauthn_ceremonies`）；
  Session 是 go-webauthn 的挑战/状态 JSON。任何实例都能 finish 别的实例
  开始的 ceremony（AGENTS §9），不依赖 server-local map。
- TTL 5 分钟（`identity.DefaultPasskeyCeremonyTTL`）。begin 生成随机 browser
  secret，库里只存 SHA-256；下发 HttpOnly cookie（`SameSite=Lax`、Path=/、
  https 时 Secure，值 = `ceremonyID.secret`）。
- finish 必须同时满足：cookie 存在且 secret 匹配、ceremony 未过期、未消费、
  kind 匹配；任何一条不满足都返回 4xx 且不区分细节。
- 单次消费在 SQLite 事务里完成（`consumed_at IS NULL AND expires_at > now`
  才更新）：重放与并发双击最多成功一次（AGENTS §7 code/state replay）。
- janitor 周期删除过期 ceremony，过期挑战不无限积累。

### 24.3 凭据

- `Passkey{ID, UserID, Name, CredentialID, Credential, CreatedAt, LastUsedAt}`；
  `CredentialID`（WebAuthn raw ID）全局 UNIQUE；私钥永不离开认证器，库里
  只有公钥与 sign counter。
- 登录是 usernameless（discoverable credential，`residentKey: required`）：
  begin 不带用户名，finish 由 assertion 的 raw ID 查 passkey → 所属 User，
  不经过 Email/NodeKey 匹配（AGENTS §5/§11）。
- 注册仅对已登录用户开放；`excludeCredentials` 防同一认证器重复注册；
  ceremony.UserID 与当前用户不一致按 not found 处理（不泄漏账号存在性）。
- finish 成功后写回 sign counter 与 `LastUsedAt`；计数器回退由 go-webauthn
  判为克隆并拒绝。

### 24.4 端点与审计

登录（公开；绑定靠 ceremony cookie + challenge，不要求 CSRF）：

```text
POST /passkey/login/begin    -> 200 {"options": ...}; Set-Cookie 绑定本浏览器
POST /passkey/login/finish   -> 200 {"redirect": <safe return_to>}; 创建会话
```

注册/管理（Console；session + CSRF header）：

```text
GET  /console/passkeys                列表（名字/创建时间/最后使用）
POST /console/passkeys/begin          {"options": ...} + Set-Cookie
POST /console/passkeys/finish         {"name": ..., "credential": ...}
POST /console/passkeys/{id}/delete    只能删自己的
```

审计：`passkey.registered` / `passkey.deleted`（detail 只记名字，绝不记
credential ID、公钥、challenge、secret）；登录成功写既有 `login.succeeded`
（detail 注明 `method=passkey`）与 `session.created`，失败写 `login.failed`
（detail 是静态原因，不含库错误文本）。

### 24.5 配置接线

- `control.Config.Passkeys *identity.PasskeyConfig`：nil 关闭功能。
- cmd/xunarad：`-passkey`（默认 true）、`-passkey-rpid`、`-passkey-origin`
  （repeatable）、`-passkey-display-name`；Console 导航新增 Passkeys（所有
  角色的用户都管理自己的凭据）。

## 25. Xunara Flux — Agent 文件投递（v1）

目标：让两台运行 `xunara-agent` 的机器之间可以投递文件（Xunara Flux）。
v1 是**存储转发**（控制面中转 + 端到端加密），不是 WireGuard 数据面：

- 只服务原生 Agent 协议（`/api/agent/v1`）。与官方客户端的 Taildrop
  （WireGuard 之上）不互通，也不改变 TS2021/Noise/netmap（AGENTS §4）。
- 控制面只保存**密文**与元数据，看不到文件内容（E2E，§25.4）；收件人必须
  显式接受（accept）才会上传数据，控制面不发起任何"推送"。
- 控制面不做杀毒、不做 DLP、不索引内容；文件名与大小对控制面可见（元数据）。

### 25.1 生命周期与状态机

```text
pending ──accept──▶ accepted ──upload──▶ uploaded ──complete──▶ completed
   │                    │                    │
   ├─deny──▶ denied     ├─fail──▶ failed     ├─fail──▶ failed
   └─cancel(cancel by sender)                  └─expire──▶ expired
```

- `pending`：发送方已报价（名字/大小/SHA-256/收件人）；收件人可见并可
  accept/deny。发送方也可 cancel。
- `accepted`：收件人已接受并附上**本次传输的 X25519 公钥**（§25.4）；发送方
  可以上传密文。
- `uploaded`：密文已落库/落盘；收件人可下载。下载可重试（状态不变），直到
  complete/fail/expire。
- `completed`：收件人已解密并校验 SHA-256；控制面立即删除密文。
- 终态：`completed` / `denied` / `failed` / `cancelled` / `expired`。
- 非法转移一律拒绝（409），不做隐式状态跳转；转移在 store 层用条件 UPDATE
  原子完成（多实例安全）。

### 25.2 数据与限额（fail-closed）

- 元数据：`name`（basename，≤128 runes、可打印、不含路径分隔符；服务端再
  次校验）、`size`（明文字节数）、`sha256`（明文十六进制，64 字符小写）。
- 密文体积上限 = `size + 64` 字节（X25519 公钥 32 + nonce 12 + GCM tag 16 =
  60，留 4 字节余量）。超过即 413；接收方解密后必须重新校验 SHA-256。
- 默认单文件 ≤ 8 MiB（`DefaultFluxMaxSize`，部署可配），报价与上传都强制。
- 活跃（pending/accepted/uploaded）传输：每节点（作为任一角色）≤ 32 条，
  每组织 ≤ 512 条、密文总量 ≤ 1 GiB；超限 429。终态行保留 24h 供双方查询，
  janitor 清理；节点删除级联删除其传输行。
- TTL 默认 1h（可配）：超过后任何非终态 → `expired`，密文删除。
- 解析/校验失败 400；未认证 401；不是本人参与的传输 404（不泄漏存在性）；
  状态冲突 409；文件超过声明大小/限额 413；配额 429。

### 25.3 HTTP 端点（Agent 协议）

认证与 M9 相同（Bearer agent token + machine/node key 复述；POST 走 JSON body，
GET/PUT 走 `X-Xunara-Machine-Key`/`X-Xunara-Node-Key` 头）。所有响应不包含
其他节点的私密材料；`recipientKey` 是收件人主动公开的本次公钥。

```text
POST /api/agent/v1/flux/transfers                   报价 {recipient, name, size, sha256}
GET  /api/agent/v1/flux/transfers                   列出本人参与的全部传输
POST /api/agent/v1/flux/transfers/{id}/accept        收件人 {publicKey}
POST /api/agent/v1/flux/transfers/{id}/deny          收件人 {reason?}
POST /api/agent/v1/flux/transfers/{id}/cancel        发送方
PUT  /api/agent/v1/flux/transfers/{id}/content       发送方上传密文（application/octet-stream）
GET  /api/agent/v1/flux/transfers/{id}/content       收件人下载密文
POST /api/agent/v1/flux/transfers/{id}/complete      收件人校验通过后确认
POST /api/agent/v1/flux/transfers/{id}/fail          收件人 {reason?}（解密/校验失败）
```

`recipient` 用节点 stable ID（CLI 可用 hostname 解析）。GET 列表返回
`direction`（sent/received）、双方 hostname、状态与时间戳；`recipientKey`
只在 accepted 之后出现。`reason` 是可打印 ASCII、≤200 字符的静态说明，
渲染时按文本转义。

### 25.4 端到端加密（控制面零知识）

- 收件人有一份本机 Flux 种子（`<state-dir>/flux.seed`，32 随机字节，0600，
  首次使用生成）。每条传输的收件人密钥对 =
  `HKDF-SHA256(seed, info="xunara-flux-recipient|"+transferID)` 派生的
  X25519 私钥；公钥在 accept 时上送（公钥不是秘密）。
- 发送方每次上传生成一次性 X25519 密钥对；共享秘密 =
  ECDH(一次性私钥, 收件人公钥) = ECDH(收件人私钥, 一次性公钥)。
  对称密钥 = `HKDF-SHA256(shared, info="xunara-flux-v1|"+transferID)`，
  密文 = `epk(32) || nonce(12) || AES-256-GCM(plaintext)`。
- 收件人下载后解密、校验 `sha256`，成功才 complete；失败调用 fail 并把
  reason 交给发送方。种子丢失时无法解密在途传输：收件人 fail，发送方重发。
- 控制面永远不接触明文或对称密钥；`sha256` 与文件名只是元数据（文档明示）。

### 25.5 本机落盘与 CLI

- `xunara-agent flux send -to <hostname|stable-id> -file <path> [-timeout 5m]
  [-json]`：报价 → 等待 accept（超时退出）→ 加密上传 → 等待终态并报告。
- `xunara-agent flux list [-json]`：本人参与的传输（id/方向/对端/状态/大小/时间）。
- `xunara-agent flux deny <id> [-reason ...]`：拒绝一条 inbound。
- `xunara-agent flux receive -dir <dir> [-yes] [-watch]`：接受并取回 pending
  inbound 传输；解密校验后原子写入 `<dir>/<name>`（0600）；`-yes` 表示无需
  确认（非交互环境必须显式给出），`-watch` 持续轮询。默认不覆盖已存在文件
  （改名为 `<name>.1` 等）。
- 上传前 CLI 预检（名字/大小/路径存在），服务端仍是权威。

### 25.6 清理与审计

- 控制面 janitor：过期非终态 → expired 并删除密文；终态行超 24h 删除；
  扫描内容目录删除无行对应的孤儿文件（节点删除的级联兜底）。
- 审计：`flux.transfer_offered/accepted/denied/uploaded/completed/failed/
  cancelled/expired`，detail 只写 id、名字、大小与静态 reason，绝不写密文或
  密钥材料。
