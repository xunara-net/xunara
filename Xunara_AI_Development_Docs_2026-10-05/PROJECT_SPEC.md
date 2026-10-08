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
- 服务就绪（§26）是节点自己写的**遥测**，与声明同源、同在 `/api/agent/v1`
  的 agent token + key 复述规则下，因此不削弱"节点是唯一写入者"。

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

启用健康跟踪（§26）的服务，以上只读面附带 `health` 与 `healthReportedAt`；
不跟踪的服务省略这两个字段。

### 22.6 审计

```text
node.services_updated   # target=节点，detail=服务名列表（含协议/端口），无 metadata 值
```

### 22.7 后续（不在 v1）

- ~~按 ACL/grants 的可见性~~：已由 §46（M39）交付——发布者声明 `visibility`
  选择器，MagicDNS 只对命中的节点发布记录；ACL 自动派生（"能连才可见"）
  的取舍见 §46.4；
- ~~服务就绪/健康状态与自动摘除~~：已由 §26（M19）交付；
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
  语义（ClusterIP 不是节点本地事实），见 §27（v1，已补 spec）。

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
  每组织 ≤ 1024 条、已上传内容的声明明文总量 ≤ 1 GiB（密文只多 60 字节，
  按声明 size 计即够）；超限 429。终态行保留 24h 供双方查询，janitor 清理；
  节点删除级联删除其传输行（内容文件由 janitor 孤儿扫描兜底删除）。
- TTL 默认 1h（可配）：超过后任何非终态 → `expired`，密文删除。
- 解析/校验失败 400；未认证 401；不是本人参与的传输 404（不泄漏存在性）；
  状态冲突 409；文件超过声明大小/限额 413；配额 429。

### 25.3 HTTP 端点（Agent 协议）

认证与 M9 相同（Bearer agent token + machine/node key 复述）。flux 端点统一
用 `X-Xunara-Machine-Key`/`X-Xunara-Node-Key` 请求头（与 `/events` 相同：
二进制上传/下载的 body 不夹带 JSON），POST 的 JSON body 只放业务字段。
所有响应不包含其他节点的私密材料；`recipientKey` 是收件人主动公开的本次
公钥。

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

- 种子：`<state-dir>/flux.seed`（32 字节，0600）。首次使用生成（`O_EXCL`
  收敛并发首用：输者读取胜者文件）；已存在但组/他人可读时拒绝运行并要求
  `chmod 600`，不静默接受。种子丢失后在途传输不可解，收件人 fail、发送方
  重发。
- `xunara-agent flux send -to <hostname|stable-id> -file <path> [-timeout 5m]
  [-json]`：报价 → 等待 accept（超时退出，传输保持 open 直到 TTL）→ 加密
  上传 → 等待终态并报告；成功才退出 0。`-to` 先经 netmap 精确匹配
  stable ID / Hostinfo hostname / MagicDNS 名（含短标签与 ComputedName）；
  多匹配报错并列出 stable ID；无匹配但形如 stable ID（`n`+16 hex）时直传，
  由服务端校验。`-file` 上传前预检：普通文件、≤64 MiB（客户端硬上限，与
  服务端一致），SHA-256 覆盖**实际上传的字节**；stat 与读取之间大小变化即
  拒绝（收件人不会收到无法校验的内容）。
- `xunara-agent flux list [-json]`：本人参与的传输（id/方向/对端/状态/大小/
  更新时间；reason 附在表后）。
- `xunara-agent flux deny [-reason <text>] <id>`：拒绝一条 inbound（Go flag
  约定：flag 在位置参数之前）。
- `xunara-agent flux receive -dir <dir> [-yes] [-watch] [-interval 5s]`：接受
  并取回 pending/uploaded inbound 传输。接受后最多等待 1 分钟让发送方上传；
  超时则本轮结束，传输保持 accepted，之后的 receive/`-watch` 继续取回。
  解密校验后原子写入 `<dir>/<name>`（0600，temp+rename）；`-yes` 表示无需
  确认（无终端时不给出 `-yes` 即报错，绝不隐式接受），`-watch` 持续轮询。
  不覆盖已存在文件（改名为 `<name>.1` 等）。以下情况调用 fail 并附固定
  reason：文件名不安全、密文超过声明大小、解密失败、SHA-256 不匹配；本地
  写入失败不 fail，保持 uploaded 供重试。传给对端的 reason 只使用固定
  字符串，绝不携带本地路径或本地错误文本。
- 上传前 CLI 预检（名字/大小/路径存在），服务端仍是权威。

### 25.6 清理与审计

- 控制面 janitor：过期非终态 → expired 并删除密文；终态行超 24h 删除；
  扫描内容目录删除无行对应的孤儿文件（节点删除的级联兜底）。
- 审计：`flux.transfer_offered/accepted/denied/uploaded/completed/failed/
  cancelled/expired`，detail 只写 id、名字、大小与静态 reason，绝不写密文或
  密钥材料。


### 25.7 配置接线（v1）

- 单组织：`xunarad -flux` 打开（**默认关**——与 Reach 同一原则，控制面替
  agent 存文件必须显式请求）；`-flux-dir`（默认 `<state-dir>/flux`）、
  `-flux-max-size`（明文字节数，默认 8 MiB，硬上限 64 MiB）、`-flux-ttl`
  （默认 1h，上限 24h）。只设置 dir/size/ttl 而不加 `-flux` 是配置错误，
  启动即失败（不静默忽略）；超范围的值同样启动失败，错误信息点名部署。
- 多组织：组织表 `flux_enabled` / `flux_dir` / `flux_max_size` / `flux_ttl`
  （同一套校验；`flux_dir` 省略时每个组织用自己的 `<state_dir>/flux`，因此
  密文永远不会跨租户共享目录）。`-org-config` 模式下 flux 命令行开关与其它
  组织级 flag 一样被拒绝。
- 未启用时 `/api/agent/v1/flux/*` 一律 404（fail-closed，不为未启用功能保留
  探测面）；启用后 janitor 负责过期、终态清理与孤儿内容扫描（§25.6）。

## 26. Xunara Atlas 健康状态与自动摘除（v1）

目标：节点可以声明"这个服务现在是否就绪"，控制面据此把未就绪或失联的服务
从 MagicDNS 发现中**自动摘除**，就绪后自动恢复。服务的声明（名字/协议/端口）
仍然只由节点自己写（§22.2）；控制面不做探测、不做代理、不做故障转移。

边界（v1 明确不做）：

- 控制面绝不主动连接服务端点（它到不了尾网地址，也拒绝成为代理层）；
- 不做负载均衡、故障转移、健康历史或评分；
- 健康只影响**发现**（MagicDNS 记录与只读视图），不影响 ACL：摘除 DNS
  记录不是安全边界，连接授权始终由既有 ACL/grants 决定；
- 不改 TS2021 / Noise / netmap 结构（AGENTS §4）：摘除只体现为 A/AAAA
  记录消失；
- Consul 导入（§23）不自动启用健康（导入器不做健康过滤）。

### 26.1 模型

- 声明中的每个服务可选 `"health": true`（默认 false）。false = 不跟踪，
  行为与 §22 v1 完全一致：永远出现在 DNS 与列表里。
- 启用健康后，服务的**生效健康**只有两种：`healthy` / `unhealthy`。
  生效 healthy 当且仅当节点最近一次上报说 `ready=true`，且距该次上报不超过
  TTL。从未上报 = unhealthy（fail-closed：不进入 DNS）。
- 上报是**完整集合**：节点每次上报其全部启用健康的服务；未列出的启用健康
  服务立即视为 not ready。
- TTL 默认 90s（`DefaultServiceHealthTTL`，可配 30s–15m）。节点停止上报
  （agent 退出、网络断开）超过 TTL，其启用健康的服务全部自动摘除。
- 重新发布声明时，同名且仍启用健康的服务保留当前健康状态（定期重发不会
  让 DNS 记录抖动）；关闭健康或改名则清空健康状态。

### 26.2 HTTP 端点（Agent 协议）

```text
POST /api/agent/v1/services/health   {services: [{name, ready}]}
```

- 认证与 `/services` 相同（agent token + machine/node key 复述）。
- 整批原子：任一 name 未声明、未启用健康、重复或超过 32 条 → 400，不部分
  应用。
- 响应与发布相同：该节点当前存储的服务集合（含 `health` 与
  `healthReportedAt`）。
- 每次上报把全部启用健康的服务写成 `healthy=<ready>`、`health_until=now+TTL`，
  未列出者 `healthy=false`。

### 26.3 摘除与恢复

- 生效 unhealthy 的启用健康服务不产生 MagicDNS A/AAAA 记录；恢复 healthy
  后记录回来。
- 状态转变（上报、过期）都会持久化到存储并唤醒 netmap 流，客户端在下一帧
  看到记录变化；janitor 每 15s 扫描一次过期上报（与 1 分钟的整体 janitor
  节奏解耦），只影响启用健康且当前 healthy 的行。
- 节点删除级联删除服务行（§22.2 不变）。

### 26.4 审计

```text
service.healthy      # target=节点，detail="<name>/<proto>:<port> is ready (reported)"
service.unhealthy    # 同上，原因 reported / report expired
```

只在**转变**时写：重复上报 true 不产生审计（与 §22.2 的 no-op 抑制一致）。

### 26.5 管理面

- `GET /api/v2/services`、gRPC `PlatformService.ListServices`、Console
  Services 页、CLI `xunara services list|show` 增加 `health`
  （`healthy`/`unhealthy`；不跟踪的服务省略）与 `healthReportedAt`。
- 管理面仍然只读（AGENTS §10）。

### 26.6 节点侧（agent）

- 声明中 `"health": true` 的服务，其就绪状态来自
  `<state-dir>/services-health.json`：

```json
{"services": [{"name": "api", "ready": true}]}
```

- `xunara-agent run` 每 `-services-health-interval`（默认 30s）把声明中全部
  启用健康的服务作为完整上报发出：文件中缺失或 `ready=false` 的即 not ready；
  文件不存在 = 全部 not ready（fail-closed，服务被摘除）。
- 文件里未声明或未启用健康的名字忽略并告警（删除服务后遗留的旧行不应让
  整批上报失败）；文件解析失败 → 本周期不上报并告警（服务最迟在 TTL 后
  摘除）。
- TTL 与上报间隔是部署契约：TTL 应 ≥ 3× 间隔；默认值（90s / 30s）满足。

## 27. Xunara Atlas — 目录导入（v1，Kubernetes）

目标与 §23 相同：节点把**本节点提供**的 Kubernetes Service 转换成 Atlas 声明
并发布，不必手工维护 `services.json`。导入器在节点侧运行，控制面拿不到集群
凭据（AGENTS §8/§12），节点仍是唯一写入者（§22.2）。

边界（v1 明确不做）：

- 不做 watch/持续同步：一次 `import` 是某一时刻的快照，之后由 `run` 按声明
  重发；集群变化后重跑 `import`（与 §23 的 Consul 导入一致）。
- 不导入 Pod/容器，也不把 ClusterIP 当作节点本地事实：只导入**在本节点上
  有就绪端点**的 Service。
- 不把 EndpointSlice 的就绪状态写入 `services-health.json`：健康上报仍只由
  节点侧文件驱动（§26），导入不做健康过滤、不自动启用健康。
- 一次调用只导入一个命名空间（默认本 Pod 的命名空间），不支持跨命名空间
  批量导入；多命名空间场景在 v1 不在支持范围内。
- 不依赖 `spec.nodeName` field selector：已核对上游 registry strategy，
  EndpointSlice 可选择的字段只有 `metadata.name`/`metadata.namespace`，
  因此按节点过滤在导入器内完成（列出后用 `endpoints[].nodeName` 匹配）。

### 27.1 连接与凭据（fail-closed）

| 项 | 默认 | 覆盖 |
|---|---|---|
| API server | in-cluster：`https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT` | `-k8s-api` |
| bearer token | `/var/run/secrets/kubernetes.io/serviceaccount/token` | `-k8s-token-file` |
| CA | 同目录 `ca.crt`（不存在则系统根证书） | `-k8s-ca-file` |
| namespace | 同目录 `namespace` 文件，否则 `default` | `-k8s-namespace` |
| 节点名 | 环境变量 `NODE_NAME`（Downward API） | `-k8s-node` |

- token 只从文件读取，只出现在请求的 `Authorization: Bearer` 头；绝不进
  argv、URL query 或日志（AGENTS §8）。节点名必填：在 Pod 里 hostname 是
  Pod 名而不是节点名，禁止从 hostname 猜测。
- `-k8s-api` 只接受 `https://`，或 loopback 的 `http://`（与 webhook 的
  端点规则一致）；token 不会被发送到非 loopback 的明文地址。
- namespace 必须是合法 DNS-1123 label（同时是 URL 路径组件，防止路径注入）。

### 27.2 映射规则（fail-closed）

读取两个只读端点（分页跟随 `metadata.continue`，页大小与页数有上限）：

```text
GET /api/v1/namespaces/{ns}/services
GET /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices
```

逐条映射：

- 只考虑注解 `xunara.io/advertise: "true"`（精确匹配）的 Service；其余
  静默忽略（未启用不是错误）。
- 就绪端点：该 Service 的 EndpointSlice（label
  `kubernetes.io/service-name=<service>`）中存在 `endpoints[].nodeName ==
  <本节点>` 且 `conditions.ready != false` 的端点。`ready == null` 视为就绪
  （上游语义：unknown 按就绪解释，与 kube-proxy 一致）。没有本节点就绪
  端点的 Service 跳过并告警（不发布不可达的名字）。
- 端口来自这些本地端点所属 slice 的 `ports[]`：

| EndpointSlice | Atlas |
|---|---|
| `ports[].protocol` 缺省 `TCP`（上游默认） | `protocol` 小写；只接受 tcp/udp，SCTP 跳过 |
| `ports[].port` 为空（"all ports"）或 0/越界 | 跳过该端口 |
| 多个可用端口 | 需注解 `xunara.io/port: <ports[].name>` 指定；未指定或指定不到唯一端口 → 整个 Service 跳过并告警（不猜） |

- `name` = Service 名（K8s 已保证 DNS-1123 label）；仍经
  `protocol.ValidateServices`（§22.4）复核，不合法跳过并告警。
- `metadata` 仅来自注解 `xunara.io/metadata` 的 JSON 对象（string→string）；
  缺省为空；解码失败或含非字符串值 → 跳过并告警。绝不整体导入
  labels/annotations：注解常用于携带凭据，值可能被写进日志（AGENTS §8）。
- 告警只说明跳过了什么与原因，不回显注解/标签值。

### 27.3 限额与原子性

同 §23.2：映射结果超过每节点 32 条 → 导入失败、不截断（发布是整批替换，
截断等于撤销）；发布走既有数据面，服务端执行 §22.4 的全部校验与冲突检查；
`services.json` 只在服务端接受之后才更新。

### 27.4 命令面与 RBAC

```text
xunara-agent services import -from kubernetes [-k8s-api https://...]
                             [-k8s-token-file path] [-k8s-ca-file path]
                             [-k8s-namespace ns] [-k8s-node name]
                             [-dry-run] [-state-dir d]
```

集群侧只需要只读权限（最小权限，按命名空间）：

```text
get/list  services             (core/v1)
get/list  endpointslices       (discovery.k8s.io/v1)
```

导入器不写集群、不创建/修改任何对象。

## 28. Workload Identity 签发限流（v1）

目标：给 `/machine/id-token` 加一条持久化的固定窗口限流，防止单个节点以任意
audience 反复要求控制面签名（耗尽签名能力、骚扰依赖方、刷审计）。

- 维度：每个 `(节点, audience)` 一个桶；窗口 1 分钟；默认每窗口 30 个 token
  （`control.DefaultIDTokenRateLimit`）。
- 计数在 store 里（state 迁移 v13 `rate_limits`，scope 为主键），不是
  server-local map：多实例共享状态目录时计数一致，重启不丢（AGENTS §9）。
  内存与 SQLite 共享同一份固定窗口语义。
- 超限：HTTP 429 + `Retry-After`（整秒向上取整）；不签发、不写审计——否则
  循环请求会把审计日志变成攻击放大器。
- 桶不引用节点，由 janitor 按年龄清理（窗口早于 1 小时）。
- 配置：`control.Config.IDTokenRateLimit`（0=默认，负数启动失败）；
  `xunarad -id-token-rate-limit`；组织配置 `id_token_rate_limit`。
- 不做：tailnet 级/全局限流、按 token 的配额与计量、按 audience 的授权策略。

## 29. Xunara Reach — 远程命令执行（v1）

目标：运维者从一台节点对另一台节点执行命令，输出流式回传。目标节点**显式
审批**后才执行；控制面只编排会话并中继输出块，不代理隧道、不碰进程。

边界（v1 明确不做）：

- 不做交互式终端：无 PTY、无 stdin（命令的 stdin 是空的）。需要交互的场景
  仍用 §22 的服务发现 + 官方 SSH（M6a）。
- 不经过 shell：`argv` 逐元素执行（`exec` 语义），因此没有 shell 注入面；
  `sh -c "..."` 由调用方自己显式写进 argv（后果自负，审批页会显示完整 argv）。
- 不跨 tailnet 直连：agent 没有 TUN，节点之间不可直达；控制面只接力
  "会话状态 + 输出块"，与 §25 的存储转发同一模式。
- 不做提权/降权：命令以 agent 进程的权限与工作目录运行，文档明示
  "不要用 root 跑 agent"，控制面不提供 sudo/runas。
- 不做持久会话/断点续跑：会话终态后输出保留到 janitor 清理。

### 29.1 模型与状态机

```text
offered ──accept──▶ accepted ──start──▶ running ──finish──▶ succeeded | failed
   │                   │                   │
   │deny/cancel        │cancel             │cancel
   ▼                   ▼                   ▼
denied              canceled            canceled
   │
   │（超时未处理）
   ▼
expired
```

- `offered`：发起节点创建，携带 `to`（目标 stable ID）、`argv`、`timeout`
  （默认 60s，上限 15m）。等待目标审批的时间上限 5 分钟，过期即 `expired`。
- `accepted`：目标审批通过；目标 agent 的 reach 循环取走并 `start` 进入
  `running`（条件更新，只有一个实例能赢）。
- `running`：命令在跑；输出以块写入。达到输出上限（每会话合计 2 MiB）时
  目标终止命令并以 `failed` + `error=output limit exceeded` 收尾（截断不静默）。
- 终态：`succeeded`（exit 0）/`failed`（非 0 或无法启动，带 `exitCode` 与
  净化后的错误）/`denied`/`canceled`/`expired`。
- 执行超时（timeout，或 `expires_at`）由目标杀进程并 `failed`
  （`error=timed out`）；目标失联时 janitor 把逾期的非终态会话置为 `expired`。

### 29.2 Agent 协议

认证与其它 `/api/agent/v1` 端点相同（agent token + machine/node key 复述）；
只有会话的两端可读，目标可 accept/deny/start/finish，双方可 cancel。

```text
POST /api/agent/v1/reach/sessions                     # {to, argv, timeoutSec} -> 会话视图
GET  /api/agent/v1/reach/sessions                     # 本节点参与（发起或目标）的会话
GET  /api/agent/v1/reach/sessions/{id}                # 参与者
POST /api/agent/v1/reach/sessions/{id}/accept         # 目标：offered -> accepted
POST /api/agent/v1/reach/sessions/{id}/deny           # 目标：offered -> denied
POST /api/agent/v1/reach/sessions/{id}/start          # 目标：accepted -> running
POST /api/agent/v1/reach/sessions/{id}/chunks         # 目标：{stream, seq, data(base64)}
GET  /api/agent/v1/reach/sessions/{id}/chunks?out=&err= # 发起方：读取 seq > 游标的块
POST /api/agent/v1/reach/sessions/{id}/finish         # 目标：{exitCode, error} -> succeeded/failed
POST /api/agent/v1/reach/sessions/{id}/cancel         # 双方：-> canceled（running 时目标杀进程）
```

- `stream` ∈ `stdout|stderr`；`seq` 从 0 单调递增（按 stream）；重复 seq 拒绝
  （幂等性由调用方负责，重试会得到 409，不会产生重复输出）。
- `chunks` 读取用每 stream 的游标（`out`/`err`），响应含 `nextOut`/`nextErr`；
  单次最多 64 块、每块 ≤ 24 KiB（base64 前）。
- 限额 fail-closed：`argv` 1–16 项、每项 ≤ 4 KiB、合计 ≤ 16 KiB；`to` 必须是
  已存在的 stable ID 且不是自己；同一对节点同时最多 8 个非终态会话；每节点
  每 10 秒最多创建 6 个会话（复用 §28 的持久化限流器）。
- 未知 `to`、跨租户（组织内不存在）→ 404；状态不允许的动作 → 409。

### 29.3 审计

```text
reach.offered    # target=目标节点，detail="session=<id> from=<stable id>"
reach.accepted   # 目标审批者（节点代理）
reach.denied
reach.started
reach.finished   # detail 含 exit code
reach.failed
reach.canceled
reach.expired
```

argv 与输出**永不**进审计/webhook；它们只在会话记录（参与者与管理面可见）
与 CLI 输出里。审批页/CLI 显示完整 argv——这正是知情同意的内容。

### 29.4 管理面（只读）

- 管理面：HTTP `GET /api/v2/reach/sessions`（§31）与 Console `/console/reach`；
  v1 只有只读视图，取消/重跑不在其中。
- session 记录保留：终态后 janitor 清理（1 小时）。

### 29.5 命令面

```text
xunara-agent reach offer  -to <host|stable-id> [-timeout 60s] -- <cmd> [args...]
xunara-agent reach list   [-json]
xunara-agent reach run    -to <host|stable-id> [-timeout 60s] -- <cmd> [args...]
                          # offer + 等待审批/执行，流式打印 stdout/stderr，退出码映射
xunara-agent reach show   <id>
xunara-agent reach accept <id> | deny <id> | cancel <id>
xunara-agent reach serve  # 目标侧执行循环（run 内默认启动；见下）
```

`xunara-agent run` 默认启动 reach 执行循环（目标侧）；`reach run` 是发起侧
一条命令走完 offer → 等待 → 打印 → 退出。

## 30. 组织自省（v1）

目标：任何已认证的调用方（浏览器会话或服务身份 API key）都能确认"我现在连的
是哪个组织"。多租户部署里客户端通常只拿到一个基础 URL，排障、自动化与
客户端 UI 需要一个权威答案；该答案必须来自 Host 路由实际选中的那个组织，
不能由调用方指定。

```text
GET /api/v2/organization        # read scope；与 /api/v2/meta 同一认证与角色规则
```

响应（只读、无 secret）：

```json
{
  "id": "acme",
  "name": "Acme Corp",
  "domains": ["login.acme.example.com", "*.acme.example.com"],
  "managed": true,
  "magicDnsDomain": "acme.internal",
  "serverUrl": "https://login.acme.example.com"
}
```

- `domains` 恒为数组（无域时 `[]`，绝不返回 null），是**路由域**（该组织响应
  的 Host 模式），不是 MagicDNS 后缀。
- `managed` 表示组织来自平台注册表（其生命周期可由 `/api/platform/v1` 改动）；
  配置型组织为 false。
- 单租户部署（无组织表）没有平台身份：`id`/`name` 省略，`domains` 为 `[]`，
  `managed` 为 false；其余字段照常返回。客户端不得把空 `id` 当作错误。
- 组织身份的权威来源是 Router 注册的 `OrgSite`；托管组织 PATCH（name/domains）
  后自省结果同步更新，ID 不可变。实现必须用并发安全方式更新（自省读路径与
  平台写路径可以并行）。
- 永不返回：用户/节点/密钥材料/secret/provider 配置细节（那些属于别的端点，
  且受各自 scope 约束）。
- gRPC 对应 `PlatformService.GetOrganizationIdentity`（语义、认证、错误映射与 HTTP
  一致：未认证 `UNAUTHENTICATED`，缺 scope `PERMISSION_DENIED`，未知 authority
  `NOT_FOUND`）。
- 不做（v1）：组织级配额/计量、跨组织目录（那是 `/api/platform/v1` 的
  ListOrganizations，只接受平台令牌）。

## 31. Xunara Reach 管理面（只读，v1）

目标：管理员能回答"谁在什么时候对哪台节点跑了什么、结果如何"（合规与排障）。
只读：没有任何写入口（取消/重跑都不在 v1）。延续 §29 的边界——argv 与输出
**对管理面可见**（§29.3），但永不进审计/webhook。

### 31.1 HTTP（`/api/v2`，read scope）

```text
GET /api/v2/reach/sessions?state=&node=&limit=&cursor=   # 最新在前，游标分页
GET /api/v2/reach/sessions/{id}                          # 详情（含 argv 与输出字节数）
GET /api/v2/reach/sessions/{id}/chunks?out=&err=         # 输出块（每流每请求 ≤64 块）
```

- 列表条目与 agent 端会话视图同构（id/state/sender/target/argv/timeoutSec/
  exitCode/error/createdAt/updatedAt/expiresAt），另加 `outputBytes`
  （`{\"stdout\":n,\"stderr\":n}`，只有计数，没有内容）。
- 过滤 fail-closed：`state=` 未知值 400（不是"忽略"）；`node=` 接受节点 id 或
  stable ID，未知节点返回空集（与 §22.3 的 v2 列表一致）。列表按
  `(createdAt, id)` 最新在前，游标不透明、带 kind 校验。
- `chunks` 与 agent 端同一形状（`out`/`err`/`nextOut`/`nextErr`）：管理面不需要
  无限拉取，2 MiB 的输出用多次请求读；每流每请求至多 64 块。
- Reach 未启用（`reach_enabled=false`）时三个端点一律 404（与 agent 端点一致，
  不为未启用功能保留探测面）。
- 响应 `Cache-Control: no-store`（内容可能含敏感 argv/输出）。永不返回：机器/
  节点密钥、agent token、其它 secret。
- 会话不存在 → 404；坏 id 形状 → 404（与其它 v2 详情端点一致，不区分"格式错"
  与"不存在"）。

### 31.2 gRPC

`PlatformService.ListReachSessions` / `GetReachSession`：语义、认证、游标与错误
映射与 HTTP 一致（未知会话/未启用 `NOT_FOUND`）。输出块只在 HTTP 暴露：2 MiB
的调试文本不值得进自动化的类型化 API。

### 31.3 Console

`/console/reach` 列表（state 过滤、最新在前）与 `/console/reach/{id}` 详情：
显示 argv、状态、exit code、error 与输出（HTML 转义、单条截断到 64 KiB 并显式
标注截断）。Reach 未启用时页面说明功能未开启；页面只读，没有任何写按钮。

### 31.4 保留与隐私

- 终态会话连同输出由 janitor 在 1 小时后删除（§29.4 不变）：管理面看到的是
  同一份记录，不产生第二份副本。
- argv/输出可能含敏感参数，所以端点受 read scope 与角色规则约束（与其它 v2
  端点相同），且不写入审计、webhook、日志。
- 不做（v1）：管理面取消/重跑、输出导出下载、按 argv 全文搜索、长期归档。

## 32. DERP 管理面（只读，v1）

目标：管理员能回答"这个组织给客户端下发了哪些 DERP 区域、节点现在落在哪个
区域"，用于排障与容量核对。只读：DERP 策略仍然只能通过启动配置/组织表修改
（§M7b），这里没有任何写入口。

### 32.1 HTTP（`/api/v2`，read scope）

```text
GET /api/v2/derp
```

```json
{
  "policyMode": "inherit",
  "policyRegions": [],
  "mapConfigured": true,
  "regionsServed": 1,
  "regions": [
    {
      "id": 1,
      "code": "xunara-veil-1",
      "name": "Xunara Veil Frankfurt",
      "hosts": ["veil.example.com:443"],
      "nodeCount": 3
    }
  ],
  "nodesWithoutHome": 4,
  "nodesWithUnservedHome": 1
}
```

- `policyMode` ∈ `inherit|none|regions`（与 `-derp-policy` / 组织表一致；未配置
  策略渲染为 `inherit`，不是空字符串）；`policyRegions` 只在 `regions` 模式
  非空，其它模式恒为 `[]`。
- `mapConfigured` 区分 nil 与空 map：false 表示部署没有配置 DERP map
  （客户端保持内置默认区域，nil = 不变）；true 且 `regionsServed=0` 表示
  策略明确告诉客户端"没有 DERP"（`none`）。两种"没有区域"语义不同，客户端
  行为也不同，管理面必须能区分。
- `regions` 按 ID 排序，只含**实际下发**的区域（策略过滤后的 map）；`hosts`
  是 relay 的 `host:port`，属于 netmap 的公开信息，不含 secret。
- `nodeCount` 是该区域作为节点 HomeDERP 的节点数；`nodesWithoutHome` 是
  HomeDERP 为 0 的节点数；`nodesWithUnservedHome` 是 HomeDERP 已设置但不
  在当前下发 map 里的节点数（策略收紧后的过渡态，下一次 map 请求会清空并
  重新归属）。
- 认证/角色与其它 v2 read 端点一致；响应 `Cache-Control: no-store`。
- gRPC 对应 `PlatformService.GetDERPStatus`（语义、认证、错误映射与 HTTP
  一致：未认证 `UNAUTHENTICATED`，缺 scope `PERMISSION_DENIED`）。
- 不做（v1）：修改策略、按区域断连/重定位、DERP 中继流量统计（那是 Veil
  的运行指标，不在控制面）、历史趋势。

### 32.2 Console

`/console/derp`：策略摘要（模式、白名单、是否配置 map）、区域表
（ID/code/名称/relay 地址/节点数）与节点归属表（hostname、stable ID、在线、
HomeDERP，未归属/不再服务的显式标注）。只读，页面不提供任何按钮。

## 33. Xunara Flux 管理面（只读，v1）

目标：管理员能回答"谁在什么时候给谁发了什么文件、结果如何"（合规与排障）。
只读，且**控制面零知识不因管理面改变**：文件内容是对端加密的密文，管理面
永远不返回内容、下载入口或任何密钥材料。

### 33.1 HTTP（`/api/v2`，read scope）

```text
GET /api/v2/flux/transfers?state=&node=&limit=&cursor=  # 最新在前，游标分页
GET /api/v2/flux/transfers/{id}                         # 详情
```

```json
{
  "id": "fx_…",
  "state": "uploaded",
  "name": "report.pdf",
  "size": 12345,
  "sha256": "…64 hex…",
  "sender": {"nodeId": 1, "stableId": "n…", "hostname": "laptop"},
  "recipient": {"nodeId": 2, "stableId": "n…", "hostname": "server"},
  "reason": "…",
  "createdAt": "…", "updatedAt": "…", "expiresAt": "…"
}
```

- 列表条目与 agent 端视图同构，但没有"收/发"方向字段：管理面是第三人称
  视角。过滤 fail-closed：未知 `state=` 400（不是忽略）；`node=` 接受节点
  id 或 stable ID，未知节点返回空集；游标不透明、带 kind 校验，按
  `(createdAt, id)` 最新在前。
- 终态行保留 24 小时（§25.2 不变），janitor 删除后管理面同样读不到：管理面
  看的就是同一份记录，没有第二份副本。
- Flux 未启用时两个端点 404（与 agent 端点一致）；坏 id 与不存在同为 404；
  响应 `Cache-Control: no-store`。
- **永不返回**：文件内容（密文或明文）、任何密钥材料（包括收件人
  `recipientKey`——发送方需要它，管理员不需要）、内容文件的路径；管理面
  **没有**内容下载端点（需要内容的是参与方，走
  `/api/agent/v1/flux/transfers/{id}/content`，且只有两端可读）。

### 33.2 gRPC

`PlatformService.ListFluxTransfers` / `GetFluxTransfer`：语义、认证、游标与
错误映射与 HTTP 一致（未启用/未知会话 `NOT_FOUND`，坏 state/游标
`INVALID_ARGUMENT`）。同样没有内容读取——没有任何消息携带内容或密钥。

### 33.3 Console

`/console/flux` 列表（state 过滤、最新在前）与 `/console/flux/{id}` 详情：
显示名字、大小、状态、双方、SHA-256、reason 与时间戳，并明确说明内容不在
控制面（端到端加密）。只读、无任何按钮；未启用时页面说明功能未开启。

### 33.4 不做（v1）

管理面取消/删除、内容下载/导出、按文件名全文搜索、跨组织视图、内容扫描
（DLP 不在 v1，§25）。

## 34. Xunara Warden 管理面（只读，v1）

目标：管理员能回答"这份策略到底写了什么、哪些规则/组/hosts 定义在案、自带
的 tests 现在是否通过"。策略文档仍然只从磁盘（`-policy`）加载，watcher 在
文件变化时整体重载：管理面没有任何写入口，也不提供在线编辑 ACL 的通道。

### 34.1 HTTP（`/api/v2`，read scope）

```text
GET /api/v2/policy
```

```json
{
  "configured": true,
  "path": "/etc/xunara/policy.hujson",
  "ruleCount": 3,
  "warnings": ["acls[1]: src \"user:nobody@example.com\" matches no node"],
  "unsupported": ["autoApprovers"],
  "loadError": "",
  "acls":     [{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"], "proto": "tcp"}],
  "grants":   [{"src": ["group:dev"], "dst": ["tag:db"], "ip": ["tcp:5432"], "app": {}}],
  "groups":   {"group:admins": ["alice@example.com"]},
  "hosts":    {"db": "100.64.0.1"},
  "tagOwners": {"tag:server": ["group:admins"]},
  "ssh":      [{"action": "check", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["root"], "acceptEnv": [], "checkPeriod": "12h"}],
  "nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
  "tests": {
    "total": 1,
    "ran": true,
    "results": [{"index": 0, "src": "alice@example.com", "proto": "", "pass": true, "failures": []}]
  }
}
```

- `configured=false` 表示部署没有配置策略文档（默认放行，与官方"无策略
  tailnet"一致）；此时其余字段为空。`path` 是本地文档路径（与 `/api/v1/policy`
  一致）。
- 各 section 按文档原样呈现，选择器字符串不做改写；`checkPeriod` 渲染为
  `"always"` 或 Go duration 字符串（如 `"12h0m0s"`），未写时省略。`ruleCount`
  是编译后的规则总数（ACLs + grants）。
- `warnings` 是编译时的不致命问题（例如某选择器当前不匹配任何节点）；
  `unsupported` 是本 build 认识但未执行的顶层字段——它们被**忽略**，
  因为未实现的字段只可能收紧语义、不会放宽。
- `loadError` 非空表示磁盘上的文件现在解析失败：watcher 保留了上一份可用
  策略，`configured` 与各 section 反映的是**生效中**的那份，管理员应据此
  判断是否需要修复或重启。
- `tests` 对当前节点快照运行文档自带的断言（与 `xunara policy check` 相同
  语义）。`ran=false` 表示没有运行：没有节点、文档没有 tests、或运行前的
  文档校验失败（原因在 `reason`）。单条断言不满足是结果里的
  `pass:false` + `failures`，不是 HTTP 错误——管理面永远不因策略内容返回
  5xx。
- 认证/角色与其它 v2 read 端点一致；响应 `Cache-Control: no-store`。
- gRPC 对应 `PlatformService.GetPolicyStatus`（语义、认证、错误映射与 HTTP
  一致：未认证 `UNAUTHENTICATED`，缺 scope `PERMISSION_DENIED`）。
- 不做（v1）：修改/热编辑策略、按选择器解析当前节点（"谁能访问谁"）、对
  任意流的按需评估、ACL 编辑器/语法高亮、`grants` 的 `via`、ACL
  `srcPosture` 条件（仍未实现，§M13/M14）。

### 34.2 Console

`/console/policy`：文档路径与规则计数；ACL、grants、组、hosts、tagOwners、
SSH、nodeAttrs 的表；自测结果（每条 `index/src/proto` 的通过/失败与失败
原因）；`warnings`、`unsupported` 与磁盘解析失败（`loadError`）显式标注。
只读，页面不提供任何按钮；未配置策略时说明"默认放行"。

## 35. SSH 审批管理面（只读，v1）

目标：管理员能回答"谁正在尝试 SSH 到哪台机器、本地的哪个账号、上一次检查
结果如何"，不必等用户把 HoldAndDelegate 链接贴过来。审批本身仍只在既有的
`/ssh/check/{authID}` 页面上进行（console session + write 角色 + CSRF），
管理面没有任何写入口。

### 35.1 HTTP（`/api/v2`，read scope）

```text
GET /api/v2/ssh-check/sessions?state=&node=&limit=&cursor=  # 最新在前，游标分页
```

```json
{
  "items": [
    {
      "id": "…",
      "state": "pending",
      "verdict": "pending",
      "src": {"nodeId": 1, "stableId": "n…", "hostname": "laptop"},
      "dst": {"nodeId": 2, "stableId": "n…", "hostname": "server"},
      "localUser": "root",
      "createdAt": "…",
      "expiresAt": "…"
    }
  ],
  "nextCursor": ""
}
```

- 记录与审批流是同一份（identity 的持久化 session），管理面没有第二份副本：
  janitor 按 TTL 删除后，这里同样看不到。列表条目就是详情——记录很小，
  v1 没有单独的详情端点。
- `state` 是派生的、互斥的生命周期状态（按优先级）：
  `expired`（pending 且已过 TTL、janitor 还没删）→ `pending`（仍可决定）→
  `consumed`（判定已被一次后续请求取走）→ `accepted` / `rejected`（已决定
  但尚未被消费）。`verdict` 保留原始判定 `pending|accept|reject`，因为
  `consumed` 会掩盖判定的方向。
- 过滤 fail-closed：未知 `state=` 400（不是忽略）；`node=` 接受节点 id 或
  stable ID，匹配**任一端**，未知节点返回空集。游标不透明、带 kind 校验，
  按 `(createdAt, id)` 最新在前；扫描上限 1 万条（TTL 15 分钟内的自然边界，
  上限只为坏掉的 janitor 兜底）。
- 节点删除后条目保留（session 不在节点级联里）：只显示 `nodeId`，stable ID
  与 hostname 为空。`decidedBy`（决定人：console 用户
  `{"userId": 1, "loginName": "…"}`）与 `decidedAt` 只在已决定时出现；
  `consumedAt` 只在已消费时出现。
- 认证/角色与其它 v2 read 端点一致；响应 `Cache-Control: no-store`。
- gRPC 对应 `PlatformService.ListSSHCheckSessions`（语义、认证、游标与错误
  映射与 HTTP 一致：未认证 `UNAUTHENTICATED`，缺 scope
  `PERMISSION_DENIED`，坏 state/游标 `INVALID_ARGUMENT`）。
- 不做（v1）：管理面 approve/deny、删除/清理记录（janitor 按 TTL 负责）、
  按 local user/时间窗过滤、实时推送（长轮询仍在 `/machine/ssh/action`）。

### 35.2 Console

`/console/ssh-check`：最新在前的会话表（ID、状态、两端、local user、创建/
过期时间、判定与决定人），state 过滤（未知值 400，与 API 一致），pending 行
显式标注；最多 200 条。页面本身只读、不含任何写表单：ID 链接到既有审批页
`/ssh/check/{authID}`，该页自行要求 console session、write 角色与 CSRF。

## 36. API 密钥管理面（Console，v1）

目标：管理员不必登录机器执行 `xunara apikey`：在 Console 里看到自动化凭据
（Service Identity API Key）的清单、按需创建并把 token 一次性展示、即时
吊销。对应 §20 P1 的 "OAuth/API Keys"。

范围说明：自动化读写仍以 `/api/v1/api-keys`（以及 `xunara apikey` CLI）为
准，本版本**不**新增 v2/gRPC 端点——同一张 identity 表再包一层 API 没有
新增能力，只会引入第二套语义。Console 是唯一新增面；登录用的 OAuth/OIDC
providers 是启动配置（§13/§15），本页只提示、不管理。

### 36.1 Console

`/console/api-keys`（nav "API keys"）：

- 列表：ID、name、owner（login name）、scopes、创建/过期/最后使用/吊销
  时间；**永不显示 token**（只有创建响应出现一次，且服务端只存哈希）。
- 创建（write 角色 + CSRF）：name 必填、scopes 至少一个（read/write 复选）、
  TTL 可选（Go duration，>0）；owner 恒为当前登录用户。创建成功后页面用
  `notice` 一次性展示 `<code>xunara_…</code>` token，并提示不可再次查看。
  身份隔离（AGENTS §5）：这是 Service Identity，不会变成任何人的登录方式。
- 吊销（write 角色 + CSRF）：写 `revoked_at`，幂等（已吊销再点不报错）；
  审计 `apikey.created` / `apikey.revoked`（与 v1 相同 action），detail 标明
  "through the console"。
- 授权边界：scope 只是上限，服务端仍要求 owner 的角色允许 write
  （`authorizeScope`），Console 创建因此不会产生超出创建者角色的凭据。
- 明确不做（v1）：编辑已有 key（scope/TTL 不可变，只能吊销重建）、显示或
  导出 token、OAuth provider 增删改（启动配置）、按 key 的用量统计。

## 37. 能力发现补齐（/api/v2/meta，v1）

目标：`/api/v2/meta` 是客户端与自动化"调用前发现可选能力"的端点（§27–§36 的
每个管理面都依赖它）；每个已交付的可选面都必须在 meta 里可见，且语义与真实
行为一致。本版本补齐遗漏字段并修正 `webhooksEnabled` 的失真语义。

### 37.1 字段

现有字段不变，新增三个布尔：

- `reachEnabled`：Xunara Reach 远程命令面（§31）启用（`cfg.ReachEnabled`）。
- `fluxEnabled`：Xunara Flux 文件传输面（§33）启用（Flux 服务已构建）。
- `passkeysEnabled`：passkey（WebAuthn）登录与凭据管理启用（passkey 服务
  已构建；`cfg.Passkeys` 只是配置来源）。

`webhooksEnabled` 语义修正：改为"存在会投递的接收端点"——启动配置了端点
（`cfg.Webhooks`），**或**存在任一 `Enabled` 的托管端点（Console/API 创建）。
此前只看启动配置，运行时创建的端点在 meta 里不可见；暂停（`Enabled=false`）
的托管端点不投递，因此不计入。meta 只回答"是否启用"，不列端点明细。

### 37.2 一致性

- gRPC `PlatformService.GetMeta` 返回同一组字段与同一判据（proto 重新生成：
  `reach_enabled`/`flux_enabled`/`passkeys_enabled`）。
- 任何字段都不得携带 secret（AGENTS.md §8）；既有字段
  （version/serverUrl/domain/capabilityVersion/minCapabilityVersion/maxPageSize/
  identityProviders/agentProtocolVersion/dnsProviderConfigured/certDomains/
  derpMapConfigured/derpPolicy/derpRegionsServed/identityTokensEnabled）语义
  不变。
- 不做能力清单/版本协商端点：客户端按字段判断即可，新增可选面继续在 meta
  追加布尔字段。

## 38. Xunara Share（跨组织机器共享，v1）

目标：把一台机器（节点）共享给**另一个组织**里的某个用户，使该用户的节点与这台
机器之间可以互相连接，而不把两个组织的地址空间、节点 ID、用户 ID 或策略互相
暴露（AGENTS §5/§6/§12）。产品语义参考 MirageServer 的 MachineShare（邀请 →
接受/拒绝 → 吊销），协议字段使用官方客户端既有的共享能力（`Node.Sharer`、
`Hostinfo.ShareeNode`、`SelfNodeV4/V6MasqAddrForThisPeer`），不新增兼容协议。

### 38.1 模型与身份

```text
Share = (id, source_org, source_node, target_org, provider, subject,
         status, created_by, created_at, accepted_at, accepted_by, ...)
status ∈ pending | accepted | rejected | revoked
```

- 目标身份键是 **(target_org, provider_id, subject)**（AGENTS §6）。provider/subject
  只有在组织内才唯一（不同组织可以用同名 provider），因此目标组织必须在创建时
  明确给出并校验存在；`local` provider 不可作为共享目标（它是每组织内置身份，
  不是全局身份）。
- 共享对象是一个节点；创建者是源组织内有 write 角色的用户，创建动作进入源组织
  审计（`share.created`）。
- 接受者必须是目标组织内、其 `external_identities` 含 `(provider, subject)` 的
  已登录用户；接受后绑定 `(target_org, target_user)`，之后创建者不能再改目标。
  接受/拒绝/吊销分别审计 `share.accepted` / `share.rejected` / `share.revoked`。
- 终态：rejected、revoked。接受后再吊销合法；对终态重复动作幂等或 409（见 38.3）。

### 38.2 持久化与启用

- 平台级 SQLite `shares.db`（`-platform-state-dir` 下，与 `platform.db` 同级）；
  打开它才启用共享（`meta.sharingEnabled`）。没有平台状态目录的部署不启用：
  共享需要能在一个权威表里看到多个组织，不能用某个组织的本地表代替（AGENTS §9）。
- 参与共享的组织必须在同一个 Router 进程内（v1）：v1 不做跨实例节点快照读取，
  也不做跨实例通知；两个组织分属不同实例时共享不生效（文档明示）。
- 每组织在**自己的**身份库里保存共享命名空间（38.4），与平台 `shares.db` 分开：
  一个记录"谁共享了什么"，一个记录"本组织用哪些合成 ID/地址展示外来节点"。

### 38.3 HTTP API 与 Console

`/api/v2/shares`（read scope 读、write scope 写）：

- `GET /api/v2/shares?direction=outgoing|incoming`（默认 outgoing）：outgoing 是
  本组织创建的共享（任意状态）；incoming 是目标身份匹配调用者的共享。未知
  direction `400`（fail-closed）。
- `POST /api/v2/shares` `{node, targetOrganization, provider, subject}`：创建
  pending 共享；`node` 接受节点 id 或 stable ID（未知 → 404）；目标组织不存在
  → 404；provider 为 `local`、字段缺失、目标就是源组织 → 400；重复的
  (source_node, target_org, provider, subject) 且未终态 → 409。
- `GET /api/v2/shares/{id}`：两侧都可读（不属于自己的共享 → 404，不泄漏存在性）。
- `POST /api/v2/shares/{id}/accept`、`/reject`：仅目标身份匹配者可调用（否则
  404/403 按"不属于我"处理）；对非 pending 状态 `409`。
- `DELETE /api/v2/shares/{id}`：源组织（write）或目标用户可调用；pending 直接
  进入 revoked；accepted 后吊销立即生效（38.4 的暴露随之消失）；重复吊销幂等。

gRPC 面 v1 不做（与 §36 同理：管理面走 HTTP/Console；自动化可用 API key 调
v2）。Console `/console/shares`（nav "Shares"）：outgoing/incoming 两个表、
创建表单（节点 + 目标组织 + provider + subject）、accept/reject/revoke 按钮，
全部 write+CSRF，页面不显示任何密钥材料。

### 38.4 网图暴露（masquerade）

共享被接受后，两个组织的网图**只在相关节点之间**发生变化，且不泄漏真实地址与
ID：

- 目标组织的接收用户 U 的每个节点，网图里出现被共享节点 Y：地址是 Y 在**目标
  组织地址空间**里的合成 masquerade 地址（IPv4 `100.127.0.0/16`、IPv6
  `fd7a:115c:a1e0:ffff::/64` 内顺序分配，每个组织自己的表，重启不丢）；`Node.ID`
  是目标组织的合成节点 ID，`Node.User` 是目标组织为"Y 的所有者/共享者"分配的
  合成用户 ID；`UserProfiles` 提供对应合成档案（DisplayName 来自源组织，v1 不
  暴露邮箱/头像）。`Node.StableID` 是"share:" 前缀的合成稳定 ID。
- 源组织里 Y 的网图出现 U 的每个节点 X：地址是 X 在**源组织地址空间**里的合成
  masquerade 地址；X 的 `Hostinfo.ShareeNode = true`（官方客户端据此在 `status`
  默认隐藏）；`Node.Sharer`/`Node.User` 用源组织的合成用户 ID。
- 双向的 `SelfNodeV4/V6MasqAddrForThisPeer` 都设置为对端在本组织网图里的 masq
  地址，使官方客户端的 tstun/routemanager 完成 SNAT/DNAT（capver ≥ 104，Xunara
  的最低支持版本 115，满足）。
- 合成 ID 基数：节点 `1<<40`，用户 `1<<41`（顺序分配；避开本地小 ID 与
  `TaggedDevicesUserID`）。节点地址分配器**跳过**上面两个 masq 段，防止与真实
  节点地址冲突（状态库与身份库的分配器都要跳过）。
- 不暴露：源组织的真实 IP、节点数字 ID、tags、CapMap、`KeySignature`/TKA 信息、
  子网路由与 exit node（`AllowedIPs` 只有 masq 单地址）；MagicDNS 名用
  `<hostname>.<source-org>.share.<目标组织 magic domain>`，避免与本地主机名冲突，
  也不暴露源组织 magic domain。
- 共享不改变任何"本地"节点：只有被共享节点与接收用户的节点互相出现在对方网图
  里，第三方节点看不到任何变化。
- 命名空间（合成 ID/地址）在吊销后保留以便重新接受时稳定复用；v1 不做回收。

### 38.5 策略与 ACL

- 接收方组织的 packet filter 决定"接收用户节点 ↔ 被共享节点"的放行；共享节点
  在评估里是**无 tag 节点**（因此 `*`、`autogroup:member` 可匹配它），但没有
  本地用户的登录名，`autogroup:self`、`user:`、`group:` 不匹配。源组织的策略对
  源侧同样生效。默认（无策略文档）仍是 allow-all，与官方"无策略 tailnet"一致。
- 共享不产生传递可达性：接收用户的其他节点、源组织的其他节点都不会因为共享出现
  在彼此的网图里。
- **TKA 边界**：任一组织启用 tailnet lock 时，创建/接受共享返回 409（v1 不支持
  在锁定尾网里共享外来节点：外来节点没有本尾网的签名，客户端会把它当作 unsigned
  并拒绝）。

### 38.6 通知与失效

- 共享创建/接受/拒绝/吊销后，两侧组织的 netmap watcher 都被唤醒（同进程内直
  接调用），客户端无需重连即可看到对等体增减。
- 被共享节点的状态变化（endpoints/hostinfo/在线状态/删除）同样唤醒目标组织里
  有已接受共享的接收用户所在组织的 watcher；反向亦然。实现由
  `control/shares.go` 的 `notifyNodePeers` 承担：记录 MapRequest、注册/轮换/
  过期调整、服务声明、健康摘除与节点删除都经它通知，接收侧按
  (SourceOrg, SourceNode) 与 (TargetOrg, TargetUser) 两个方向查
  `shares` 表后唤醒对侧。v1 是"尽力而为"的同进程通知：跨实例不传播
  （38.2 已限定同 Router），客户端重连时总能拿到最新网图。
- 节点删除：共享记录保留，网图里不再出现该节点（视同不可用）；Console 显示为
  missing。

### 38.7 明确不做（v1）

- 跨 Router/多实例共享、共享给整个组织、邀请链接/token、邮件通知；
- 子网路由/exit node/服务 VIP 的共享；per-port/per-路径范围；
- tag 暴露与 `CapMap`（Taildrive、Funnel、Serve 等能力不传递）；
- TKA 环境下的共享；共享审计/日志内容的跨租户读取；
- 共享命名空间的回收/复用统计（38.4 的保留策略是刻意的）。

### 38.8 测试

- `control/share_registry_test.go`：状态机（pending→accepted/rejected、吊销
  幂等、终态 409）、唯一性冲突、按目标身份查询、重启后仍在。
- `control/api_v2_shares_test.go`：两端可见性、fail-closed 过滤、未知 direction
  400、非目标身份 accept 404、重复创建 409、吊销后网图对等体消失。
- `control/shares_netmap_test.go`：合成 ID/地址的稳定性与唯一性、masq 双向一致、
  不泄漏真实 IP/tags/ID、`ShareeNode` 标记、第三方节点不受影响、吊销后消失、
  重启后不变、TKA/单组织等拒绝路径。
- `state`/`identity`：分配器跳过 masq 段。

---

## 39. Xunara Security Center（只读，v1）

目标：把分散在各面的安全姿态聚合成**一个快照 + 一组可执行发现**，管理员不必
逐页翻查就知道 tailnet 现在处于什么状态、下一步该修什么。只读、不新增存储、
不产生新的密钥材料（AGENTS §8/§18）。

### 39.1 数据来源与判据（全部来自现有状态）

快照 `GET /api/v2/security`（read scope）与 Console `/console/security`
（nav "Security"，任意角色可看）渲染同一份视图：

- `tailnetLock`：`s.TKAStatus()` 的 everEnabled/enabled/disabled/head 与
  signed/unsigned/total 节点计数（§§ 见 `control/tka_status.go`）。
- `policy`：`policyView()` 的 configured（是否有文档）、ruleCount、
  warningCount、unsupportedCount、loadError 是否存在；不复制 ACL 内容。
- `nodes`：total、online（持有 poll 会话）、expired（`Expiry` 非零且已过）、
  expiringSoon（30 天内到期）、unsigned（无 `KeySignature`）、tagged、
  untagged、ephemeral、exitNodes（已批准默认路由的节点）计数。
- `devices`：pending = `ListPendingDeviceAuthorizations(now)` 数量。
- `authKeys`：total、expired、unused（单次未用；可复用键不计）。
- `apiKeys`（Service Identity）：total、live、revoked、expired、
  neverExpires（live 且无过期时间，按 owner 角色可写时才是高危信号，v1 只
  报告计数）。
- `sharing`：enabled（平台注册表已接线）；启用时给 outgoing/incoming 的
  pending/accepted 计数（按本组织为源或目标），未启用时 enabled=false 且
  零计数，不查库。
- `webhooks`：configured（启动配置数）、managedEnabled/managedPaused
  （托管端点）、enabled（`webhooksEnabled()`：是否存在会投递的端点）。
- `derp`：mapConfigured、policy（模式）、regionsServed（与 meta 同口径）。

SSH 检查会话已有自己的只读管理面（§35），安全快照不重复统计，避免"总数"在
分页语义下失真。

### 39.2 findings（发现）

`findings` 是按 severity 排序的数组，每项 `{id, severity, title, detail}`。
severity ∈ `high | medium | low | info`；同 severity 内按 id 排序，结果稳定。
判据必须来自上面的确定状态，不做猜测、不做启发式评分：

- `policy.absent`（high）：没有策略文档 → allow-all，每个节点都能互访。
- `policy.load_error`（high）：策略文件已无法解析，仍在执行上一份好文档。
- `tka.unsigned_nodes`（high）：TKA 已启用但仍有未签名节点（这些节点会被
  对端拒绝，且说明锁定未完成）。
- `nodes.expired_keys`（medium）：存在密钥已过期的节点。
- `apikeys.never_expires`（low）：存在无过期时间的 live API key（凭据轮换
  提示；只报数量，不报 key 名/ID）。
- `nodes.keys_expiring`（low）：存在 30 天内过期的节点密钥。
- `devices.pending`（info）：有待批准的设备授权在等待处理。

v1 明确不产生"评分"：没有 0–100 分、没有风险等级合成，避免用不可审计的
数字替管理员做决定。

### 39.3 HTTP 与 Console

- HTTP `GET /api/v2/security`：read scope；响应只含计数、布尔、告警来源摘要
  （策略 load error 的文本来自本地文件解析，属于管理员可见的配置错误，不是
  密钥材料）。不启用 gRPC（与 §31/§33/§35 同理：只读管理面走 HTTP/Console）。
- Console `/console/security`：概览卡片（锁定/策略/节点/设备/密钥/共享）、
  findings 列表（高→低）、节点密钥到期表（最多 200 行，按到期时间升序）、
  可复用键/API key 计数。页面不显示任何 token、secret 或节点密钥。
- `meta` 不新增字段：页面永远可用，没有"未启用"一说；页面在无策略文档时
  恰好在教管理员为什么 allow-all 是一个发现。

### 39.4 明确不做（v1）

- 实时监控、告警、通知、定期报告、指标导出；
- 漏洞扫描、配置基线评分、合规框架映射；
- 按流日志、包内容、连接审计（不在控制面数据模型内）；
- 任何写操作（签名节点、轮换密钥、吊销凭据等仍走既有管理面/CLI）；
- 跨组织聚合（每个组织只看自己的快照；平台 operator 视图不在 v1）。

### 39.5 测试

- `control/security_test.go`：
  - 裸服务器：policy.absent、devices.pending 按需出现，feature 计数为零，
    findings 顺序稳定（high→medium→low→info）；
  - 种子节点覆盖 online/expired/expiringSoon/unsigned/tagged/ephemeral/
    exit node 计数；
  - 配置策略后 policy.load_error 与 warning 计数；
  - TKA 启用 + 未签名节点 → high finding；全部签名后消失；
  - live 且无过期的 API key → apikeys.never_expires；
  - 共享启用时计数正确、未启用时 enabled=false 且不查询注册表；
  - HTTP：匿名 401、read scope 200、响应不含 secret/密钥材料；
  - Console：页面渲染 findings、任意角色可读、无表单/POST 入口。

---

## 40. Xunara Horizon 管理面（Exit Nodes，只读，v1）

目标：把 exit node 的"供给"和"消费"放在一个面上——哪些节点被批准为 exit
node、每台正在被哪些节点使用、哪些选择已经失效。只读；批准/撤回仍在
Machines 面（路由审批），选择 exit node 永远在客户端本地（`ipn.Prefs`），
控制面不远程改客户端的出口选择。

### 40.1 数据模型与判据

- exit node：`ApprovedRoutes` 含默认路由（`0.0.0.0/0` 或 `::/0`）的节点；
  批准是控制面的授权事实。节点是否**正在广播**默认路由单独报告
  （`announced`），因此"已批准但不再广播"会在表里显示为异常，而不是消失。
- 使用关系：官方客户端在 `Hostinfo.ExitNodeID` 上报当前选择的 exit node
  **stable ID**（upstream `ipn/ipnlocal` 明确该字段告知控制面选择，见
  reference）。控制面按 stable ID 把客户端归到 exit node 下。
- 选择可能失效：客户端选中的 stable ID 已不是批准的 exit node（撤回、删除、
  或换机）。这类选择标记为 `resolved=false`，仍然列出（fail-visible），
  控制台显示为 unresolved，而不是静默丢弃。
- 一个节点没有选择 exit node 时不出现在 clients 列表（不占位）。

### 40.2 HTTP 与 Console

`GET /api/v2/exit-nodes`（read scope）：

```text
{
  "exitNodes": [
    { nodeId, stableId, hostname, owner, online, announced, ipv4, ipv6,
      derpHome, lastSeen, clientCount,
      clients: [ { nodeId, stableId, hostname, owner, online } ] }
  ],
  "clients": [
    { nodeId, stableId, hostname, owner, online,
      exitNodeStableId, exitNodeHostname, resolved }
  ]
}
```

- `exitNodes` 按 nodeId 升序；`clients` 按 nodeId 升序（全体有选择的关系）。
- owner 是 login name；不返回节点密钥、地址以外的网络细节或任何 secret。
- gRPC 不做（只读管理面走 HTTP/Console，与 §31/§33/§35/§39 同构）。

Console `/console/exit-nodes`（nav "Exit nodes"，任意角色可看）：

- Exit nodes 表：节点/所有者/在线/地址/DERP home/客户端数与被使用列表；
- Clients 表：节点/所有者/在线/选中的 exit node（hostname + stable ID）/状态
  （resolved 或 unresolved）；
- 无表单、无写入口；批准/撤回路由仍在 Machines 页。

### 40.3 明确不做（v1）

- 远程为节点选择/取消 exit node（客户端本地偏好，控制面只读）；
- exit node 的流量统计、带宽、按流日志（控制面没有数据面遥测）；
- 出口节点的高可用/自动选择/故障转移（客户端能力，控制面不参与）；
- MagicDNS 层面的 exit 策略、per-app 分流（均为客户端功能）。

### 40.4 测试

- `control/exit_nodes_test.go`：
  - 批准默认路由的节点进入 exitNodes；未批准/已撤回的节点不进入；
  - `Hostinfo.ExitNodeID` 把客户端归到对应 exit node，clientCount 正确；
  - 选择未知 stable ID（已删除/未批准）→ clients 中 resolved=false；
  - 撤回默认路由后，原使用关系变为 unresolved，exitNodes 消失；
  - 没有选择的节点不出现在 clients；
  - HTTP：匿名 401、read scope 200、member 可读；响应不含密钥材料；
  - Console：页面渲染两个表、无表单、member 可读。

---

## 41. Xunara 设备授权管理面（v1）

目标：把"等待批准的设备"从浏览器页面变成可审计、可自动化的 API 面。设备授权
是机器身份的准入环节：客户端在注册时提交 `(machine key, node key)` 对，人在此
确认"这台机器可以被接入"，而不是把自己的身份变成机器身份（AGENTS.md §5）。

### 41.1 身份与决策语义

- 每个待批准项是一条 `DeviceAuthorization`：key 对在注册时提交并落库，审批
  **只**作用于该行。
- 审批请求只携带授权 ID，不携带任何 key；审批从存储行读取 key 对，因此 API
  调用者不能替换成自己指定的 key 对（AGENTS.md §10/§11）。
- 批准把机器归属到**调用者**：会话 cookie 或 API key 的所有者成为节点 owner
  （与 `/register/{authID}` 页面、Console 一致）。审批不创建人类身份。
- User Approval 不引入新的存储：OIDC 用户在首次登录时自动建立（§21），角色
  管理在 Users 面（§23）与 `/api/v2/organization`；没有"用户审批队列"这种
  东西，也不得从邮箱推导机器信任（§5/§6）。
- 决策与既有入口（Console、`/register/{authID}`、v1 API）共享同一服务函数与
  审计；重复同向决策幂等，反向决策冲突，过期 fail-closed。

### 41.2 HTTP 与 Console

`GET /api/v2/devices`（read scope）：

```text
{
  "devices": [
    { id, hostname, os, ephemeral?, requestedTags?, created, expires }
  ],
  "truncated": false
}
```

- 只列 pending 且未过期的授权，最新在前；响应上限 500 条，超出时
  `truncated=true`——被截断的是最旧的、最不可能还能被处理的条目。
- **不返回 machine key / node key**：审批不需要 key 材料（v1
  `GET /api/v1/devices` 的稳定形状不在本面改变）。`requestedTags` 与
  `ephemeral` 是客户端对策略的声明，审批人需要看到；hostname/os 为空时原样
  返回空串，显示层再兜底。
- `POST /api/v2/devices/{id}/approve`、`POST /api/v2/devices/{id}/deny`
  （write scope + 可写角色）：返回 `{id, state}`。
  - 未知 ID → 404；已过期 → 410；已决定后的反向决策 → 409；重复同向决策 →
    200（幂等）；
  - 批准创建/原地轮换节点并唤醒等待中的注册（既有 `approveDevice`）；
  - 拒绝只记录状态并唤醒注册，使客户端尽快得到失败（既有 `denyDevice`）。
- 审计复用既有动作：批准记 `node.approved`（节点存在时）、拒绝记
  `device.denied`；actor 是调用者（会话或 `user:N/apikey:key-X`）。
- Console `/console/devices` 不变：与 API 共用列表构造与决策函数，避免两处
  口径漂移。

### 41.3 明确不做（v1）

- 不做批量审批、审批规则引擎或自动批准（自动化必须显式调用 API）；
- 不返回或接受 key 材料，不允许调用者指定 key、地址或节点 ID；
- 不提供"以他人身份批准"，也不提供批准后的所有权转移；
- 不做用户审批队列、邀请制注册、邮箱验证（人类身份来自 OIDC，见 §21）；
- 不做 gRPC（管理面走 HTTP/Console，与 §31/§33/§35/§39/§40 同构）。

### 41.4 测试

- `control/devices_test.go`：
  - 匿名 401；read scope 列表 200 且 member 可读；
  - 列表不泄漏 key 材料（原始响应不含 machine/node key 值）；
  - read scope 决策 403；member 写 scope 403；可写角色 200；
  - 批准创建节点、owner 记为调用者、重复批准幂等、审计归属 API key；
  - 拒绝 200 且状态落库，之后列表不再包含该设备；
  - 未知 ID 404、已过期 410、已批准后拒绝 409；
  - 超过上限时 `truncated=true` 且保留最新。

---

## 42. Xunara Relay 管理面（Peer Relay，只读，v1）

目标：把 peer relay（上游 mesh extension）的"供给"与"授权"放在一个面上——
哪些节点愿意作为 underlay UDP relay、哪些 ACL grant 允许谁从谁那里分配 relay
端点、以及两者是否对得上。只读；是否启用 relay server 与是否使用 relay 都是
客户端本地决定（`ipn.Prefs`），控制面不远程开关、也不替客户端选择 relay。

参考：`reference/headscale` 的 relay cap 编译与集成测试（`PeerRelay` 形如
`{ip}:{port}:vni:{vni}`）、`tailscale.com/tailcfg` 的
`PeerCapabilityRelay` / `PeerCapabilityRelayTarget` 与
`nodecap.DisableRelayServer` / `DisableRelayClient`。

### 42.1 数据模型与判据

- **供给**：节点在 `Hostinfo.PeerRelay` 上报它愿意运行 relay server
  （客户端 `tailscale set --relay-server-port=<port>` 的结果）。控制面只报告
  这个事实。
- **授权**：`grants` 行的 `app` 含 `tailscale.com/cap/relay` 时，该行是 relay
  授权：`src` 命中的节点可以从 `dst` 命中的节点分配 relay 端点。编译结果就是
  既有的 `tailcfg.FilterRule.CapGrant`（`grants.go`），并伴随一条反向
  companion 规则（反向节点获得 `tailscale.com/cap/relay-target`）。本面不改变
  任何 wire 输出。
- **策略开关**：`nodeAttrs` 的 `disable-relay-server` / `disable-relay-client`
  按上游语义透传到 `NodeCapMap`（self 侧生效），本面把它显示为
  `disabled` / `clientDisabled`，因为这是 grant 无法生效的原因。
- 三个事实互相独立：愿意供给 ≠ 被 grant 点名 ≠ 允许供给。管理面把它们并排
  显示，让"grant 指向一个不供给或已被禁用的节点"这类配置错误可见（fail
  visible），而不是替管理员纠正。

### 42.2 HTTP 与 Console

`GET /api/v2/relays`（read scope）：

```text
{
  "relays": [
    { nodeId, stableId, hostname, owner, online,
      announced, disabled, clientDisabled, targeted }
  ],
  "grants": [
    { sources: [ {nodeId, stableId, hostname, owner, online, announced,
                  disabled, clientDisabled, targeted} ],
      targets: [ … ] }
  ]
}
```

- `relays` = 上报了 `PeerRelay` 的节点 ∪ 被任一 relay grant 点名的节点，按
  nodeId 升序；未被点名且未上报的节点不出现。
- `grants` = 文档中带 relay cap 的 `grants` 行，按文档顺序，两侧都解析成节点；
  `dst: ["autogroup:self"]` 按源节点展开（每个源只能用自己的设备）。解析不到
  任何源或目标的行使整个关系为空，不列出。
- 不返回节点密钥、relay 端点、VNI 或任何流量信息；控制面没有数据面遥测。
- gRPC 不做（只读管理面走 HTTP/Console，与 §31/§33/§35/§39/§40/§41 同构）。

Console `/console/relays`（nav "Relays"，任意角色可看）：

- Relay candidates 表：节点/所有者/在线/是否上报供给/`disable-relay-server`/
  `disable-relay-client`/是否被 grant 点名；
- Relay grants 表：源 → 目标，目标旁标注"未上报供给"或"已被禁用"；
- 无表单、无写入口；页面在无供给或无 grant 时说明如何启用与如何书写授权。

### 42.3 明确不做（v1）

- 远程启用/禁用 relay server 或 relay client（客户端偏好与 nodeAttrs 决定）；
- 远程选择 relay、分配/释放 relay 端点、查看 VNI 或 relay 会话（数据面行为，
  控制面不参与）；
- relay 流量统计、带宽、按流日志（控制面没有数据面遥测，见 §39.4/§40.3）；
- 自动为没有 grant 的节点生成 relay 授权（策略必须显式书写）。

### 42.4 测试

- `policy/relay_test.go`：
  - relay grant 编译为 `CapGrant`（`tailscale.com/cap/relay`）并为目标节点生成
    `relay-target` companion 规则；客户端只匹配以自己为源的规则；
  - `RelayGrants` 只报告 relay 行（其他 app cap 不算）、selector 解析为节点、
    空关系被丢弃；
  - `dst: autogroup:self` 按源用户展开，tagged 节点不作为源也不作为目标。
- `control/relays_test.go`：
  - 视图区分"启用/被禁用/仅愿意/grant 源/无关"五种姿态；
  - `disable-relay-client` 在源侧可见、`disable-relay-server` 在目标侧可见；
  - HTTP：匿名 401、read scope 200、member 可读；
  - Console：两个表、跨角色可读、无表单；
  - 兼容性：真实客户端路径下 relay grant 进入 `PacketFilters.base`、
    `disable-relay-*` 进入 self 的 `CapMap`、peer 的 `PeerRelay` 供给可见。

---

## 43. Xunara Serve / Funnel 管理面（只读，v1）

目标：把 tailnet 的 HTTPS 发布能力放到一个面上——哪些设备被授权 `tailscale
serve`、证书能不能签发、哪些设备报告了 Funnel 或 ingress 活动。只读：serve
配置在节点本地，控制面只会授予能力与代理 ACME 挑战。

### 43.1 数据模型与判据

- **授权**：策略 `nodeAttrs` 的 `https` → `tailcfg.CapabilityHTTPS` 进入节点
  CapMap，是 `tailscale serve` 在设备上能被启用的前提（§M6b/M6f）。
- **证书**：配置 DNS provider 后控制面为节点代写 `_acme-challenge` TXT（DNS-01，
  私钥与 CSR 始终留在客户端），并按 `certDomainsFor` 下发 `CertDomains`；没有
  provider 时客户端报告"证书不支持"，serve 无法完成 TLS。
- **Funnel**：需要公网 ingress，本构建不运营；策略加载即拒绝 `funnel` 属性，
  任何 netmap 都不会授予它。设备仍可能上报 `Hostinfo.IngressEnabled` 或
  `WireIngress`（例如手工配置），管理面把这类报告按事实显示为异常，而不是
  静默丢弃或假装支持。

### 43.2 HTTP 与 Console

`GET /api/v2/serve`（read scope）：

```text
{
  "certificates": true,            // 是否配置了 DNS provider
  "certDomains": ["extra.example.com"],
  "funnelSupported": false,        // 本构建恒为 false
  "nodes": [
    { nodeId, stableId, hostname, owner, online,
      serve, funnel, wantsIngress,
      certDomains: ["node.tailnet.example.com", "extra.example.com"] }
  ]
}
```

- `nodes` = 被授予 `https` ∪ 上报 Funnel ∪ 上报 ingress 需求的节点，按 nodeId
  升序；`certDomains` 在该节点无证书能力时为空数组（不是 null）。
- 不返回证书、私钥、ACME 挑战值或任何 DNS 记录内容。
- gRPC 不做（只读管理面走 HTTP/Console，与 §31/§33/§35/§39/§40/§41/§42 同构）。

Console `/console/serve`（nav "Serve"，任意角色可看）：

- 证书状态（是否配置 DNS provider）、附加证书域名、Funnel 明确不支持的说明；
- 节点表：节点/所有者/在线/`https` 授权/可用证书域名/Funnel 与 ingress 报告；
- 无表单、无写入口；serve 配置仍在设备本地。

### 43.3 明确不做（v1）

- 远程开启/停止 serve 或 Funnel、下发 serve 配置（客户端本地状态）；
- 运行公网 ingress、为 Funnel 分配域名/地址（架构排除，策略 fail-closed 拒绝）；
- 证书内容的查看/导出/吊销（私钥从不经过控制面，见 M6f）；
- 按域名/端口的 serve 流量统计（控制面没有数据面遥测）。

### 43.4 测试

- `control/serve_test.go`：
  - `https` 授权、Funnel 报告、ingress 需求、无关节点四种姿态区分；
  - 配置 DNS provider 时 `certificates=true` 且节点证书域名含自身 FQDN 与附加域
    名；未配置时为空数组且页面说明证书不可用；
  - HTTP：匿名 401、read scope 200、member 可读；
  - Console：渲染四种姿态、Funnel 不支持的说明、无表单、跨角色可读。

---

## 44. Flow Logs（明确不做，v1）

目标：记录 _spec §20 P2_ 的 Flow Logs 结论，避免以后把"没做"误读成"漏做"。

- 官方客户端的流日志（`wgengine/netlog`）不是控制面数据：其开启条件是
  self netmap 同时具备 `tailscale.com/cap/data-plane-audit-logs`、
  合法的 `DataPlaneAuditLogID` 与 `DomainAuditLogID`（参考 upstream
  `ipn/ipnlocal` 的 `netLogNodeSource.NetLogIDs`），收集端是 Tailscale 的
  logtail 服务。
- Xunara 从不设置这两个 audit log ID（netmap 里始终为空），因此即使管理员在
  `nodeAttrs` 里写了该能力，客户端的 netlog 也不会启动：不存在"日志被悄悄
  发往第三方"的路径。这是安全决策，不是实现缺口。
- 控制面看不到数据面包，无法从任何既有状态推导按流日志；若要自建收集协议，
  那属于 §19 的 Xunara Pulse（Telemetry）新工作，需要单独的规格（上报协议、
  隐私边界、留存、限额），不在 v1。
- v1 的替代物是控制面审计日志（平台/Console 的 `audit`）与 §39 Security
  Center 的安全姿态快照；§39.4 与 §40.3 同样明确排除按流日志。

---

## 45. Xunara Veil 自动 TLS 证书（ACME TLS-ALPN-01，v1）

目标：消除 M6e 遗留的运维缺口——DERP 服务此前只能手工提供 TLS 证书文件，
续期与轮换全部由操作者负责。Veil 现在可以直接向 Let's Encrypt 申请并自动
续期证书，域名控制权用 **TLS-ALPN-01** 证明：ACME 校验握手复用 DERP 自己的
TLS listener，不需要额外开放 80 端口，也不依赖 DNS provider。

### 45.1 配置与判据

`veil.Config` 新增：

- `CertMode`：`""`（缺省：有 `CertFile`/`CertKeyFile` 等价 `manual`，都没有
  则不服务 TLS）、`manual`、`letsencrypt`；未知值启动即拒绝（fail-closed）。
- `CertDir`：ACME 缓存目录（账号密钥 + 已签发证书），`letsencrypt` 必填；
  目录必须持久化，否则每次重启都会重新向 CA 申请。
- `ACMEEmail`：可选的联系邮箱，仅用于 CA 的证书到期提醒，不写日志。

`letsencrypt` 的启动校验（全部 fail-closed）：

- 必须提供 `CertDir`，且不得与 `CertFile`/`CertKeyFile` 同时出现；
- `HostName` 必须是 FQDN（含点、非 IP、无端口/空白、仅 `[a-z0-9-.]`），
  小写归一化后使用——SNI 与证书名必须与 DERP map 中客户端拨号的域名一致；
- `HostPolicy` 固定为 `autocert.HostWhitelist(host)`：SNI 非配置域名（含空
  SNI、父域）在**任何** ACME 请求之前被拒绝，攻击者无法借本服务对任意域名
  触发签发或消耗 CA 速率限制；
- TLS 最低版本 1.2；证书与账号密钥由 `autocert.DirCache` 以 0600 落盘。

证书续期由 `autocert` 自动执行（默认在 30 天或生命周期 1/3 的较小者之前
续期），失败重试有节流；重启后从 `CertDir` 复用缓存，不重复下单。

### 45.2 CLI 与兼容性

- `cmd/xunara-veil` 新增 `-cert-mode`、`-cert-dir`、`-acme-email`；原
  `-cert-file`/`-cert-key-file` 行为不变（缺省即 manual），`-hostname`
  仍是 map 与证书共用的名字。
- 官方客户端协议不变：DERP upgrade、probe、STUN、mesh 均照旧；新增的 ALPN
  `acme-tls/1` 只在客户端主动提供时协商（即 CA 校验），普通 DERP 客户端
  仍走 `h2`/`http/1.1`。控制面 netmap 无任何改动。

### 45.3 明确不做（v1）

- HTTP-01：不开放 80 端口、不提供明文挑战面；
- DNS-01 自动续期（那是 §M6f 的证书签发路径，私钥在客户端）；
- 通配符证书、多域名 SAN、自定义 ACME directory/CA、EAB（企业 CA）；
- 证书内容查看/导出/吊销（与 §43.3 同口径）。

### 45.4 测试

- `veil/acme_test.go`：
  - 表驱动：无 TLS / manual（缺一文件、显式成对）/ letsencrypt（缺 CertDir、
    与证书文件冲突、缺 HostName、IP、非 FQDN、带端口）/ 未知模式；
  - TLS-ALPN-01 wiring：`NextProtos` 含 `acme.ALPNProto` 与 `http/1.1`；
    空 SNI、其他主机、父域被 HostPolicy 拒绝；
  - 缓存复用路径：向 `DirCache` 播种证书后 `GetCertificate` 直接命中，不发
    任何 ACME 网络请求（模拟重启后的部署）；
  - manual 模式端到端：手工证书起 TLS listener，HEAD `/derp/probe` 通过。

---

## 46. Xunara Atlas 服务可见性（v2）

目标：v1 的服务名对全组织可见（与 MagicDNS 节点名一样，见 §22.7）。v2 允许
发布者给服务声明 **visibility**（发现范围），收紧"谁能解析这个名字"，同时
不改变任何可达性语义——ACL 仍然决定谁能连接（发现不等于授权）。

### 46.1 语义

- 声明字段：`visibility: ["<selector>", ...]`，选择器语法与 ACL 的 **src**
  一致：`*`、`user:<login>`、`group:<name>`、`tag:<tag>`、`autogroup:member`、
  `autogroup:tagged`、`autogroup:self`、`host:<alias>`、IP/前缀。
  `autogroup:internet` 只能作目的端，拒绝。
- 省略/空 = `*`：全组织可见，即 v1 行为（向后兼容）。
- 解析基准是**发布者节点**：`autogroup:self` 指发布者所属用户的设备。
- 发布者永远能发现自己发布的（自己的服务名不因选择器而对自己消失）。
- 影响面只有 MagicDNS 中由 Atlas 注册表派生的 A/AAAA 记录
  （`DNSConfig.ExtraRecords`）。管理面（`/api/v2/services`、gRPC、Console、
  `xunara services`）始终显示真实声明与可见范围；`set-dns` 管理员记录保持
  全局。

### 46.2 校验与失败模式（fail-closed）

- 发布时：选择器必须在**当前加载的策略文档**里可解析（未声明的 tag/group、
  未定义的 host alias、非法前缀、空串、控制字符、超过 16 条/128 字节 → 400）；
  没有策略文档时只接受默认（`*`）。
- 解析时：选择器解析不出任何节点（例如策略变更后 group 被删）→ 该选择器贡献
  空集；若全部选择器都解析不出，服务只对发布者可见。**绝不因为解析失败而扩大
  可见范围。**
- 策略文档被移除（watcher 将引擎置空）→ 受限服务只对发布者可见；默认服务
  不变。
- 健康（§26）与可见性是 AND：不健康先摘除，与可见范围无关。

### 46.3 兼容性

- 官方客户端协议不变：可见性只改变节点自己 netmap 里
  `DNSConfig.ExtraRecords` 的内容；`MapResponse` 结构、TS2021/Noise、ACL
  编译都不动。
- 每个节点本来就收到自己的 `DNSConfig`，逐节点差异是协议内行为；
  `mapSession.dns` 指纹继续保证只在变化时下发。
- 升级：老数据没有 visibility 行（state 迁移 v16 只加表），读出为空 = 默认，
  行为与 v1 完全一致。
- 跨组织（§38 Share）不适用：可见性只在本组织的节点之间判定，共享不会扩展
  服务发现。

### 46.4 与 ACL 派生的取舍

§22.7 的原始设想是"按 ACL/grants 自动收敛（能连才可见）"。v2 选择**发布者
声明**而不是自动派生，理由记录在此，避免以后误读：

- ACL 编译（`FilterFor`）是"按目的节点"展开的，逐服务评估会把
  O(服务 × 规则 × 节点) 摊到每次 map update（`DNSConfig` 在每个 update 帧
  都要重算），在 512 服务上限下不可接受；
- 声明式可见性的成本是 O(服务 × 选择器)，默认值与 v1 一致，升级零风险；
- 发布者最清楚服务面向谁；可见性只影响发现、不扩大任何访问权限，因此把
  "收紧发现"交给发布者不违反零信任（ACL 仍是唯一授权来源）。
- 将来若要做 ACL 自动收敛，必须先解决评估成本（例如按 engine 代际缓存），
  并单独写规格。

### 46.5 测试

- `policy/visibility_test.go`：规范化（排序/去重/空白/控制字符/长度/条数）、
  校验（未声明 tag/group、`autogroup:internet`、其它 autogroup、合法
  user/host/前缀）、解析（`*`/group/tag/`autogroup:self` 随发布者变化/
  未知选择器为空集）。
- `control/service_visibility_test.go`：发布→按节点过滤 MagicDNS（发布者、
  选择器命中者、无关节点）、默认服务全组织可见、netmap 端到端、管理面仍显示
  声明与 `["*"]`、发布校验表（含无策略文档）、策略移除后 fail-closed。
- `client/protocol/validate_test.go`：客户端镜像校验与规范化。
- `state/service_test.go` + `state/sqlite_test.go`：往返、拷贝隔离、
  v15→v16 迁移（老服务读回默认可见性）。
- Console 与 gRPC：服务页与 `ListServices` 渲染 `visibility`。
