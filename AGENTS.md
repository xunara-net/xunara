# AGENTS.md — Xunara AI Development Rules

## 1. 项目身份

Xunara / 玄序是 Tailscale-compatible Control Plane。

它不是 Headscale + UI，也不是 MirageServer fork。

第一目标：

> 保持官方 Tailscale Client compatibility。

## 2. 参考优先级

Protocol：

```text
Tailscale upstream
>
Headscale upstream
>
Xunara
>
MirageServer
```

Product：

```text
Xunara specification
>
MirageServer
>
Tailscale
>
Headscale
```

Identity：

```text
MirageServer
+
Dex
+
go-oidc
+
oauth2
+
WebAuthn
>
Xunara Identity
```

## 3. 严禁猜 API

修改代码前必须：

1. 搜索 symbol
2. 找定义
3. 找调用方
4. 找测试
5. 查 upstream
6. 确认数据流
7. 最小修改
8. 测试

禁止凭印象猜 Tailscale/Headscale API。

## 4. 协议修改

修改以下内容前必须检查 upstream：

```text
TS2021
Noise
MapRequest
MapResponse
NodeKey
MachineKey
DiscoKey
Register
Poll
DNS
DERP
Capabilities
FeatureQuery
```

禁止为了 WebUI、OAuth、Multi-Tenant、Native Client、Funnel 等随意改变兼容协议。

## 5. Identity

永远区分：

```text
Human Identity
Machine Identity
Service Identity
```

禁止：

```text
Google Login → Machine Trusted
Email → Machine Identity
NodeKey → Human User
```

## 6. External Identity

唯一身份键：

```text
(provider_id, subject)
```

Email 只是属性。

## 7. OAuth/OIDC

必须考虑：

```text
state
nonce
PKCE
issuer
audience
signature
exp
iat
redirect_uri
JWKS rotation
clock skew
code replay
state replay
```

Redirect URI 必须 allowlist。

禁止开放重定向。

## 8. Secret Handling

禁止把以下内容放 URL query：

```text
client_secret
appkey
access_token
refresh_token
API secret
```

优先使用：

```text
Authorization header
POST body
secure secret storage
```

HTTP 请求必须：

- 使用 context
- 设置 timeout
- 正确处理 request error
- 正确处理 response
- 避免 secret 写入日志

## 9. Session

不要使用 server-local map 作为核心 Session 存储。

必须考虑：

```text
multi-instance
revocation
expiration
audit
rotation
```

## 10. Device Authorization

必须独立于 OAuth transaction：

```text
AuthTransaction
≠
Session
≠
DeviceAuthorization
```

不要把 OAuth State、User Identity、MachineKey、Organization、Device Approval 全塞进一个 cache struct。

## 11. Machine Identity

至少验证：

```text
MachineKey
NodeKey
Tenant
```

避免简单：

```sql
machine_key = ? OR node_key = ?
```

导致跨租户 identity confusion。

## 12. Multi-Tenant

必须考虑 tenant boundary：

```text
User
Machine
Node
Device
Route
ACL
Grant
Auth Key
API Key
DERP Policy
Service
Share
Audit
```

## 13. Core / Platform

依赖方向：

```text
Platform
    ↓
Core interfaces
```

而不是 Core 依赖 WebUI/具体业务。

## 14. MirageServer 使用规则

允许参考：

- 第三方登录
- Dex / OIDC
- OAuth
- Aggregator
- 微信扫码
- Device Authorization
- Organization/User
- Machine
- Funnel / Share

禁止未经审查直接复制：

```text
stateCodeCache
controlCodeCache
mirage-authstate2
miragecontrol
Email identity
server-local session cache
旧 Machine lookup
```

## 15. 测试

修改 Go 代码后至少：

```bash
go test ./...
go vet ./...
```

涉及并发、Session、Identity、Control Plane：

```bash
go test -race ./...
```

协议修改应增加 compatibility/integration tests。

## 16. 修改原则

```text
small
reviewable
reversible
testable
```

## 17. AI Agent 工作流程

```text
定位模块
  ↓
搜索定义
  ↓
搜索调用链
  ↓
查 upstream
  ↓
查测试
  ↓
建立数据流
  ↓
设计最小修改
  ↓
实现
  ↓
测试
  ↓
总结兼容性影响
```

每次修改说明：

```text
What changed
Why
Compatibility impact
Security impact
Tests
```

## 18. 优先级

```text
Security
>
Protocol Compatibility
>
Data Integrity
>
Architecture
>
Feature Completeness
>
Convenience
```
