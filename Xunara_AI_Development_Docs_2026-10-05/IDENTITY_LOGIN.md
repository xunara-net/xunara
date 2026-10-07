# Xunara Identity & Login Architecture

## 1. 目标

Xunara Identity 是完整 Trust Plane：

```text
Human Identity
Machine Identity
Service Identity
Device Trust
Organization Identity
Cryptographic Trust
```

## 2. 总体结构

```text
                    Xunara Identity
                           │
            ┌──────────────┼──────────────┐
            │              │              │
            ▼              ▼              ▼
       Human Auth      Machine Auth    Service Auth
            │              │              │
     ┌──────┼──────┐       │              │
     │      │      │       │              │
    OIDC   OAuth  Passkey  MachineKey    API Key
     │      │      │       │              │
     └──────┼──────┘       │              │
            ▼              ▼              ▼
       User Identity   Device Identity  Service Identity
            │              │              │
            └──────────────┼──────────────┘
                           ▼
                      Trust Engine
                           │
                           ▼
                     Policy Engine
```

## 3. Provider Adapter

```go
type IdentityProvider interface {
    ID() string
    Begin(context.Context, *AuthTransaction) (*AuthorizationRequest, error)
    Callback(context.Context, *AuthTransaction, *CallbackRequest) (*IdentityResult, error)
}
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

## 4. Provider Registry

```text
Local
Generic OIDC
Google
Microsoft
GitHub
Gitea
Apple
WeChat
WebAuthn
Passkey
External Identity Broker
```

## 5. AuthTransaction

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

生命周期：

```text
Created
  ↓
Redirected
  ↓
Callback
  ↓
Verified
  ↓
Consumed
```

## 6. OIDC Callback

```text
Browser
  ↓
/login
  ↓
Create AuthTransaction
  ↓
state + nonce + PKCE
  ↓
Provider
  ↓
Callback
  ↓
Validate state
  ↓
Exchange code
  ↓
Validate ID Token
  ↓
Extract subject
  ↓
Find/Create User
  ↓
Create Session
```

必须验证：

```text
issuer
audience
signature
nonce
exp
iat
```

## 7. External Identity

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

核心身份键：

```text
provider + subject
```

不能仅使用 Email。

## 8. Account Linking

绑定必须是显式安全操作：

```text
Existing Account
   ↓
Authenticated
   ↓
Add Provider
   ↓
Provider Authentication
   ↓
Confirm
   ↓
Link External Identity
```

不能因为 Email 相同就自动合并。

## 9. Organization Mapping

```text
External Identity
       ↓
User
       ↓
Organization Membership
       ↓
Groups / Roles
       ↓
Policy
```

OIDC groups/roles/tenant 等必须经过明确映射策略。

## 10. MirageServer 参考

仓库：

```text
mirage-008/MirageServer
```

重点源码：

```text
controller/console_auth.go
controller/oidc.go
controller/cockpit_dex_helper.go
controller/cockpit_syscfg_dex.go
controller/config.go
```

相关依赖：

```text
github.com/coreos/go-oidc/v3
golang.org/x/oauth2
github.com/dexidp/dex
github.com/go-webauthn/webauthn
```

涉及：

```text
Microsoft
GitHub
Gitea
Google
Apple
Ali
WeChat Scan
Aggregator
WebAuthn
```

## 11. Mirage Login Flow

```text
Browser
   ↓
/login?provider=...
   ↓
stateCodeCache
   ↓
mirage-authstate2 Cookie
   ↓
Dex / Aggregator / WXScan
   ↓
/a/oauth_response
   ↓
Identity
   ↓
findOrCreateNewUserForOIDCCallback
   ↓
controlCode
   ↓
miragecontrol Cookie
```

可吸收的核心思想：

```text
OAuth transaction ≠ Web session
```

Xunara 正式使用：

```text
AuthTransaction
Session
DeviceAuthorization
```

而不是直接复制 Mirage cache/Cookie 架构。

## 12. External Identity Broker

Aggregator 在 Xunara 中抽象成：

```text
External Identity Broker
```

可连接：

```text
Dex
Keycloak
Authentik
Zitadel
Auth0
Cloudflare Access
Enterprise IdP
```

## 13. WeChat / QR

```text
Browser
   ↓
QR
   ↓
External Provider
   ↓
Verification
   ↓
IdentityResult
   ↓
Xunara Session
```

不修改：

```text
TS2021
Noise
MapRequest
NodeKey
MachineKey protocol
```

## 14. Device Login

```text
Device
  ↓
Machine Registration
  ↓
DeviceAuthorization
  ↓
User Browser
  ↓
Login
  ↓
Review Device
  ↓
Approve
  ↓
Machine Authorized
```

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

## 15. Session

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

Session 不应依赖单机内存 cache。

## 16. Machine Identity

```text
Noise MachineKey
       ↓
candidate nodes
       ↓
exact NodeKey
       ↓
tenant scope
       ↓
Node
```

禁止仅凭 MachineKey OR NodeKey 得出最终身份。

## 17. Service Identity

支持方向：

```text
API Key
mTLS certificate
Workload identity
OIDC workload token
Automation credential
```

## 18. Security Test Matrix

OAuth：

```text
invalid state
replayed state
wrong nonce
wrong issuer
wrong audience
expired token
invalid signature
PKCE mismatch
code replay
```

Redirect：

```text
absolute external URL
javascript:
data:
wrong host
wrong scheme
encoded redirect bypass
```

Identity：

```text
same email / different provider
same subject / different provider
account linking
tenant mismatch
organization mismatch
```

Device：

```text
expired approval
wrong machine key
wrong node key
wrong tenant
duplicate approval
replay approval
revoked device
```

Session：

```text
expired session
revoked session
session fixation
cross-tenant session
parallel logout
```

## 19. 最终认证链路

```text
Provider
   ↓
AuthTransaction
   ↓
External Identity
   ↓
User
   ↓
Organization
   ↓
Session
   ↓
Device Authorization
   ↓
Machine Identity
   ↓
Trust Engine
   ↓
Policy Engine
```
