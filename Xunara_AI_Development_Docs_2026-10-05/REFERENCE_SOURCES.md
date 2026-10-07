# Xunara Reference Sources

## 1. Tailscale

https://github.com/tailscale/tailscale

用途：

- 官方客户端行为
- TS2021
- Noise
- MapRequest / MapResponse
- MachineKey / NodeKey / DiscoKey
- DERP
- DNS
- Grants
- Device posture
- Funnel / Serve
- Tailnet Lock
- Exit Nodes
- Site-to-site
- API
- Taildrive / Taildrop

> Tailscale upstream 是协议兼容性的最高参考。

## 2. Headscale

https://github.com/juanfont/headscale

用途：

- 开源 Control Plane
- Tailscale compatibility
- `/key`
- `/ts2021`
- `/api/v1`
- `/api/v2`
- Poll
- MapSession
- Node database
- ACL / Policy
- DERP

重点：

```text
hscontrol/
├── app.go
├── noise.go
├── poll.go
└── db/
    └── node.go
```

> Headscale 是 Xunara 的核心工程参考，但不是最终产品边界。

## 3. MirageServer

https://github.com/mirage-008/MirageServer

用途：

- Web Console
- Organization
- User
- Machine
- Device registration
- Third-party login
- Dex
- OIDC
- OAuth
- Aggregator
- WeChat Scan
- WebAuthn
- Funnel
- Sharing

重点：

```text
controller/console_auth.go
controller/oidc.go
controller/cockpit_dex_helper.go
controller/cockpit_syscfg_dex.go
controller/config.go
```

## 4. MirageNetwork/MirageServer

https://github.com/MirageNetwork/MirageServer

用途：

- 当前协议实现参考
- Machine / Organization
- Noise
- Funnel
- Share
- Console
- Cockpit

重点安全经验：

```text
Noise identity binding
MachineKey uniqueness
Noise Map authorization
Tenant boundary
Username validation
Route overlap
Funnel security
```

## 5. go-oidc

https://github.com/coreos/go-oidc

用于：

```text
OIDC discovery
ID Token verification
JWKS
claims
issuer
audience
nonce
```

## 6. OAuth2

https://github.com/golang/oauth2

用于：

```text
Authorization Code
PKCE
Token exchange
OAuth client
```

## 7. Dex

https://github.com/dexidp/dex

用于：

```text
Identity Broker
Connector
OIDC
GitHub
Microsoft
Google
LDAP
SAML
```

Xunara 可以将 Dex 作为外部 Identity Broker，而不是让 Core 强耦合 Dex。

## 8. WebAuthn

https://github.com/go-webauthn/webauthn

用于：

```text
WebAuthn
Passkey
Hardware-backed authentication
```

## 9. 阅读顺序

首次进入项目：

```text
1. Tailscale
2. Headscale
3. MirageNetwork/MirageServer
4. mirage-008/MirageServer
5. go-oidc
6. oauth2
7. Dex
8. WebAuthn
```

Protocol 任务：

```text
Tailscale
   ↓
Headscale
   ↓
Xunara Compatibility Core
```

Identity 任务：

```text
Mirage console_auth.go
        ↓
Mirage oidc.go
        ↓
Dex helper
        ↓
go-oidc
        ↓
oauth2
        ↓
Xunara Identity
```

不要用 Mirage 定义 Tailscale 协议。

## 10. 关键设计结论

### Protocol 与 Platform 分离

```text
TS2021 / Noise / Map
        ↓
Compatibility Core
        ↓
Platform
```

### Human 与 Machine 分离

```text
Human Authentication
        ↓
User / Session
```

与：

```text
Machine Registration
        ↓
MachineKey / NodeKey
```

分离。

### Email 不是 Identity Key

必须：

```text
provider + subject
```

而不是：

```text
email
```

### OAuth Transaction / Session / Device Authorization 分离

```text
AuthTransaction
      ≠
Session
      ≠
DeviceAuthorization
```

### Aggregator → External Identity Broker

统一接入：

```text
Dex
Keycloak
Authentik
Zitadel
Auth0
Enterprise IdP
```

## 11. 最终架构

```text
                         Xunara
                           │
                    Compatibility Core
                           │
                 ┌─────────┴─────────┐
                 │                   │
              Network             Identity
                 │                   │
              Tailnet              Trust
                 │                   │
                 └─────────┬─────────┘
                           │
                       Policy
                           │
          ┌────────────────┼────────────────┐
          │                │                │
        Service         Application        Data
          │                │                │
        Remote            Mesh            Files
          │                │                │
          └────────────────┼────────────────┘
                           │
                     Xunara Platform
```

核心定位：

> Identity + Network + Service + Application + Data Control Plane
