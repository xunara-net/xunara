# Xunara · 玄序

Tailscale 兼容的自托管控制面：**官方 Tailscale 客户端无需改动**，把登录地址指向
自己的服务器即可接入；身份、策略、网络与 DERP 中继全部自持。

```bash
tailscale up --login-server=https://control.example.com
```

## 状态

v1 规格范围（M1–M38）已全部实现：`go test ./...` 与关键包的 `go test -race`
通过。规格 [PROJECT_SPEC.md](Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md)、
进度 [ROADMAP.md](ROADMAP.md)、开发约束 [AGENTS.md](AGENTS.md)。

## 能力概览

- **协议兼容**：TS2021 / Noise、`/machine/*` 内层端点、MapRequest/MapResponse
  （含流式长轮询与 zstd）、DERP、node key 轮换、Tailnet Lock（TKA）。
- **身份**：本地账号 / OIDC / Passkey（WebAuthn）；多租户；人类 / 机器 / 服务
  身份分离；Session 支持吊销、过期、轮换，可多实例部署。
- **网络**：MagicDNS、ACL / Grants / nodeAttrs、子网路由与 Exit Node 审批、
  Tailscale SSH（含 check 审批）、设备授权与预认证密钥。
- **扩展**：Atlas 服务发现（健康摘除、Consul/K8s 导入、按选择器收敛的
  MagicDNS 可见范围）、Flux 端到端加密文件投递、Reach 远程命令（目标显式
  审批）、Share 跨组织机器共享、Workload Identity。
- **运维**：Web Console（22 页）、HTTP `/api/v2` + gRPC、Webhooks（签名 + 重试）、
  审计日志、Security Center，以及路由 / DERP / Relay / Serve / Reach / Flux
  等只读管理面。
- **自建 DERP（Veil）**：`/derp` upgrade、probe、STUN、mesh、带宽限速、
  ACME TLS-ALPN-01 自动证书。

## 仓库结构

```text
control/     控制面：Noise/注册/Map、平台 API v1/v2、Console、管理面
control/mapper/ netmap 构建
identity/    身份：用户、Session、OIDC、Passkey、设备授权、审计
policy/      ACL / Grants / SSH / nodeAttrs 编译
state/       节点与协议状态存储（内存 + SQLite）
client/      原生客户端协议、agent 库、flux/reach
cmd/         xunarad（控制面）、xunara（CLI）、xunara-agent（节点）、xunara-veil（DERP）
veil/        自建 DERP 服务
dnsprovider/ ACME DNS-01 的 DNS provider 适配
webhook/     审计事件签名投递
```

## 构建与运行

```bash
go build ./...
go test ./...

# 控制面（示例）
go run ./cmd/xunarad -listen 0.0.0.0:8080 -server-url https://control.example.com -state-dir ./data

# 管理 CLI / 节点 agent / 自建 DERP
go run ./cmd/xunara -h
go run ./cmd/xunara-agent -h
go run ./cmd/xunara-veil -h
```

## 文档

- [PROJECT_SPEC.md](Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md) — 产品与协议规格（§1–§45）
- [ROADMAP.md](ROADMAP.md) — 里程碑与进度（M1–M38）
- [IDENTITY_LOGIN.md](Xunara_AI_Development_Docs_2026-10-05/IDENTITY_LOGIN.md) — 身份与登录设计
- [AGENTS.md](AGENTS.md) — 开发规则与约束

## 明确不做（v1）

公网 Funnel ingress、Flow Logs、官方 Taildrop 互通、ACL `srcPosture` 强制语义、
交互式终端/PTY、告警与合规扫描。

## 许可

暂未选择开源许可证。
