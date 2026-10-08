# Xunara · 玄序（已迁移 · 只保留历史）

> **本仓库（`xunara-net/xunara`）已停止开发。** 项目按规范重构为 GitHub Organization
> 多仓库结构，代码、文档与部署都在新仓库继续演进；这里只保留迁移前的提交历史。

## 现在的仓库

| 仓库 | 职责 |
|---|---|
| [xunara-server](https://github.com/xunara-net/xunara-server) | Tailscale 兼容控制面 + 产品 API（用户/组织/套餐/审计），不含 Web UI |
| [xunara-web](https://github.com/xunara-net/xunara-web) | 用户控制台（Vue 3 + TypeScript） |
| [xunara-admin](https://github.com/xunara-net/xunara-admin) | 超级管理员后台（Vue 3 + TypeScript） |
| [xunara-relay](https://github.com/xunara-net/xunara-relay) | DERP/STUN 中继、托管注册、限速与远程配置 |
| [xunara-deploy](https://github.com/xunara-net/xunara-deploy) | systemd / nginx 同源 / Docker Compose 部署 |
| [xunara-docs](https://github.com/xunara-net/xunara-docs) | 文档中心：规范全文、架构、ADR、运维、安全、手册 |

依赖方向：`web/admin → server`、`relay → server`、`deploy → 全部`，不允许循环依赖。

## 从这个仓库迁移走了什么

```text
本仓库（旧单仓）                      迁移目标
├── control/ cmd/  identity/ state/ …  → xunara-server
├── veil/ cmd/xunara-veil              → xunara-relay（二进制更名 xunara-relay）
├── 内嵌 Web Console / Admin 页面       → xunara-web / xunara-admin（Vue 3 重写）
├── deploy/                            → xunara-deploy
└── 规格与文档                          → xunara-docs
```

原内嵌控制台（`/console` 服务端渲染页面）在 `xunara-server` 中仍作为过渡保留，
待 `xunara-web` 功能对等后删除（见
[ADR-0003](https://github.com/xunara-net/xunara-server/blob/main/docs/adr/ADR-0003-server-web-split.md)）。

## 从这里开始

- 想读规范：[xunara-docs](https://github.com/xunara-net/xunara-docs)
  （《AI 长期开发与架构规范》《GitHub 多仓库与中继生态补充规范》全文）
- 想部署：[xunara-deploy](https://github.com/xunara-net/xunara-deploy)
- 想看控制面：[xunara-server](https://github.com/xunara-net/xunara-server)
- 想看前端：[xunara-web](https://github.com/xunara-net/xunara-web) ·
  [xunara-admin](https://github.com/xunara-net/xunara-admin)
- 想看中继：[xunara-relay](https://github.com/xunara-net/xunara-relay)

## 关于本仓库的代码

本仓库代码停留在拆分前状态，**不要**在这里提交功能或修复：新的 `go.mod` module 路径
是 `github.com/xunara-net/xunara-server`，部署脚本、前端与规范也已分仓，直接复用
旧代码会导致版本不一致。需要旧行为作参考时，请用 `git log` 查阅历史。

```bash
tailscale up --login-server=https://control.example.com
```
