# Xunara — 开发路线图

> 定位与约束见 `AGENTS.md`、`PROJECT_SPEC.md`。本文件只描述**进度与下一步**。

## 约定（继续开发前先读）

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/xunara/xunara` |
| Go 版本 | `go 1.27.1`（`GOTOOLCHAIN=auto` 自动下载，已验证） |
| 关键依赖 | `tailscale.com v1.104.0`、`github.com/go-chi/chi/v5` |
| 上游参考 | `reference/`（tailscale / headscale / 两个 MirageServer / go-oidc / oauth2 / dex / webauthn） |
| 提交策略 | 每个里程碑 `small / reviewable / reversible / testable` |

常用命令：

```bash
go build ./...
go vet ./...
go test ./state/... ./control/... ./cmd/...
go test -race ./state/... ./control/...     # 涉及并发/Session/Identity 时必跑
```

参考仓库目录：

```text
reference/tailscale                   # 协议最高参考
reference/headscale                   # 工程参考（/key /ts2021 poll 等）
reference/mirage-008-MirageServer     # 产品/身份参考
reference/MirageNetwork-MirageServer  # 安全经验参考
reference/{go-oidc,oauth2,dex,webauthn}
```

---

## M1 — Compatibility Core 传输层（已完成）

目标：官方 Tailscale 客户端能完成 TS2021 握手，并走到登录页。

已实现：

- `state/`
  - `node.go` — `Node`（MachineKey / NodeKey / DiscoKey / 地址 / Hostinfo…）、`RegisterMethod`。
  - `store.go` — `Store` 接口（Core 依赖接口，Platform → Core interfaces）。
  - `memory.go` — 并发安全的内存实现，顺序分配 `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`。
- `control/`
  - `capver.go` — 版本窗口 `MinSupportedCapabilityVersion = 115`（对齐 headscale），`/key` 的 `v` 解析。
  - `key.go` — 控制面 Noise 私钥的落盘/加载（`<state-dir>/noise_private.key`，0600）。
  - `server.go` — 公共路由：`/key` `/health` `/version` `/ts2021` `/register/{authID}` `/`，优雅关闭。
  - `noise.go` — TS2021 升级（`controlhttpserver.AcceptHTTP`）+ 版本门控的 early-noise payload（`tailcfg.EarlyNoise` node-key challenge）+ 内层 HTTP/2 `/machine/{register,map}`。
  - `register.go` — 注册决策：logout / 已注册重连（校验 machine key）/ followup 等待 / 交互式登录（AuthURL + pending registration + `ApproveRegistration` 审批接缝）。
  - `poll.go` — `/machine/map`：校验 node/machine 绑定、持久化 disco/hostinfo、lite update 返回 200、非流式返回自节点、流式长轮询 + keep-alive + 帧封装（4 字节 LE 长度前缀 + 可选 zstd）。
- `cmd/xunarad/main.go` — 服务入口（`-listen` `-state-dir` `-server-url` `-log-level`）。

验证：

- `control/noise_test.go` — 用上游 `controlhttp.Dialer` + `ts2021.Conn` 跑通真实握手 → 注册（拿 AuthURL）→ 审批 → followup 授权 → `/machine/map` 取回自节点。
- 其余：`/key` 版本门、Noise 密钥跨重启稳定、注册分支、logout、map 帧封装、内存 Store 并发。

已知限制（M2 起补齐）：

- Store 无持久化；无预认证密钥（PAK）；`/register/{id}` 页面不自动审批（审批仅经 `ApproveRegistration` 接缝）。
- 未处理 TKA、Funnel、SSH check、`/machine/set-dns` 等内层端点。

---

## M2 — 完整 netmap（Mapper）—— 进行中

目标：客户端能真正"上线"并看到 tailnet。

已完成（M2a）：

- `control/mapper/` 新包（纯函数，节点状态进、wire 类型出）：
  - `Full()` — 会话首帧：`Node` + `Peers` + `Domain` + `DNSConfig` + `DERPMap` + `UserProfiles` + 防火墙规则。
  - `Update()` — 变更帧：只带可变字段（nil = 客户端侧"不变"）。
  - `Node()` — `state.Node` → `tailcfg.Node`（地址、endpoints、HomeDERP、Cap、LastSeen、Online、Hostinfo）。
- capver gating：`PacketFilters`（capver ≥ 81）与旧 `PacketFilter` 二选一。
- 默认策略：`tailcfg.FilterAllowAll`（ACL 落地前与官方"无策略 tailnet"一致）。
- `Peers` 按 ID 排序、排除自身；`UserProfiles` 按 user ID 排序。
- 在线状态：`Server.markOnline/markOffline` 维护会话计数，离线时写 `LastSeen`；`Online` 反映实时会话。
- 变更广播：`Server.watch/notifyWatchers`（非阻塞），节点审批 / endpoint / hostinfo / disco 变化都会唤醒流式会话并推送 `Update()`。
- 配置：`Config.Domain`、`Config.DERPMap`，命令行 `-domain`、`-derp-map <file>`（`tailcfg.DERPMap` JSON）。
- `recordMapRequest` 现在持久化 `CapVer` / `DiscoKey` / `Endpoints` / `Hostinfo`，并返回更新后的节点供本帧使用。
- 测试：`control/mapper/mapper_test.go`（自/对等节点、排序、capver 分支、在线状态、Update 语义）；
  `control/noise_test.go` 新增 `TestNetmapPushesPeerChanges`（审批新节点后，已连接节点收到含该 peer 的推送）。

已完成（M2b-1，路由与 Exit Node）：

- `state.Node` 增加 `ApprovedRoutes`；`AnnouncedRoutes()` 从 `Hostinfo.RoutableIPs` 派生，
  `EffectiveRoutes()` = 已通告 ∩ 已批准，`IsExitNode()`。
- `Store.SetNodeApprovedRoutes` + `Store.ConfigRevision` / `BumpConfigRevision`：
  运行中的服务通过 revision 轮询感知 CLI 等带外改动（多实例同样成立）。
- mapper：`AllowedIPs` = 自身地址 + 生效路由；`PrimaryRoutes` 仅含非 exit 子网路由；
  `RouteTable` 做 primary 选举（同一前缀多播报者时取最小 node ID），与上游一致。
- `recordMapRequest` 不再是"每次请求都写库"：Hostinfo 变更用 `Hostinfo.Equal` 判定，
  并在缺省 `NetInfo` 时沿用旧值（避免 PreferredDERP 被清空）。
- `Server.Start(ctx)` 显式启动后台任务（janitor + config watcher）；`Serve` 内部调用。
- CLI：`xunara routes list|approve|unapprove`（`-node <id|stable-id>`，`-all` 或显式前缀）。

已完成（M2b-2，增量 netmap）：

- `control/mapsession.go`：每会话记录已下发的 self/peers 指纹（`tailcfg.Node.Equal`），
  后续帧用 `PeersChanged` / `PeersRemoved` 增量下发；全部 peer 都变化时退回全量列表
  （非空 `Peers` 会让客户端忽略 delta 字段，二者不同时出现）。
- 无可观察变化时不发帧（例如他人的 keep-alive 唤醒），keep-alive 仍每 50s 一次。
- `MapSessionHandle`（首帧、会话唯一）+ `Seq`（状态帧单调递增）；客户端重连带
  handle/seq 时按上游允许的方式开新会话并回全量 netmap。
- 测试：`control/mapsession_test.go`（初始帧、无变化、仅 self、单 peer、全量回退、
  移除、空 tailnet）、`TestStreamingNetmapIsDeltaEncoded`（真实流式端到端）；
  测试侧新增 `netmapView`（按客户端语义合并 Peers/PeersChanged/PeersRemoved）。

已完成（M2b-3，MagicDNS 与 set-dns）：

- `state.Node.FQDN(baseDomain)`：hostname 经 `dnsname.SanitizeHostname` 规范化为 DNS
  label（长度截断到 63），域名非空时输出 `<host>.<domain>.`；`tailcfg.Node.Name` 与
  之一致。
- `mapper.Config` 增加 `Resolvers` / `Routes` / `ExtraRecords`；`mapper.DNSConfig()`
  生成 `Domains` + `Proxied` + `CertDomains` + `ExtraRecords`。
- `state.DNSRecord` + `DNSRecordStore`（内存与 SQLite 共用同一套一致性测试）：
  按 `(name, type, value)` 幂等 upsert，SQLite 迁移 v4 建 `dns_records` 表。
- `POST /machine/set-dns`：校验 node key/machine key 绑定、记录名必须位于本 tailnet
  MagicDNS 域内、类型白名单（A/AAAA/TXT/CNAME）、值长度上限；写入后推送 netmap。
- 流式会话只在 DNSConfig 真正变化时下发（`mapSession.syncDNS` 指纹比对），避免每次
  netmap 重建都迫使客户端全量刷新。
- 服务端配置：`-nameserver`（可重复）、`-dns-route suffix=resolver[,resolver]`；
  解析在 `New()` 中一次性完成，配置错误直接启动失败。
- CLI：`xunara dns list|delete`。
- 测试：`TestNetmapCarriesMagicDNSConfig`、`TestSetDNSPublishesRecordToTailnet`、
  `TestSetDNSRejectsOutsideDomain`、`TestSetDNSUnknownNodeIsRejected`、
  `TestSetDNSRequiresAConfiguredDomain`、`mapSession` DNS 指纹用例、
  `runDNSRecordConformance`（内存 + SQLite）。

已完成（M2b-4，ACL 策略引擎）：

- 新包 `policy/`（纯函数，文档 + 节点快照进、`tailcfg.FilterRule` 出）：
  - HuJSON 解析（`github.com/tailscale/hujson`），未实现的顶层字段（如 `ssh`/`grants`）
    被显式记录并告警，**不会**被当成授权。
  - 选择器：`*`、CIDR/IP、`hosts` 别名、`group:`（支持嵌套、环检测）、`tag:`
    （需在 `tagOwners` 声明）、用户（登录名或 `login@domain` 的本地部分）、
    `autogroup:self`（按节点用户展开，逐节点编译）、`autogroup:member`；
    目标侧另有 `autogroup:internet` → `0.0.0.0/0` + `::/0`。
  - 端口：`*`、单端口、`8000-9000`、逗号列表；IPv6 目标支持 `[addr]:port`。
  - `proto`：协议名或 IANA 号；缺省不写 `IPProto`（= 客户端默认 TCP/UDP/ICMP）。
  - 文档自带 `tests` 由 `Engine.RunTests` 按"目的端过滤"语义求值。
- `control`：`Config.PolicyPath` + `Server.policy`（atomic）。启动时编译，文档非法
  直接启动失败（绝不回落到 allow-all）；运行中文件变更则重新加载，失败保留旧策略
  并记 error 日志。
- mapper：`Config.FilterFor`；空规则以**非 nil 空切片**下发（`{"base":[]}` = 阻断
  全部），与 `{"base":null}`（删除）区分；无策略时保持 allow-all（官方默认）。
- 流式会话用同样方式指纹比对 packet filter，仅在变化时下发。
- CLI：`xunara policy check [-domain] [-skip-tests] <file>`（编译 + 跑文档测试；
  无节点时跳过并说明）。
- 测试：`policy/engine_test.go`（解析、选择器、端口、proto、校验错误、tests）、
  `control/policy_test.go`（策略替换 allow-all、热重载推送、空策略=`[]`、
  坏文档保留旧策略、非法文档启动失败）。

待办（M2b 剩余）：

- `PeersChangedPatch`（更细粒度端点/DERP patch）。
- `tag:` 的实际赋值（tagged auth key / tagOwners 校验）——当前 tag 选择器匹配不到节点。
- `ClientVersion` 下发（版本提示）；`HomeDERP` 延迟择优（当前仅单 region 自动归位）。
- 说明：`set-dns` 记录通过 `ExtraRecords` 在 tailnet 内可见，**不**写入外部 DNS 提供商；
  公网 ACME 校验需要额外的 DNS 集成（后续里程碑）。

## M3 — 持久化与密钥 —— 进行中

已完成（M3a/M3b）：

- `state/sqlite.go`：`SQLiteStore` 实现 `Store`（`database/sql` + `modernc.org/sqlite`，纯 Go 无 cgo）。
  - 迁移框架（`PRAGMA user_version`），v1 `nodes`/`counters`，v2 `preauthkeys`。
  - WAL + `busy_timeout` + `synchronous(NORMAL)`；单连接串行化，ID/地址分配在事务内完成。
  - 连接串对 `?`/`#` 做校验，避免 DSN 注入。
- 地址分配改为偏移量算术（`state/addr.go`），ID/地址计数器持久化，重启不重号。
- `Store` 接口拆分出 `PreAuthKeyStore`；内存实现补齐同样方法。
- **共享一致性测试套件** `state/store_test.go`：内存与 SQLite 跑同一套断言（含富字段往返、索引重建、唯一性、删除清理）。
- 预认证密钥：`state.PreAuthKey`（一次性/可复用/过期/绑定 user/ephemeral）、`NewPreAuthKeySecret`
  （`tskey-auth-` + base32，长度 26 字符 ≈130 bit 熵；格式刻意落在官方客户端日志打码正则 `tskey-[A-Za-z0-9-]+` 内）。
- 注册流程接入 PAK：`registerWithAuthKey` 同步授权；密钥单次使用在节点落库**之后**才标记，避免崩溃烧掉密钥。
- `cmd/xunara` 管理 CLI：`preauthkey create|list|delete`。
- 服务端默认使用 SQLite（`<state-dir>/state.db`），`Server.Close()` 释放；`-db` 可覆盖路径。
- 测试：`TestNodeSurvivesServerRestart`（重启后节点免登录重连并可取 netmap）、
  `TestSQLiteStorePersistsAcrossReopen`、`TestTS2021RegisterWithAuthKey`（`tailscale up --authkey=` 等价链路）。

已完成（M3c）：

- Node 过期：`Config.NodeKeyExpiry` 决定服务器策略；客户端请求的 `RequestedExpiry`
  只能**缩短**不能延长（`applyRegistrationDefaults`），并写入 `state.Node.Expiry`。
- 到期失效：`state.Node.Expired()`，mapper 在 `tailcfg.Node.Expired` 下发。
- Ephemeral 回收：`Server.ReapEphemeral`（跳过在线节点，按 `LastSeen` 否则 `Created` 计龄）
  由 `runJanitor` 每分钟调度，`Config.EphemeralInactivityTimeout`（默认 30 分钟）可调。
- 测试：`control/janitor_test.go`（过期应用、只可缩短、默认不过期、回收与在线保护）、
  `control/mapper/mapper_test.go::TestNodeMarksExpiredKeys`。

待办（M3 剩余）：

- 用户表与多用户（当前锚定 `DefaultUserID`）。
- 审计记录（注册/审批/回收事件落库）。

## M4 — Identity & Login（Trust Plane）

- `IdentityProvider` 接口 + Provider Registry（本地 / Generic OIDC / WebAuthn）。
- `AuthTransaction` / `Session` / `DeviceAuthorization` **三者分离**（见 `AGENTS.md` §10）。
- External Identity 唯一键 `(provider_id, subject)`，Email 仅属性。
- OIDC 安全清单：state / nonce / PKCE(S256) / issuer / audience / signature / exp / iat / redirect allowlist / JWKS rotation / clock skew / code & state replay。
- Session 存储必须支持多实例、吊销、过期、审计、轮换（禁止 server-local map 作为核心存储）。
- 测试：`IDENTITY_LOGIN.md` §18 Security Test Matrix。

## M5 — Platform API 与 Web Console

- `api/v1`、`api/v2`、`api/platform`（REST + 鉴权中间件）。
- Web Console P0：Machines / Users / DNS / ACL-Grants / Routes / Exit Nodes / Auth Keys。
- 审批流接线：`/register/{id}` → 登录 → 审批 → 设备授权。

## M6 — 服务与客户端

- `services/`：Serve / Funnel / SSH check / Discovery。
- `client/`：Xunara Agent（自研客户端，独立协议，不侵入 TS2021）。
- DERP（`Xunara Veil`）、ACL/Zero Trust（`Xunara Warden`）。

---

## 横切注意事项

- **禁止猜 API**：改 `control/` 前先查 `reference/`（AGENTS.md §3）。
- **协议边界**：不得为 WebUI / OAuth / 多租户等改动 TS2021、Noise、MapRequest、NodeKey、MachineKey（§4）。
- **身份分离**：Human / Machine / Service 身份永不互推（§5）。
- **Secret 处理**：不得进 URL query；日志不得含 secret（§8）。
- **优先级**：Security > Protocol Compatibility > Data Integrity > Architecture > Feature Completeness > Convenience（§18）。

## 每次修改的说明模板（AGENTS.md §17）

```text
What changed
Why
Compatibility impact
Security impact
Tests
```
