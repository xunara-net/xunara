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
- 内层端点：`/machine/{register,map,set-dns,feature/query,audit-log,update-health,whoami}` 与 SSH check 已实现；`set-device-attr`、`id-token` 显式 501；TKA、Funnel 未处理。

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

已完成（M2b-2 追加，PeerChange patch）：

- `control/peerchange.go`：`peerChangeDiff` 按上游 `controlclient.peerChangeDiff` 的字段
  分类做节点级 diff；可 patch 字段（Key/KeyExpiry/KeySignature/DiscoKey/Endpoints/
  HomeDERP/Cap/CapMap/Online/LastSeen）进 `PeersChangedPatch`，结构性变化（Name、
  Addresses、AllowedIPs、Hostinfo、Tags、PrimaryRoutes、Expired 等）仍整节点下发。
  无法表达的变化（清空 Endpoints/HomeDERP/Cap/CapMap/Online/LastSeen）fail-closed，
  回退整节点，避免客户端静默丢弃。
- 字段集合通过反射枚举并配有守卫测试：tailscale.com 升级新增 `tailcfg.Node` 字段时
  测试失败，已知字段之外一律 fail-closed（整节点下发）。
- `mapSession.diff` 现在只在全部 peer 都是本会话未见过的节点时才用 `Peers` 全量列表；
  其余增量帧优先 patch。未变化的 self node 不再随帧下发（nil = 不变），否则客户端
  会因非增量字段（`resp.Node != nil`）而每次全量重建 netmap。
- 全量列表（`Peers` 非空）与 `PeersRemoved` 仍互斥，`OmitPeers` 同时清空 patch 字段。
- 测试：`control/peerchange_test.go`（逐字段 patch/不可 patch、字段全集守卫）、
  `control/mapsession_test.go`（patch、结构性整节点、新节点、移除、全量回退）、
  `TestStreamingNetmapIsDeltaEncoded` 改为断言端点更新以 patch 下发且省略 self。

已完成（M2b 追加，HomeDERP 延迟择优与 ClientVersion）：

- `recordMapRequest` 采纳客户端上报的 `Hostinfo.NetInfo.PreferredDERP` 作为
  `HomeDERP`：客户端测速后自行择优，服务端只接受自身 DERPMap 中存在的 region
  （未知 region 视为不可信输入忽略）；例行更新未携带 NetInfo 时沿用既有值；
  单 region 部署仍自动归位。多 region 下 peer 的 DERP 归属由此不再为空。
- `-client-version` / `-client-version-url`（`Config.LatestClientVersion` /
  `ClientVersionURL`）：`mapper.Full/Update` 下发 `tailcfg.ClientVersion`。
  按短版本比较（`1.88.3-t1234abcd` 与 `1.88.3` 视为相同），已是最新则
  `RunningLatest`，否则 `LatestVersion` + `Notify`（含 URL 与提示文本）；
  节点未上报版本则不猜、不下发。
- 会话指纹去重（`mapSession.syncClientVersion`）：`ClientVersion` 是客户端全量
  重建字段，只在值真正变化时携带；与 DNS/packet filter 的处理一致。
- 测试：`control/poll_test.go`（PreferredDERP 采纳/未知 region/无 NetInfo 保留/
  单 region 回退、提示计算与 full/update 下发）、`TestMapSessionClientVersionSync`、
  端到端 `TestStreamingNetmapAdoptsClientPreferredDERP`。

待办（M2b 剩余）：
- ~~说明：`set-dns` 记录通过 `ExtraRecords` 在 tailnet 内可见，**不**写入外部 DNS 提供商；
  公网 ACME 校验需要额外的 DNS 集成（后续里程碑）。~~
  已完成（M6f）：配置 DNS provider 后，`_acme-challenge.` 记录写入外部权威 DNS。
- 已完成（M2b 追加）：`tag:` 的实际赋值。
  - `state.PreAuthKey.Tags`（迁移 v5）与 `state.Node.Tags`（迁移 v6）；
    `state.NormalizeTags` 用上游 `tailcfg.CheckTag` 校验并排序去重，名称长度有上限。
  - mapper 下发 `tailcfg.Node.Tags`；tag 选择器现在能匹配到节点。
  - tagged 节点永不过期（`applyRegistrationDefaults` 跳过 key expiry，对齐上游）。
  - `policy.Engine.TagExists`/`UserOwnsTag`：tagOwners 直连用户、嵌套 group、
    tag→tag 链（含环保护）。
  - 创建面校验（tag 必须已在 tagOwners 定义）：CLI `preauthkey create -tags ... -policy ...`、
    console 表单、`POST /api/v1/auth-keys`。
  - 客户端 `--advertise-tags`（`Hostinfo.RequestTags`）：审批时按审批人的 tagOwners
    归属校验，任一 tag 不通过则整个审批失败（不静默降级），记 `device.tag_rejected` 审计。
  - 已修正（M4a 追加）：tagged 节点在 wire 上呈现为保留的 tagged-devices 伪用户；
    内部 `state.Node.UserID` 仍保留（tagOwners 归属校验需要）。节点 tag 的
    “仅 tag 拥有者”操作语义与角色模型一起在 M5c+ 完善。

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

已完成（M3 剩余 / M4a Identity 基础层）：

- `identity/` 包与 `User` / `ExternalIdentity` / `AuditEvent` 模型（`identity/identity.go`）。
- SQLite 信任面存储（`identity/sqlite*.go`）：`users`（login_name 大小写不敏感唯一）、
  `external_identities`（主键 `(provider_id, subject)`，禁止改绑他人）、`audit_events`；
  迁移独立于 state 的 `PRAGMA user_version`，使用 `schema_migrations(module, version)` 共用同一数据库。
- 内置本地用户：`identity.EnsureLocalUser`（首个用户 ID=1，同时登记 `(local, local)` 外部身份）。
- 控制面接线：`Server.Identity()`、`Server.UserProfile()`（netmap `UserProfiles` 来自信任面，
  未知用户回落默认 profile）、ACL `LoginName` 解析也走信任面。
- 审计落库：`user.created`（播种）、`node.registered`（PAK）、`node.approved`（交互审批）、
  `node.deleted`（logout）、`node.reaped`（ephemeral）、`dns.record_set`、`policy.reloaded`；
  CLI 侧 `route.approved/unapproved`、`dns.record_deleted`、`preauthkey.created/deleted`、`user.updated`。
  审计 detail 不复制 secret（PAK 明文、DNS TXT 值、OAuth token 等）。
- CLI：`xunara user list|update`、`xunara audit list [-limit N]`。
- 测试：`identity/sqlite_test.go`（CRUD、大小写、唯一键与改绑拒绝、幂等播种、审计顺序/limit）、
  `control/identity_test.go`（播种、用户资料下发到 netmap）、`control/audit_test.go`
  （注册/审批/登出/回收/set-dns 审计）、`policy` 热重载审计断言。

已完成（M4a 追加，节点归属与 tagged 身份）：

- 归属链路：PAK 注册归属密钥创建者、交互审批归属登录用户、API/Console 归属
  principal/session；tagged 设备不再伪装成其 tag 所有者的设备。
- 协议侧 tagged 身份：`tailcfg.Node.User`、`RegisterResponse.User/Login` 与
  `UserProfiles` 使用保留的 `tagged-devices` 伪用户（ID 2147455555，
  `mapper.TaggedDevicesUserID`），对齐 headscale 的 `types.TaggedDevices`。
- ACL/SSH 语义：`user:` 选择器与 `autogroup:self` 双向不匹配 tagged 设备
  （含 SSH 目的端与 check 时长）；tagged 设备只能通过 `tag:` /
  `autogroup:tagged` 寻址，与 headscale policy/v2 一致。
- 测试：`policy` 的 self/user 选择器与 SSH 目的端/checkPeriod 用例、
  `mapper` 的伪用户与 UserProfiles 用例、`control/tags_test.go` 端到端断言
  注册响应与 netmap 的 tagged-devices 身份。

## M4 — Identity & Login（Trust Plane）

- M4a 已完成：见 M3 段落的「Identity 基础层」。
- M4b-1 已完成：`IdentityProvider` 接口 + Provider Registry + 内置 LocalLogin；
  `AuthTransaction` / `Session` / `DeviceAuthorization` 三张表、三个对象，全部走 SQLite（无 server-local map）。
  - AuthTransaction：state/nonce/PKCE(S256) 生成，浏览器绑定 secret 只存 SHA-256，
    `ConsumeAuthTransaction` 原子单次消费（code/state replay 防护），过期清扫。
  - Session：token 只存哈希，支持过期、吊销、并行登出、轮换（旧 token 立即失效）、LastSeen。
  - DeviceAuthorization：绑定精确 (machine_key, node_key)，审批/拒绝原子条件更新，
    重复审批幂等、他人重放拒绝、过期拒绝。
  - 测试：`identity/state_machine_test.go`（生命周期 + 重放/过期/轮换/跨用户）。
- `AuthTransaction` / `Session` / `DeviceAuthorization` **三者分离**（见 `AGENTS.md` §10）。
- M4b-2 已完成：Generic OIDC Provider（`identity/oidc.go`）。
  - 懒发现（启动不依赖 IdP 可用性）+ JWKS 自动轮换（go-oidc RemoteKeySet）。
  - 强制校验：state（常量时间）、nonce、PKCE(S256)、签名（仅非对称算法，拒绝 HS*）、
    issuer、audience、exp/nbf（库）+ iat 未来/过旧（本层，含 clock skew 与 MaxTokenAge）。
  - 端点安全：issuer/授权/令牌/redirect URL 必须 https（或 loopback http），
    拒绝算法混淆与明文端点；redirect_uri 只来自配置。
  - 测试：`identity/oidc_test.go` 内置假 IdP（discovery/JWKS/token），覆盖
    错误 state/nonce/issuer/audience/过期/未来 iat/过旧 iat/未知签名密钥/无 id_token/
    PKCE 不匹配/code 重放/JWKS 轮换/懒发现失败关闭/URL 校验。
- External Identity 唯一键 `(provider_id, subject)`，Email 仅属性。
- M4b-3 已完成：控制面登录/会话/设备审批接线。
  - `GET /login`（provider 选择、`return_to` 仅接受同源绝对路径，杜绝开放重定向）、
    `GET /oidc/callback/{providerID}`、`POST /logout`。
  - 登录流程：AuthTransaction（浏览器绑定 cookie）→ Provider.Callback →
    原子消费（重放拒绝）→ `(provider, subject)` 查找/创建用户（**绝不按 email 合并**）
    → SQLite Session → HttpOnly/SameSite=Lax/（https 时）Secure cookie。
  - 设备审批：`GET /register/{authID}` 展示设备信息（客户端参数字典落库在
    DeviceAuthorization.client_metadata），`POST .../approve|deny`（会话 + 每会话 CSRF）。
  - 多实例：followup 以 DeviceAuthorization 为依据（按 node key 查询），
    审批任一实例可见；内存 pending 仅作唤醒快路径。
  - 审计：login.succeeded/failed（原因分类有界、不含 provider 原文）、
    session.created/revoked、user.created、device.approved/denied、node.approved。
  - 客户端注册响应（`RegisterResponse.Login`）改用信任面资料。
  - 配置：`Config.OIDCProviders`（每个 provider 默认回调
    `<server-url>/oidc/callback/<id>`）、`Config.Providers`（自定义适配器）、
    `Config.AllowLocalLogin`；xunarad 增加对应参数，**client secret 只从
    `XUNARA_OIDC_CLIENT_SECRET` 环境变量读取**（不进 argv）。
  - 测试：`control/login_test.go`（本地登录/登出、未知 provider、开放重定向表、
    OIDC 浏览器流与重放/无绑定拒绝、同 email 不同 subject 不合并、设备审批的
    会话/CSRF/幂等/拒绝、过期与未知链接、注册响应资料）。
- OIDC 安全清单：state / nonce / PKCE(S256) / issuer / audience / signature / exp / iat / redirect allowlist / JWKS rotation / clock skew / code & state replay。
- Session 存储必须支持多实例、吊销、过期、审计、轮换（禁止 server-local map 作为核心存储）。
- 测试：`IDENTITY_LOGIN.md` §18 Security Test Matrix。

## M5 — Platform API 与 Web Console

- M5a 已完成：Platform API（`/api/v1`）。
  - 认证：`Authorization: Bearer`（Service Identity API Key，token 只存哈希，
    带 read/write scope、TTL、吊销、last-used）或浏览器会话 cookie。
  - 端点：overview、machines（列表/详情/删除/路由审批）、routes、users（列表/详情/改名）、
    dns（列表/删除）、policy、auth-keys（创建/列表/删除，secret 仅创建时返回）、
    devices（待审批列表/批准/拒绝）、audit、api-keys（创建/列表/吊销）、sessions（列出/吊销）。
  - 节点视图不包含任何 key 材料；所有写操作落审计（actor 含 `apikey:<id>`）。
  - `state.ApplyRouteApproval`/`RouteDelta`：路由审批的纯函数（CLI 与 API 共用语义）。
  - CLI：`xunara apikey create|list|revoke`（bootstrap 第一把管理员 key）。
  - 测试：`control/api_test.go`（401/403/scope、密钥不泄漏、注册/路由/删除、
    用户改名冲突、auth-key 一次性 secret、设备审批归属、key 吊销即时生效）。
- `api/platform` 已完成（M7a）：组织表 + `/api/platform/v1`（见 M7 段）。
- M5d 已完成：Platform API v2（`/api/v2`，`control/api_v2.go`）。
  - 认证/角色模型与 v1 相同（session 或 service API key，write 需 admin+）；
    v1 响应形状不变，v2 是增量版本。
  - `GET /api/v2/meta`：版本、capver 窗口、页面大小上限、身份 provider、
    agent 协议版本、webhook/DNS provider/DERP map 是否配置；不包含任何
    密钥材料或 secret。
  - 游标分页（不透明 base64 游标，服务端校验种类与格式；调用方只回传）：
    `GET /api/v2/machines`（过滤 state=online|offline、user=<id|login>、
    tag=，未知用户返回空集而非忽略过滤）、`GET /api/v2/audit`
    （过滤 action/actor/target 前缀，扫描上限防止全表遍历）、
    `GET /api/v2/agent-tokens`（含节点信息，永不返回 credential）。
  - `DELETE /api/v2/agent-tokens/{id}`：吊销原生客户端凭证（幂等、404 未知、
    审计 `agent.token_revoked`），下一个 agent 请求立即 401。
  - 查询串必须可解析（`net/url` 会静默丢弃坏 pair，这里 400 拒绝），
    非法 cursor/limit/filter 一律 400。
  - console 新增 Agents 页面（只读角色可见列表、admin+ 可吊销；secret 永不渲染）。
  - 测试：`control/api_v2_test.go`（meta 认证与不泄漏、分页不重不漏、过滤、
    非法输入表、token 列出/吊销/幂等/404/权限、吊销后即时失效）、
    `identity/sqlite_agent_test.go`（跨节点列出、单条吊销、limit、幂等）、
    console 渲染与吊销端到端。
- 待办（M5 剩余）：gRPC。Webhook 已完成（M8a）。

- M5b 已完成：Web Console（`/console/`，浏览器会话 + 每会话 CSRF）。
  - 页面：Overview（在线/离线、待审批设备、DNS、auth key、策略摘要）、Machines
    （地址、方法、announced/approved 路由、approve-all/withdraw、删除）、Devices
    （approve/deny）、Users（display name/email 编辑）、DNS（删除）、Auth Keys
    （创建/吊销，secret 仅创建时展示一次，列表永不回显）、Policy（规则数、
    warnings、unsupported、重读错误）、Audit（最新优先，最多 200 条）。
  - 无脚本、无外部资源、`Cache-Control: no-store`；所有写操作走 CSRF + 审计；
    除一次性 `CreatedKey` 外不渲染任何 key 材料。
  - 测试：`control/console_test.go`（未登录重定向、8 个页面渲染、CSRF 拒绝、
    路由审批/撤回、机器删除、auth key 生命周期与一次性 secret、设备审批、
    用户编辑、策略页、审计排序）。
  - 已知限制（M5c 后已解决角色部分）：组织/多租户与 `api/v2` 未实现。
- M5c 已完成：角色模型（owner / admin / member）。
  - `identity`：`User.Role`（迁移 v5）；此前所有用户已在做管理操作，迁移把它们
    提升为 owner，不静默降权；`CreateUser` 默认 member；内置 local 用户是
    owner，作为引导角色（首个 OIDC 用户用 `xunara user role` 提升）。
    新增 `Role.CanWrite()`（admin+）与 `Role.IsOwner()`；审计
    `user.role_changed`。
  - `control`：`apiPrincipal.Role`；API 与 console 的写操作要求 admin+，
    角色变更要求 owner，且拒绝把最后一个 owner 降级（409）。服务身份 API key
    只在其 owner 的角色范围内生效（scope 只收窄、不放大）；owner 被删除后其
    session 与 key 立即失效（401）。`session`/`api-key` 的自助吊销不受角色限制，
    但不能吊销他人的对象。
  - console：只读角色页面顶部提示、隐藏全部写表单；设备审批
    `/register/{id}/approve|deny`、SSH check 审批 `/ssh/check/{id}/approve|deny`
    也要求 admin+（此前任何登录用户皆可批准）。
  - CLI：`xunara user role <id|login> <member|admin|owner>`（最后一个 owner
    拒绝降级）；`xunara user list` 显示 ROLE。
  - 测试：`identity/role_test.go`、`identity/sqlite_test.go`（默认 member、
    local owner、迁移提升、角色往返）、`control/role_test.go`（API/console
    角色门禁、服务 key 不放大权限、owner-only 角色变更、最后 owner 保护、
    已删除用户会话/密钥失效、设备与 SSH check 审批门禁、自助吊销）。
- 审批流接线（已完成）：`/register/{id}` → 登录 → 审批 → 设备授权。

## M6 — 服务与客户端

- M6a 已完成：Tailscale SSH（accept 模式）。
  - `policy`：解析/校验文档 `ssh` 段（原为 unsupported）；`CompileSSHPolicy`
    为“作为目的端的节点”编译 `tailcfg.SSHPolicy`（principals 按源地址展开，
    `users` → wire SSHUsers 映射，`dst: autogroup:self` 仅限同用户设备）。
  - `Engine.SSHDestinations`：被 ssh 规则点名为目的端的节点获得
    `tailscale.com/cap/ssh`（写入 `tailcfg.Node.CapMap`），客户端才能
    `tailscale up --ssh` 启动 SSH server。
  - `mapper.Config.SSHPolicyFor`，Full/Update 均下发 SSHPolicy。
  - `action: "check"` 目前编译为空并给出 warning（不静默当作 accept）。
  - 顺带修复：`Engine.warnf` 去重，避免每次 netmap 构建重复累积同一 warning。
  - 测试：`policy/ssh_test.go`、`control/ssh_test.go`。
- M6b 已完成：`nodeAttrs` 能力授予与 CapMap 下发。
  - `policy`：解析/校验文档 `nodeAttrs` 段（target × attr），target 支持
    用户、组、tag、host/prefix、`autogroup:member`、`autogroup:tagged`、`*`;
    拒绝 `autogroup:self` / `autogroup:internet`，attr 拒绝空值/空白/超长，
    `funnel` 在加载时 fail-closed 拒绝（本构建没有公网 ingress）。
  - `Engine.NodeCapMaps` 把授予编译成 `tailcfg.NodeCapMap`；`mapper.Config.NodeCaps`
    在 self 与 peer 两个方向写入 `tailcfg.Node.CapMap`，并与 SSH 目的端的
    `tailscale.com/cap/ssh` 合并。
  - 新增选择器 `autogroup:tagged`（ACL src/dst、SSH、nodeAttrs 通用）。
  - 测试：`policy/nodeattrs_test.go`、`control/nodeattrs_test.go`。
  - 说明：`nodeAttrs: ["https"]` 解锁客户端侧的 `tailscale serve`；配置 DNS
    provider 后控制面同时下发 `CertDomains` 并代理 DNS-01 校验（M6f）。
    Funnel 需要公网 ingress，保持不支持。
- M6c 已完成：Tailscale SSH check 模式（hold and delegate）。
  - `policy`：`ssh` 规则支持 `checkPeriod`（缺省 12h、"always"=0、上限 168h、
    仅 check 规则可用）；check 规则编译为 `SSHAction.HoldAndDelegate`
    （`<ServerURL>/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER`，
    转发能力在裁决前保持关闭）。`Engine.SSHCheckPeriod` 按首个匹配 check 规则
    解析 (src, dst) 的自动放行窗口。
  - `identity`：迁移 v4 新增 `ssh_check_sessions`（ID、src/dst 节点、local_user、
    verdict、decided_by/at、consumed_at、TTL）与 `ssh_check_auth`（每对节点最近
    一次批准）。审批是原子条件更新；裁决只交给一个跟随请求（consume-once）；
    TTL 到期由 janitor 回收。全部持久化，无 server-local cache（AGENTS §9/§10）。
  - `control`：Noise 内 `GET /machine/ssh/action/{src}/to/{dst}`；请求方必须是
    目的节点（machine key 绑定），auth_id 只能用于其绑定的 (src, dst) 对。
    初次请求命中窗口内批准则直接 accept，否则创建/复用 pending 会话并返回
    hold + 审批链接；跟随请求长轮询（500ms 轮询持久层，任何实例都能服务）。
    浏览器流程 `GET/POST /ssh/check/{id}(/approve|/deny)`：走既有 Session + CSRF，
    落审计 `ssh.check_approved` / `ssh.check_denied`；策略重载清空已记住的批准。
  - 测试：`policy/ssh_test.go`（check 编译、checkPeriod 取值/拒绝、pair 解析）、
    `identity/sshcheck_test.go`（生命周期、过期、consume-once、方向性记忆）、
    `control/sshcheck_test.go`（端到端 approve/deny、长轮询、自动放行、策略重载
    失效、machine key 与 auth_id 绑定、always 每次复查、审批页需登录）。
- M6d 已完成：`grants`（ACL v2）与 `autogroup:member` 语义修正。
  - `policy`：解析 `grants`（原为 unsupported 字段）；每条规则编译为
    `tailcfg.FilterRule`：`ip` 条目（`tcp:443`、`udp:6000-6100`、裸端口、`*`）
    逐条生成带 IPProto/Ports 的规则；`app` 生成 `CapGrant`（Dsts 为目的地
    前缀，CapMap 原样透传文档 JSON），并为 `drive`→`drive-sharer`、
    `relay`→`relay-target` 生成反向 companion 规则（对齐上游）。
    `dst: autogroup:self` 仍按目的节点解析；wildcard CapGrant.Dsts 展开为
    尾网网段（CapGrant 不能使用 wire 的 `"*"`）。`via` 未实现，加载即拒绝。
  - `autogroup:member` 现在排除 tagged 节点（上游语义）；tagged 设备改用
    `tag:` 或 `autogroup:tagged` 引用。ACL/SSH/nodeAttrs/grants 全部生效。
  - 测试：`policy/grants_test.go`（ip 规则、CapGrant 值透传、companion、
    self 目的、wildcard 网段、校验表、裸端口、计数）、
    `control/grants_test.go`（CapGrant 到达 netmap）、
    `policy TestAutogroupMemberExcludesTagged`。
- M6e 已完成：`Xunara Veil`（DERP 中继）。
  - 新增 `veil/`：基于上游 `tailscale.com/derp/derpserver` 的独立 DERP 服务，
    与官方客户端协议一致（`/derp` HTTP upgrade、WebSocket-DERP、`/derp/probe`、
    `/derp/latency-check`、`/generate_204`）；支持 STUN（`net/stunserver`）与
    手动 TLS（`CertFile`/`CertKeyFile`）。
  - DERP node key 持久化到 `<state-dir>/derp.key`（0600、原子写、与 derper
    的 config JSON 格式兼容）；重启后 public key 不变，客户端 pin 不失效。
  - `Config.VerifyURL` 指向控制面的准入端点；未配置时启动即 warn。
    `DERPMap()`/`-derp-map-out` 生成单节点 `tailcfg.DERPMap`（`OmitDefaultRegions`），
    直接交给 `xunarad -derp-map`。
  - 新增 `cmd/xunara-veil`（`-listen`、`-hostname`、`-state-dir`、`-key-file`、
    `-stun`/`-stun-port`、`-verify-url`、`-cert-file`/`-cert-key-file`、
    `-region-*`、`-derp-map-out`、`-insecure-for-tests`、`-log-level`）。
  - `control`：新增 `POST /derp/admit`（上游 `derper --verify-client-url` 协议，
    `tailcfg.DERPAdmitClientRequest/Response`），仅放行已注册且未过期的 node key；
    请求体限长、未知节点返回 200 + `allow:false`、fail-closed（错误绝不放行）。
  - 测试：`veil/veil_test.go`（key 持久化与 0600、DERP map 字段、两客户端经
    Veil 中继互发、准入放行/拒绝/控制面不可达 fail-closed、probe 端点）、
    `veil/integration_test.go`（Veil ↔ `control` `/derp/admit` 真实联通）、
    `control/derpadmit_test.go`（注册/未知/过期/零 key/坏请求）。
  - M6e 收尾（已完成）：DERP mesh key 与带宽限速。
    - `veil.Config.MeshKey`（64 hex）：构造时经 `key.ParseDERPMesh` 校验并
      交给上游 `derpserver.SetMeshKey`，mesh peer 由 derpserver 内部信任；
      `Server.MeshKeyEnabled()` 只报告开关，永不导出/记录密钥；错误信息不含
      密钥原文。`cmd/xunara-veil -mesh-key-env <ENV>` 只从环境变量读取，
      变量名为空但取值失败时拒绝启动（AGENTS §8：secret 不进 argv）。
    - `veil.Config.BandwidthLimit`（字节/秒）+ `BandwidthBurst`：在 listener
      层对每条连接双向共享一个 token bucket（覆盖 TLS 与 mesh 链路），
      burst 缺省为 limit 并夹在 [64 KiB, 4 MiB]；Close 取消等待中的限速，
      不会把 goroutine 卡在低速率上。语义是每连接公平性上限（不是节点总容量）。
    - `cmd/xunara-veil -bandwidth-limit/-bandwidth-burst`。
    - 测试：`veil/ratelimit_test.go`（限速生效、Close 解除等待、mesh key
      校验与不泄漏、burst 派生表、限速下 DERP 中继端到端）。
  - 已知限制：DERP 服务自身无自动证书（TLS 证书目前手动
    `-cert-file`/`-cert-key-file`）。
- M6f 已完成：证书签发 DNS-01（`services/serve` 的控制面部分）。
  - `control.DNSProvider` 接口（`PutTXT`/`DeleteTXT`，带 context）：控制面在
    ACME DNS-01 校验期间代表节点写入/清理 `_acme-challenge` 记录，
    私钥与 CSR 始终只留在客户端（`tailscale cert` 流程）。
  - `Config.CertDomains` / `-cert-domain`（可重复）+ 节点自身 FQDN 组成
    `certDomainsFor(node)`；无 DNS provider 时不下发 `CertDomains`
    （客户端显示"不支持"）；域名规范化（小写、去尾点、去重）并在启动时
    fail-closed 拒绝 `_acme-challenge.` 前缀/空格/不含点的值。
  - `mapper.Config.CertDomainsFor` 钩子；`DNSConfig(cfg, self)` 按节点下发
    `tailcfg.DNSConfig.CertDomains`。
  - `POST /machine/set-dns`：`_acme-challenge.` 记录必须命中 `certDomainsFor`
    （越权 400），写入本地库（本地挑战记录不进入 `ExtraRecords`，不对客户端
    泄露校验值）后调用 provider `PutTXT`；provider 失败返回 502（fail-closed，
    不假装成功）。
  - janitor `reapACMEChallenges`：超过 24h 的挑战记录从库与公网 zone 同时清理
    （`DeleteTXT` 幂等，provider 已删除不报错）。
  - 新包 `dnsprovider/`：`Webhook`（JSON POST `{action,name,type,value}`，
    Bearer token，仅允许 https 或 loopback http）与 `Cloudflare`
    （API v4，zone 查询缓存、TTL 60、先删旧值再建、错误透传）。
  - `cmd/xunarad`：`-dns-webhook-url` / `-dns-webhook-token-env` /
    `-dns-cloudflare-zone` / `-dns-cloudflare-token-env`；token 只从环境变量
    读取，绝不进 argv 或 URL query（AGENTS §8）。
  - 测试：`control/cert_test.go`（CertDomains 下发、challenge 走 provider 且
    不进 ExtraRecords、越权 400、provider 失败 502、reap 只删过期 challenge）、
    `dnsprovider/webhook_test.go`、`dnsprovider/cloudflare_test.go`
    （请求体/鉴权、put 替换旧值、幂等删除、API 错误、URL 校验）。
- M6h 已完成：内层端点补齐（health / audit-log / whoami）。
  - `POST /machine/update-health`（`tailcfg.HealthChangeRequest`）：健康报告是
    咨询性遥测，只记 debug 日志（字段截断/去控制字符），不影响注册、策略或
    路由；node key 非零时校验 machine key 绑定，为零（旧客户端）时仍接受。
  - `POST /machine/audit-log`（`tailcfg.AuditLogRequest`）：客户端上报的审计
    事件落持久审计日志；action 必须在白名单（当前 `DISCONNECT_NODE` →
    `node.disconnect_reported`），未知 action 400；details 截断 512 字节并去
    控制字符（控制台/终端渲染安全）；actor/target 用节点 stable ID。
  - `GET /machine/whoami`：`tailscale debug ts2021` 的握手探针；按 Noise 会话
    machine key 找节点（多节点取最旧），返回 node id/stable id/FQDN/地址/
    短公钥；未注册 machine key 404。
  - `PATCH /machine/set-device-attr` 与 `POST /machine/id-token` 显式 501
    （设备姿态属性、OIDC ID token 未实现；不伪造 token，不代表支持）。
  - 测试：`control/machine_misc_test.go`（审计落库与净化、未知 action 400、
    跨节点 404、health 204/绑定、whoami 成功与未注册 404、501 表）。
- M6g 已完成：`/machine/feature/query`（serve / funnel 的启用指引）。
  - `control/featurequery.go`：解析 `tailcfg.QueryFeatureRequest`，Noise 会话
    machine key 必须匹配请求中的 node key（跨节点探测 404）；节点已持有全部
    所需能力时返回 `Complete:true`（"serve"/"https" → `https`，
    "funnel" → `https` + `funnel`）。
  - 未持有时返回可执行说明文本：`https` 需管理员在策略 `nodeAttrs` 中授予；
    Funnel 明确不支持（策略加载即拒绝 `funnel` 属性，绝不会 Complete）；
    未知 feature 返回有界、可打印（去除控制字符、截断）的文本。
  - `ShouldWait` 恒为 false、`URL` 恒为空：Xunara 没有"服务端一键启用"流程，
    CLI 打印说明后退出，不阻塞（对齐上游 `enableFeatureInteractive` 语义）。
  - `poll.go` 的 CapMap 编译抽出 `nodeCapsAdvertiser`，netmap 与 feature query
    共用同一份 nodeAttrs + cap/ssh 视图。
  - 测试：`control/featurequery_test.go`（已授权 Complete、未授权说明、
    Funnel 不支持、跨节点/未知 node key 404、未知 feature 有界、
    截断 JSON 拒绝）。
- `services/` 其余：Funnel（明确不支持）；Discovery。
- M9 已完成：Xunara Agent（自研客户端，独立协议）。
  - 服务端 `/api/agent/v1`（`control/agent.go`，独立于 TS2021）：
    `POST /enroll`（pre-auth key 同步授权，或复用设备审批流的交互式授权；返回
    machine/node 绑定的 agent token，重新 enroll 轮换旧 token）、
    `POST /netmap`（返回与官方客户端同构的 `tailcfg.MapResponse` JSON）、
    `POST /heartbeat`（复用 MapRequest 持久化路径：hostinfo/endpoints 变更检测、
    PreferredDERP 采纳、watcher 唤醒；2 分钟 TTL 内计入"在线"）。
  - 身份：`identity.AgentToken`（迁移 v7）绑定 node ID + machine key + node key，
    只存哈希；每个请求必须复述两把公钥并与存储节点核对（AGENTS §11）；节点
    删除或 node key 过期即失效；`agent.enrolled` 审计。
  - 客户端：`client/protocol`（类型化 HTTP 客户端，Bearer 头、超时、错误分类）、
    `client/daemon`（`agent.json` 0600 原子写、enroll、心跳+netmap 循环、401 停止
    并提示重新 enroll、指数退避）、`cmd/xunara-agent`（`enroll|run|status|version`；
    授权密钥只从环境变量或 `-auth-key-file` 读取，绝不进 argv）。
  - 测试：`control/agent_test.go`（pre-auth/交互式授权、netmap 自节点、心跳写入
    hostinfo/endpoints、凭证轮换与旧 token 失效、跨节点 403、节点删除 401、
    输入校验）、`client/protocol/protocol_test.go`（请求形状、Bearer 头、token
    不入 body/URL、错误映射）、`client/daemon/daemon_test.go`（状态 0600、
    pending/rejected、循环与停止、401 终止）、`client/daemon/e2e_test.go`
    （真实控制面端到端：授权、netmap 状态、心跳在线、删除后失效、交互审批）。
  - M9 收尾（已完成）：netmap SSE 推送。
    - 服务端 `GET /api/agent/v1/events`（`control/agent.go`）：SSE
      (`text/event-stream`/`no-store`/`X-Accel-Buffering: no`)，身份规则与轮询
      端点相同（Bearer token + `X-Xunara-Machine-Key`/`X-Xunara-Node-Key` 头，
      GET 无 body）；打开即推送一帧完整 netmap，tailnet 变化时经既有 watcher
      推送新帧，25s 注释心跳保活；节点删除或凭证吊销后流结束。
    - 客户端 `protocol.StreamNetmap`：SSE 解析（keepalive/未知事件忽略、
      2 分钟滞留判定、ctx 取消即返回）、`IsStreamUnsupported` 识别老服务端；
      `daemon.Run` 稳态优先走事件流（旁边跑心跳循环），流结束按指数退避重连，
      老服务端或持续失败时回落到原轮询循环。
    - 测试：`control/agent_test.go`（首帧、tailnet 变化推送、Content-Type/
      no-store、匿名 401、键不匹配 403）、`client/protocol/stream_test.go`
      （头、解析、取消、404 回落判定）、`client/daemon/e2e_test.go`
      （真实控制面下 Interval=10m 仍收到推送，证明是 push 而非轮询）。
  - 已知限制（M9 剩余）：Remote/File Transfer 尚未构建。
    （credential 的列出/吊销已完成：M5d 的 `/api/v2/agent-tokens` 与 console
    Agents 页面。）
- ACL/Zero Trust（`Xunara Warden`）。

---

## M7 — 多租户（Organizations）—— 进行中

- M7a 已完成：组织表与按 Host 路由的多租户控制面。
  - `control.Router`（`control/router.go`）：一个监听器承载多个组织，按请求
    Host 分发到各自的 `*Server`；精确域与单层通配域（`*.example.com`，只匹配
    一个 label，DNS 通配语义），最长模式优先。唯一组织且未配置域时退化为
    全 Host 兜底，单租户行为不变。
  - 隔离是结构性的：每个组织一个独立 `Server`，即独立 state 目录、SQLite、
    Noise key、策略、DNS provider 与身份库（对应 AGENTS.md §12 的租户边界，
    不靠查询过滤）。
  - 启动校验 fail-closed：组织 ID 必填且唯一、域不得重复、多组织时不得有
    无域组织、域格式校验（拒绝 scheme/空格/裸主机名/多级通配）。
  - `/health` `/version` 由 Router 回答（进程级，不落到某个组织）；未知 Host
    返回不泄漏组织列表的 404（`Cache-Control: no-store`）。
  - `/api/platform/v1/organizations[/{id}]`（`control/platform.go`）：只读跨
    组织视图（id/name/domains + 节点/在线/用户/待审批设备/策略状态）。
    认证只接受进程环境变量里的平台令牌（Bearer、SHA-256 后常量时间比较、
    `Cache-Control: no-store`）；未配置令牌时整个 API 403 关闭；组织自己的
    session cookie 或 API key 不能访问（租户凭据不外溢）。
  - `cmd/xunarad -org-config <json> -platform-token-env <env>`：组织表 JSON
    （`examples/organizations.example.json`；`DisallowUnknownFields`）、每组织
    独立 state 目录（重复即拒绝，防止共享 SQLite）、可选 per-org OIDC/DNS
    provider（secret 只从环境变量读取）、`node_key_expiry` 支持 `180d`。
    与单组织 flag 互斥（`flag.Visit` 检查，拒绝歧义配置）。
  - 测试：`control/router_test.go`（真实 TS2021 端到端经 Host 路由注册、跨组织
    不可见、通配域、未知 Host 404、单组织兜底、校验表、域匹配表、
    平台 API 认证/禁用/统计/组织凭据拒绝）、`cmd/xunarad/orgconfig_test.go`
    （构建、共享 state 目录拒绝、坏配置表、expiry 解析、flag 互斥）。
- M7b 已完成：组织级 DERP 策略。
  - `control.DERPPolicy`（`control/derp_policy.go`）：
    `""`（继承，零值）/ `none`（不提供任何 DERP 区域）/ `regions`（只提供
    白名单区域，名单外的区域视为配置错误，启动即失败——防止拼写错误悄悄
    缩小覆盖）。`ParseDERPPolicy` 解析命令行值，`Apply` 校验并生成服务给
    该组织的 DERP map。
  - 协议语义（照 upstream `control/controlclient/map.go` 核对）：
    `tailcfg.DERPMap.Regions` 为 nil 表示"不变"，因此 `none` 必须发送
    **非 nil 的空 region 表**（JSON 里是显式的 `"Regions":{}`），才能让客户端
    清空既有区域。
  - 落地：`Server.derpMap`（策略应用后的 map）替换 mapper / `singleDERPRegion`
    / `derpRegionKnown` 中的 `cfg.DERPMap`；节点下次 map request 时，若 HomeDERP
    已不在服务范围内会被清空并按单区域回退重新归属。
  - 可执行的一侧：`/derp/admit` 按策略放行——`none` 拒绝所有节点；`regions`
    拒绝 HomeDERP 在白名单外的节点（尚未选择 home 的节点放行，它只能看到被
    服务的区域）。
  - `/api/v2/meta` 增加 `derpPolicy` 与 `derpRegionsServed`。
  - 配置：单组织 `-derp-policy` / `-derp-regions`；组织表
    `"derp_policy": {"mode","regions"}`（`examples/organizations.example.json`
    已更新）。
  - 测试：`control/derp_policy_test.go`（Apply 表、空 map 的 JSON 形状回归、
    `ParseDERPPolicy` 表、过滤后的 map 与重新归属、`none` 的 admission 拒绝、
    白名单外 home 的 admission 拒绝、坏策略拒绝启动、真实注册+map 请求的
    端到端字节校验）、`cmd/xunarad/orgconfig_test.go`（组织表策略解析、
    未知区域/缺 map/模式不匹配的拒绝）。
- M7c 已完成：跨组织审计导出（`control/platform_audit.go`）。
  - `GET /api/platform/v1/audit`（平台令牌，与其他 platform API 同一认证；
    `Cache-Control: no-store`）返回所有（或 `org=` 选定）组织的审计事件，
    按 `(time, org, id)` 归并排序，每条带 `org`。
  - 分页按组织：每个组织拥有独立数据库与 ID 空间，不存在可靠的全局游标。
    响应返回 `cursors`（每组织已消费到的最大 ID）与 `has_more`，调用方保存
    游标并在下次请求用 `cursor=org:id` 传回；`limit` 限制每个组织单次扫描的
    原始事件数（默认 500，上限 2000）。
  - 过滤：`action=` 支持 webhook 同款 glob（`*` 唯一通配符，新增导出
    `webhook.MatchGlob`）；被过滤掉的事件同样推进游标（与 webhook 语义一致，
    不会再次提供）。
  - 校验 fail-closed：未知组织、格式错误的 cursor、非法 glob、非法 limit
    一律 400，避免拼写错误静默导出全部日志。
  - 测试：`control/platform_audit_test.go`（归并顺序与 org 标注、游标续传、
    org/action 过滤与游标推进、limit 分页与 has_more、401、7 类 400 拒绝、
    时间戳为 UTC 真实时间）。
- M7d 已完成：组织 CRUD（平台托管组织）。
  - `control/org_registry.go`：平台注册表（独立 SQLite `platform.db`，
    `PRAGMA user_version` 迁移）+ `OrgRegistryConfig{Path, StateRoot,
    NewServer}`。ID 形如 `^[a-z0-9][a-z0-9-]{0,31}$`（同时是路径组件与路由
    键），状态目录由注册表推导（`<StateRoot>/<id>`），绝不接受请求里的路径
    （避免目录穿越）。
  - 校验 fail-closed（`validateManagedOrg`）：ID/名称/域名（≥1，通配符规则
    与路由一致）/MagicDNS 域（禁通配）/`server_url`（http(s)、无凭据/查询/
    片段，且 host 必须落在该组织域名内）。校验错误用 `orgAPIError{400/409}`
    类型携带状态，DB 故障不会被误报成客户端错误。
  - Router：组织表加读写锁，注册/加载逻辑抽成 `register`（配置型 + 托管型
    共用，域名冲突检测同一份）；新增 `CreateManagedOrg`（先写注册表、起不来
    就回滚行）、`UpdateManagedOrg`（仅 name/domains 可变；ID/server_url/
    MagicDNS 域不可变，客户端是按 URL 配置的）、`DeleteManagedOrg`（先把状态
    目录改名归档到 `<StateRoot>/deleted/<id>-<ts>` 再停止服务并删行，重新创建
    同一 ID 不会继承旧身份库/密钥）。
  - 平台 API：`POST /api/platform/v1/organizations`（201）、
    `PATCH .../{id}`、`DELETE .../{id}`（返回 archivedAt）；配置型组织
    PATCH/DELETE 返回 409，未启用注册表时返回 403。`PlatformOrg` 增加
    `managed` 字段。
  - 进程接线：`-platform-state-dir`（多租户模式启用；要求设置
    `-platform-token-env`，单组织模式下拒绝）。托管组织继承部署的 logger，
    其余（OIDC/DNS/webhook/DERP map）不共享，保持租户隔离。
  - 并发的托管组织在 `Router.Start` 之后创建时会立即 `Server.Start(ctx)`。
  - 测试：`control/org_registry_test.go`（CRUD/重复/不存在/持久化重开、
    11 条校验拒绝、归档改名与幂等、状态目录推导）、
    `control/platform_orgs_test.go`（HTTP 全生命周期 + 路由跟随 + 独立 Noise
    key + 列表 managed 标记、11 条 400/409/404 拒绝表、未启用注册表 403、
    跨进程重启后同一 Noise key）。
- 待办（M7 剩余）：`api/v2` 组织级 API 版本。说明：每个组织已经通过 Host
  路由直接提供 `/api/v2/*`（M5d），组织生命周期在 `/api/platform/v1`
  （M7a/M7d）；若还需要"组织自省"的 v2 形状，应先补 spec 定义再实现
  （不猜 API）。

---

## M8 — 自动化与集成 —— 进行中

- M8a 已完成：Webhook 事件投递（`webhook/`）。
  - 游标驱动：新表 `webhook_cursors`（身份迁移 v6）+ `ListAuditAfter`；
    投递语义 at-least-once、每端点有序、重启后续传（无 server-local 队列，
    AGENTS §9）。接收方按 payload 的 delivery ID 去重。
  - 签名：`X-Xunara-Signature: sha256=<hex HMAC-SHA256(secret, "<ts>.<body>")>`
    （`webhook.Sign` 导出给接收方/测试）；secret 只从环境变量读取
    （单组织 `-webhook-secret-env`，多组织 `secret_env`），空 secret 拒绝启动。
  - 端点校验：仅 https 或 loopback http；不跟随重定向（避免把签名交给
    重定向目标）；`events` glob（仅 `*`，其他通配符拒绝）按审计 action 过滤。
  - 失败策略：5xx/429/网络错误 → 指数退避重试（上限 1 分钟），游标不动；
    4xx（除 408/429）→ 记录 error 并跳过该事件（避免毒事件卡住队列）；
    写游标失败按失败处理。
  - 接线：`control.Config.Webhooks`；`Server.Start` 启动 dispatcher；
    xunarad `-webhook-url/-webhook-secret-env/-webhook-events`，组织表
    `"webhooks": [{"id","url","secret_env","events"}]`（每组织独立投递）。
  - 测试：`webhook/webhook_test.go`（顺序/签名/头、过滤与游标推进、500 重试后
    成功、400 丢弃且不阻塞、配置校验表、glob 表）、
    `control/webhook_test.go`（真实注册审计事件端到端经签名投递）、
    `identity/sqlite_webhook_test.go`（游标往返/回退、ListAuditAfter 顺序与限长）。
- M8b 已完成：Webhook 投递租约与持久化退避（多实例去重）。
  - identity 迁移 v8：`webhook_cursors` 增加 `attempts` / `retry_at` /
    `claim_owner` / `claim_expires_at`（与游标同一行）。
  - `WebhookCursorStore` 新增：ClaimWebhookEndpoint（到期租约可被接管、
    单条 UPDATE + INSERT OR IGNORE 原子竞争）、RenewWebhookClaim（仅 owner，
    返回 false 表示被接管）、ReleaseWebhookClaim、WebhookRetryState /
    SetWebhookRetryState。
  - dispatcher：每个端点单写者（先抢租约，续租 goroutine 被接管即停止），
    失败后指数退避写入数据库、启动时先等待持久化的 `retry_at`（上限
    MaxBackoff）再投递；成功清零。`Config.InstanceID`（缺省随机）标识实例。
  - 测试：`identity/sqlite_webhook_test.go`（租约竞争/接管/续租归属/释放、
    退避往返与游标互不覆盖）、`webhook/webhook_test.go`
    （两个实例共享 store 只投递一次、holder 停止后接管、
    重启后遵守持久化 retry_at）。
- M8c 已完成：Webhook 管理 API 与 Console 页面。
  - identity 迁移 v9：`webhook_endpoints`（id/url/secret/events/enabled/
    时间戳）+ `WebhookEndpointStore`（Create/Get/List/Update/Delete，删除时
    一并删除该端点的投递游标）。
  - 运行时管理：`POST/GET /api/v2/webhooks`、`DELETE /api/v2/webhooks/{id}`
    （需 ScopeWrite；创建返回 201，ID 冲突 409，校验失败 400）；
    console `/console/webhooks`（列表 + 创建表单 + 删除按钮，写操作需
    admin/owner 且带 CSRF）。
  - 密钥处理（AGENTS §8）：创建请求的 secret 只在 POST body 中出现，
    入库前用 AES-256-GCM 密封（`control/webhook_secret.go`，密钥文件
    `state/webhook.key` 0600、O_EXCL 创建、权限校验），存储值为 `v1:` 前缀
    密文；API/console 任何响应都不回显 secret；日志只记录端点 ID。
  - 与配置型端点共存：`initWebhooks` 合并启动配置与托管端点（ID 冲突拒绝
    启动），两者共用一个 dispatcher、游标与租约；配置型端点只能改启动配置，
    API/console 删除返回 409。
  - dispatcher 支持运行时 `Upsert`/`Remove`（每代 owner 独立，替换 goroutine
    不会释放后继租约）。
  - 审计：`webhook.created` / `webhook.deleted`。
  - 测试：`control/api_v2_webhooks_test.go`（生命周期 + 真实投递 + 列表不泄漏
    secret、校验表、密封往返/篡改/换密钥/密钥文件权限）、
    `control/console_test.go`（console 创建/删除、配置型保护、只读角色）。
- 待办（M8 剩余）：gRPC API。

---

## M10 — Node key rotation（兼容性核心，已完成）

目标：同一台机器（machine key 不变）换新 node key 重新授权时，原地更新既有节点，
不产生重复 peer。对齐上游 `hscontrol/state`（`HandleNodeFromPreAuthKey` 的
in-place re-registration 与 `HandleNodeFromAuthPath` 的 reauth/convert 语义）。

- `control/rotation.go`：
  - `rotationCandidate` 选取要原地轮换的唯一节点：tagged 节点，或属于本次授权身份的
    节点；tags-only 预认证密钥可转换任意单一 user-owned 节点（上游语义）。
    机器键对应多个候选（tagged + user-owned、或多个 user-owned）时拒绝（409），
    不任意挑一个。
  - `rotateNodeKey` 保留节点身份与历史（ID / StableID / 地址 / 路由 / 端点 /
    LastSeen / Created），更新 node key、hostname/hostinfo、Method、Expiry 与
    Ephemeral；`GetNodeByNodeKey` 旧键立即失效。仍然强制 1:1
    NodeKey↔MachineKey（新键已绑到别的机器时 409，避免 node key 索引投毒）。
  - 标签规则：交互式审批由审批人的 tag 决定（空集把 tagged 节点转回 user-owned，
    对齐上游 reauth）；预认证密钥带标签时替换标签（含 user→tagged 转换），
    不带标签的密钥保留既有标签（对齐“复用同一把密钥保留管理员改过的标签”）。
- 接线：`registerWithAuthKey`（轮换需要一把仍然有效的密钥——已烧掉的单次密钥
  不能轮换，`.Usable` 失败返回 401，节点保持原样）与 `approveDevice`
  （交互式 relogin 经设备审批后原地轮换）。
- 审计：`node.key_rotated`（detail 含新旧 node key 短公钥；公钥不是秘密）。
  peers 经既有 `PeerChange.Key` 补丁看到新 node key。
- 测试：`control/rotation_test.go`（auth key 原地轮换且不重复、旧键失效、身份/地址
  保留、node.key_rotated 审计；已用单次密钥拒绝轮换且节点不变；标签替换与保留；
  交互式 relogin 原地轮换；歧义归属 409）。

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
