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
- 内层端点：`/machine/{register,map,set-dns,feature/query,audit-log,update-health,whoami,id-token,set-device-attr}` 与 SSH check 已实现，不再有 501；TKA 见 M11、ID token 见 M13、姿态属性见 M14（均已完成）；Funnel 未处理。

---

## M2 — 完整 netmap（Mapper，已完成）

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

已完成（M2b 剩余）：
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

## M3 — 持久化与密钥（已完成）

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
- 客户端信号（M15a）：`RegisterResponse.NodeKeyExpired` 在已知节点重连且 node key
  已过期时置位，官方客户端据此立即生成新 key 重注册（`doLoginOrRegen`），不必等
  一次 netmap；机器仍 `MachineAuthorized`（过期的只是 key）。新 key 走交互审批
  后原地轮换：ID/StableID/machine key 不变、旧 key 注销、有效期刷新。
- 客户端缩短有效期（M15b）：已知节点重连时携带 `RegisterRequest.Expiry`
  （客户端 `SetExpirySooner`，GUI 的 "set expiry sooner"）→ 只允许**缩短**，
  落地后写审计 `node.expiry_shortened` 并唤醒 netmap 流；尝试延长返回 400
  （不静默忽略）；`Expiry` 为零（永不送期：tagged 节点或无过期策略的部署）
  时拒绝改为有限值；过去时间仍是 logout，语义不变。
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

## M4 — Identity & Login（Trust Plane，已完成）

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

## M5 — Platform API 与 Web Console（已完成）

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
- M5 剩余：gRPC 已由 M8d 以平台服务面覆盖（`xunara.v2.PlatformService`）；
  Webhook 已完成（M8a）。

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

## M6 — 服务与客户端（已完成）

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
  - `PATCH /machine/set-device-attr` 与 `POST /machine/id-token` 当时都是
    501（不假装接受再丢弃）；id-token 见 M13，姿态属性见 M14，两个端点均已
    实现。
  - 测试：`control/machine_misc_test.go`（审计落库与净化、未知 action 400、
    跨节点 404、health 204/绑定、whoami 成功与未注册 404）。
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
- `services/`：Funnel 明确不支持；Discovery 见 M16（Xunara Atlas）。
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
  - 已知限制（M9 剩余）：无。Remote 已由 M22（Xunara Reach，spec §29）交付，
    File Transfer 已由 M18（Xunara Flux，spec §25）交付；credential 的列出/
    吊销已完成：M5d 的 `/api/v2/agent-tokens` 与 console Agents 页面。
- ~~ACL/Zero Trust（`Xunara Warden`）。~~ 已完成（M28）：只读管理面（spec §34）。

---

## M7 — 多租户（Organizations，已完成）

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
- 待办（M7 剩余）：无。"组织自省"的 v2 形状已由 M23 交付（spec §30）：
  `GET /api/v2/organization` + gRPC `GetOrganizationIdentity`；组织生命周期
  仍在 `/api/platform/v1`（M7a/M7d）。

---

## M8 — 自动化与集成（已完成）

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
- M8d 已完成：平台 API v2 over gRPC（`api/proto/xunara/v2/platform.proto`）。
  - 服务 `xunara.v2.PlatformService`：GetMeta / ListMachines / ListAudit /
    ListWebhooks / RevokeAgentToken，语义与 `/api/v2` 一一对应（同一套
    service API Key、scope + 角色规则、同一 base64 游标与页面边界，
    secret 永不回传）。无缓冲流：每次调用独立、可重试。
  - 认证与 HTTP 共享 `Server.principalForToken`（Bearer 从 gRPC
    `authorization` metadata 读取，只认 Bearer scheme）；未认证
    `UNAUTHENTICATED`，缺 scope/角色不足 `PERMISSION_DENIED`，坏游标/
    坏过滤 `INVALID_ARGUMENT`，未知 agent token `NOT_FOUND`。
  - 多组织：以 gRPC `:authority` 选组织（等价 HTTP Host，含 wildcard 与端口
    归一化），未知 authority 返回 `NOT_FOUND`；跨组织凭据不会通过校验
    （AGENTS §12）。
  - 接线与生命周期：`Config.GRPCListenAddr` / `RouterConfig.GRPCListenAddr`
    （xunarad `-grpc-listen`，空值关闭 gRPC），与 HTTP 监听并行；ctx 取消时
    `GracefulStop`（10s 未完成转硬停），绑定失败在启动时即报错。
  - 兼容性：不改动 TS2021 / Noise / MapRequest 与 key 规则；gRPC 只是平台面
    的第二个传输。
  - 测试：`control/grpc_platform_test.go`（未认证与坏凭据、meta 字段与不泄漏、
    机器分页/过滤/坏游标、审计过滤与游标续传、webhook 列表与 secret 不回传、
    吊销权限/幂等/404/审计、authority 选组织与跨租户拒绝、Serve gRPC
    生命周期与坏地址）。
- M8e 已完成：部署级平台管理面 over gRPC（`xunara.v2.PlatformAdminService`）。
  - 服务镜像 `/api/platform/v1`：ListOrganizations / GetOrganization /
    CreateOrganization / UpdateOrganization / DeleteOrganization /
    ListAudit（跨组织审计导出，保持"每组织游标 + 过滤事件也推进游标"语义）。
  - 认证只接受进程级平台令牌（常量时间比较）：未配置令牌一律
    `PERMISSION_DENIED`（fail closed），错误/缺失令牌 `UNAUTHENTICATED`；
    组织自己的 session 或 API key 永远不能到达该服务（AGENTS §12）。
  - HTTP 错误映射沿用同一份 `orgAPIError` 状态：400→`INVALID_ARGUMENT`、
    409→`ALREADY_EXISTS`、404→`NOT_FOUND`、配置型组织只读→
    `FAILED_PRECONDITION`、未启用注册表→`PERMISSION_DENIED`。
  - `UpdateOrganization` 用 `optional` 字段表达 PATCH 语义：`name` 缺失即
    不变，`domains` 用 `StringList` 包装以区分"缺省"与"清空"。
  - 审计导出的解析（org/cursor/action/limit）抽成纯函数，HTTP 与 gRPC
    共用同一套校验，避免两份实现漂移。
  - 测试：`control/grpc_platform_admin_test.go`（令牌缺失/错误/被禁用、
    组织 key 越界拒绝、CRUD 生命周期与域名规范化、重复 ID/域名 409、
    校验 400、配置型组织只读、归档路径、注册表未启用、跨组织审计导出与
    游标续传、glob/游标/组织名校验）。

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

## M11 — Tailnet Lock（TKA，已完成）

目标：控制面成为 tailnet 的 key authority（TKA）存储与分发点——保存 AUM 链、向
节点提供 `/machine/tka/*` RPC、把每个节点的 node-key signature 广播进 netmap，
让客户端之间互相验证 node key 而不是信任控制面。协议形状以官方客户端为准
（`reference/tailscale/ipn/ipnlocal/tailnet-lock.go`），不改变 TS2021/Noise/MapRequest。

- `state`（迁移 v7/v8，向后兼容的新列/新表）：
  - `Node.KeySignature`（`tkatype.MarshaledSignature`，BLOB，可空）——netmap 广播的
    node-key signature。
  - `Node.NLKey`（`key.NLPublic`，TEXT，迁移 v8）——注册时上报的 tailnet-lock 公钥。
    它是"节点可自行轮换 node key"的前提：管理员签名时把 `NLKey.Verifier()`（raw
    ed25519）作为 `TKASignInfo.RotationPubkey` 包进签名，节点之后就能用自己的 NL
    私钥把旧签名链成 rotation 签名，无需再次联系管理员。
  - `tka_meta` 单行表 + `TKAStore`（`TKAMeta`/`SetTKAMeta`）：`EverEnabled`、
    `Enabled`（init/finish 之后才为真）、`Disabled`、密封后的 support disablement
    secret。`Store` 接口内嵌 `TKAStore`，内存与 SQLite 实现同步更新
    （`nodeColumns`/`scanNode`/INSERT/UPDATE 全部覆盖新列）。
- `control/tka.go`：`tkaManager` 持有链（上游 `tailchonk`，落盘 `stateDir/tka/`，
  因此磁盘格式与上游一致）与密封密钥（`stateDir/tka_secret.key`，0600）：
  - `initBegin(genesis)` 只安装链，不生效；`enable(secret)` 在 init/finish 原子地
    开启 enforcement 并密封 support disablement secret；`disable(secret)` 用
    `Authority.ValidDisablement` 校验后关闭 enforcement（链保留，便于审计与
    重新初始化）；`bootstrap()` 返回 genesis AUM（+禁用后的 secret）。
  - `syncOffer`/`syncSend`（`ToSyncOffer`/`Authority.SyncOffer`/`MissingAUMs`/
    `Inform`）、`verifyNodeSignature`（`NodeKeySignature.Unserialize` +
    `NodeKeyAuthorized`）、`nodeKeyAuthorized`。
- `control/tka_handlers.go`（全部 GET + JSON body，路径与客户端一致）：
  `/machine/tka/{init/begin,init/finish,bootstrap,sync/offer,sync/send,disable,sign,affected-sigs}`。
  每个请求的 `NodeKey` 必须属于 Noise 会话的 machine key（与其它内层端点同一认证），
  并受 capability 下限约束。init/finish 先整体校验再写入，避免半启用状态。
- `control/tka_netmap.go` + mapper：`MapResponse.TKAInfo`（从未启用 → nil；启用 →
  `{Head}`；禁用 → `{Disabled:true}`，避免 delta 里 nil 被当成"不变"）、
  `tailcfg.Node.KeySignature`、未签名节点在**他人** netmap 中
  `UnsignedPeerAPIOnly=true`；只要链已启用，self CapMap 就带上
  `tailscale.com/cap/tailnet-lock`（官方客户端据此启动 TKA 同步循环）。
- 防火墙收窄：客户端会整体丢弃"允许未签名 peer"的 packet filter（fail closed），
  因此启用 TKA 且存在未签名节点时，`*`/`0.0.0.0/0`/`::/0` 源被展开为已签名节点的
  地址与它们服务的路由；显式命中未签名地址的规则整条丢弃（不做部分相减）。
- 注册路径：`RegisterRequest.NodeKeySignature` 在启用状态下必须通过
  `NodeKeyAuthorized` 校验，否则整个注册被拒（401），避免把无法验证的授权声明静默
  降级成"未签名节点"；未启用（或已禁用）的 tailnet 上签名不具权威，直接丢弃，绝不
  落库（真正有效的签名由 init/finish 重新签发）。校验通过的签名随注册落库并广播。
  交互式登录时签名与 `NLKey` 先随设备授权元数据持久化（跨实例、跨审批可用），审批
  建节点/原地轮换时一并生效；`req` 里为零值的 `NLKey` 不会清空已存的值。
- node key 轮换（对齐上游 `doLoginOrRegen` / `RegisterResponse.NodeKeySignature` 语义）：
  - 客户端换 node key（key 过期、`tailscale up` 重新认证——两者客户端都本地判定，
    控制面只负责答复）时在 `OldNodeKey` 里带上旧 key。若旧节点持有签名，控制面在
    `RegisterResponse.NodeKeySignature` 里回传旧签名，客户端用 `tka.ResignNKS` 自行
    生成 rotation 签名后重试注册；该响应不建节点、不开始登录，客户端据此只做一次重试。
  - 只有带 `WrappingPubkey`（即管理员按 `RotationPubkey` 签过）的签名会被回传，且
    请求上报的 `NLKey` 必须与该 wrapping key 一致：否则节点根本无法链签，回传只会
    换来一次注定失败的校验，此时直接走普通注册/登录路径。
  - logout、follow-up 轮询、新 node key 已注册、machine key 不匹配的请求都不回传。
  - 轮换时 `KeySignature` 随 node key 一起替换（旧签名的 Pubkey 指向旧 key，留着会让
    peer 把节点判成未签名）；`NLKey` 属于机器、跨轮换保留。
- 审计：`tailnet_lock.enabled` / `tailnet_lock.disabled` / `tailnet_lock.node_signed`。
- 测试：
  - `control/tka_test.go`：manager 生命周期（init 未生效 → enable → 重启恢复 →
    disable/re-init）、同步 offer/send（含幂等与 stale 节点）、签名校验（恶意/未知
    签名拒绝）、禁用后拒绝写入。
  - `control/tka_e2e_test.go`：真实 Noise 会话上的完整链路（init begin/finish →
    netmap 广播 head/capability/signature → 未签名节点被标记并收窄防火墙 →
    sync pull → `/tka/sign` 解禁 → `affected-sigs` → disable 后 `TKAInfo.Disabled`
    与 bootstrap 返回 secret）；流式会话收到显式的启用/禁用帧；注册携带可信/不可信
    signature 的接受与拒绝；未启用 tailnet 上提交的签名不落库。
  - node key 轮换全链路：`init/begin` 下发 `RotationPubkey`（等于节点上报的
    `NLKey.Verifier()`）→ 管理员按它签名 → 换 key 注册先拿到旧签名（hint）→
    `tka.ResignNKS` 生成的 rotation 签名通过校验并随设备审批落库 → 节点原地轮换
    （ID/StableID/地址不变、旧 key 注销、netmap 广播新签名、重复注册幂等）；无
    rotation key 的签名不回传 hint。
  - `control/tka_netmap_test.go`：防火墙收窄规则（通配展开、未签名源丢弃、exit route
    不得回流）。
  - `state`：`TKAStore` 一致性（内存/SQLite）、`KeySignature`/`NLKey` 往返、SQLite
    重启后 meta 保留、v7 → v8 迁移（旧库缺少 `nl_key` 列时能直接升级）。
- 已知限制（后续里程碑）：
  - 控制面从不代替管理员重签 node key：rotation 签名必须由节点自己的 NL 私钥生成，
    控制面只保管公钥（TKA 威胁模型不允许把管理员/节点的 NL 私钥交给控制面）。
  - ~~控制面尚未返回 `RegisterResponse.NodeKeyExpired`~~：已由 M15a 实现。
  - 未提供 CLI/Platform API 的 TKA 状态与初始化入口（协议面已完整，官方客户端
    可直接使用 `tailscale lock ...`）。

---

## M12 — Tailnet Lock 管理面（只读状态，已完成）

目标：把 TKA 的运行状态交给运维与自动化（CLI、平台 API、Console），补上 M11
「无 CLI/Platform API 入口」的限制。启用/禁用/签名仍由持有 NL 私钥的客户端经
`/machine/tka/*` 驱动——控制面不代持任何私钥（AGENTS.md §5/§8），所以这一层只读。

- `control/tka_status.go`：`Server.TKAStatus()`（`everEnabled`/`enabled`/`disabled`/
  `head` + `nodes{total,signed,unsigned}`）。数据取自 netmap 与 `/machine/tka/*`
  共用的同一个 manager，平台面不会与客户端看到的状态漂移；head 与"节点是否已有
  签名"本就是 netmap 公开信息，响应不含 AUM 链内容、可信 key 材料或密封的
  disablement secret。
- HTTP：`GET /api/v2/tka`（read scope；未认证 401、缺 scope 403）。
- gRPC：`PlatformService.GetTailnetLock`（同一份状态与相同的 scope 规则；
  `platform.proto` 补上可复现的 protoc 生成命令，`api/gen` 已重新生成）。
- Console：Overview 增加 Tailnet lock 段落——未启用 / 已启用（chain head、已签名
  节点数）/ 已禁用（链保留）三态。
- CLI：`xunara tka status [-state-dir]`（只读）。读 SQLite 的 `tka_meta` 与
  `<state-dir>/tka` 链（`tka.ChonkDir` + `tka.Open`，不创建目录、不写入），并交叉
  校验「启用但磁盘无链」「有链但库说从未启用」两种不一致并告警。
- 明确不做：init/disable/sign 的 CLI/API 入口。genesis AUM 必须由管理员持有的
  NL 私钥在本地生成并签名（`tailscale lock init`），把它搬进控制面等于让控制面
  代持管理员私钥，会让 TKA 的威胁模型失效。
- 测试：`control/api_v2_test.go`（三态、字段形状、未认证 401）、
  `control/grpc_platform_test.go`（未认证/缺 scope、与 HTTP 同值）、
  `control/console_test.go`（Overview 三态渲染）、`cmd/xunara/tka_test.go`
  （缺失/空/有链三种 state dir）。

---

## M13 — Workload Identity（`/machine/id-token`，已完成）

目标：让节点向第三方（云厂商 STS、Kubernetes、内部服务）证明自己的 tailnet
身份。官方客户端 `tailscale id-token <aud>`（需 `TAILSCALE_USE_WIP_CODE=1`）
经 Noise 发 `tailcfg.TokenRequest{CapVersion,NodeKey,Audience}` 到
`POST /machine/id-token`，期望 `tailcfg.TokenResponse{IDToken}`；claim 集合
以 `tailcfg.TokenResponse` 的注释为准（上游控制面实现不开源，不猜 API）。

- `idtoken/`（新包，只做签名与轮换，不认识任何 tailnet 概念）：
  - RSA-2048 密钥环 `<state-dir>/id_token_keys.json`（0600，PKCS#8 PEM，
    原子 temp+rename 写入）；kid = RFC 7638 JWK thumbprint（从公钥推导，
    手改文件无法让两把钥同名）。
  - 懒生成：从不签发 token 的部署不会有密钥文件。每次使用都重新读盘，因此
    `xunara id-token rotate` 对运行中的服务立即生效。
  - `TTL=15m`；`KeyGrace=TTL+5m`。轮换不删旧钥：旧公钥继续留在 JWKS，直到它
    签过的 token 全部过期（+时钟偏移余量），所以没刷新 JWKS 的依赖方仍能验签；
    过期钥在下次读盘时清除（JWKS 不会无限增长）。
  - 权限过宽的文件（group/other 可读）直接报错拒绝使用；解析失败时若内存中
    已有可用密钥则告警并继续（不因一个坏文件让控制面停止签发）。
- `control/idtoken.go`：
  - `POST /machine/id-token`（Noise 内层）：版本门 → audience 非空且 ≤256
    字节 → `getAndValidateNode`（NodeKey 必须属于本会话的 machine key，跨节点
    404）。签发 RS256 token 并落审计 `identity_token.issued`（target=节点，
    detail=audience；token 永不入日志/审计）。
  - Claims：`iss`=ServerURL，`sub`=节点 MagicDNS FQDN（含尾点），`aud`、`exp`
    （+TTL）、`iat`、`nbf`、`jti`（16 字节随机）；私有 claim `key`（node public
    key）、`addresses`（/32、/128）、`nid`、`node`、`domain`、`tags`
    （`<domain>:<tag>`，非 tagged 节点为空数组）、`user`/`uid`（仅非 tagged
    节点；`<provider>:<login name>`，与注册响应的 Provider 一致，绝不使用裸
    email，AGENTS §5/§6）。
  - `GET /.well-known/jwks.json`：公开公钥（`use=sig`，RS256，Cache-Control
    max-age=300）；响应里没有任何私钥字段。
  - `GET /.well-known/openid-configuration`：只声明 `issuer`、`jwks_uri`、
    `id_token_signing_alg_values_supported`、`subject_types_supported`、
    `claims_supported`。不声明 authorization/token/userinfo 端点：本服务不是
    登录 OP，声明不存在的端点会误导依赖方（AGENTS §3）。
  - 未配置 `ServerURL` 时（没有可作为信任锚的 issuer）端点返回 501，
    `/.well-known/*` 404：宁可不签，也不签出 issuer 为空的 token。
- CLI：`xunara id-token show [-state-dir] [-issuer]`（当前 active/retired 密钥）、
  `xunara id-token rotate [-state-dir]`（打印新 kid）。只操作状态目录，不需要
  服务在跑。
- 信任模型（同时写在代码注释里）：issuer 就是控制面自身；任何已注册节点都能为
  自己（且仅为自己）取任意 audience 的 token。还没有"哪些节点可以联邦"的 grant
  （上游是 tsidp capability），所以管理员只应在"整个 tailnet 的节点都允许以自身
  身份认证"时把该 issuer 配进依赖方。~~尚未做按节点/按 audience 的限流~~
  已由 M21 交付（spec §28）。
- 测试：`idtoken/idtoken_test.go`（0600 建钥、JWKS 验签往返、轮换后旧钥仍可验
  已签发 token、grace 后裁剪、权限过宽/坏文件拒绝、Keys 视图）、
  `control/idtoken_test.go`（端到端拿 token → 用公开 JWKS 验签并断言全部 claim、
  tagged 节点无 user/uid、跨节点与未注册会话 404、audience 校验与版本门、
  无 issuer 时 501/404、JWKS 只有公有字段、discovery 内容）、
  `cmd/xunara/idtoken_test.go`（无密钥/有密钥/轮换三种 show 输出）。
- 管理面（与 M12 同一模式：只读、无密钥材料）：
  - HTTP `GET /api/v2/id-token`（read scope）；`GET /api/v2/meta` 增加
    `identityTokensEnabled`。
  - gRPC `PlatformService.GetIDTokenIssuer`（相同的 scope 规则与相同的值；
    `Meta.identity_tokens_enabled` 同步；`platform.proto` 与 `api/gen` 已重新
    生成）。
  - Console Overview 增加 "Workload identity" 段落：未启用（无 issuer URL）/
    已启用（issuer、jwks_uri、密钥数、active kid、TTL）/ 密钥不可用告警
    （权限或文件损坏时只降级该段落，不影响整页）。
  - 状态读取会让密钥环就位（与 JWKS 首次拉取一致）——否则"配置了 issuer 但
    JWKS 为空"会让依赖方接入流程因为一个不真实的原因失败。
  - 测试：`control/api_v2_test.go`（未认证 401、write-only 403、字段与 active
    kid、无私钥字段、meta 标志、无 issuer 时 disabled 空数组）、
    `control/grpc_platform_test.go`（未认证/缺 scope、与 `Server.IDTokenStatus()`
    同值、无 issuer 时 disabled）、`control/console_test.go`（已启用渲染
    issuer/active kid、密钥不可用告警、无 issuer 文案）。
- 明确不做：`userinfo`/`authorize`/`token`（不是登录 OP）、按 audience 的授权
  策略与限流、token 撤销列表（短 TTL + 一次性签发；依赖方自行缓存 JWKS）。

---

## M14 — 设备姿态属性（`/machine/set-device-attr`，已完成）

目标：补上最后一个 501 内层端点。客户端（`tailscale set --report-posture` 的采集
链路，corp 构建）经 Noise 发 `tailcfg.SetDeviceAttributesRequest{Version,NodeKey,
Update}`（`AttrUpdate` = `map[string]any`，值可为 string / float64 / bool，
`null` 表示删除）到 `PATCH /machine/set-device-attr`；响应 200 即成功。

上游把该特性标为 experimental（tailscale/corp#24690），OSS 客户端里只有形状
（`control/controlclient/direct.go:SetDeviceAttrs` + localapi
`alpha-set-device-attrs`），没有消费方；属性值的语义（ACL `srcPosture` 条件）
在上游控制面里，不在开源代码中。因此本构建的实现边界是：

- 接受并**持久化**属性（不再"接受后丢弃"），审计"哪些属性被设置/删除"；
- 不发明姿态语义：ACL `srcPosture` 条件仍未实现，属性目前是信息性的，
  不参与任何允许/拒绝判断（这一点写进代码注释与本节，避免被误当成强制）；
- 属性值不写审计：姿态数据可能含设备标识（AGENTS §8）。

- `state`（迁移 v9）：
  - 新表 `node_device_attrs(node_id, attr, value, updated_at)`，主键
    `(node_id, attr)`，`FOREIGN KEY ... ON DELETE CASCADE`：删节点即删属性。
    `value` 存 JSON 标量文本，string/number/bool 的类型在往返后保持不变。
  - `DeviceAttrStore`（内嵌进 `Store`）：`SetNodeDeviceAttrs`（nil 值=删除，
    其余=覆盖；未知节点报错）、`NodeDeviceAttrs`（返回副本）、
    `NodeDeviceAttrCounts`（列表视图用计数，不携值）。内存与 SQLite 同步实现。
  - 旧库（v8）可直接升级，有测试。
- `control/deviceattrs.go`：
  - `PATCH /machine/set-device-attr`（Noise 内层）：版本门 →
    `getAndValidateNode`（只能写自己的属性，跨节点/未注册 404）→ 校验 →
    落库 → 审计 `node.device_attrs_updated`（detail 只列设置/删除的属性名，
    有序、截断）。空 update 是幂等 no-op。
  - 校验 fail-closed：名字非空、≤128 字节、可打印 ASCII 无空格；字符串值
    ≤256 字节且不含控制字符；number 必须有限；object/array 拒绝；一个节点的
    属性 ≤64 个、编码后 ≤4096 字节；一次 update ≤256 项。**整批原子**：任一
    项非法则整批 400，不部分应用。
  - 400 的错误文本只回显属性名（经净化），绝不回显值。
- 测试：`control/deviceattrs_test.go`（往返/合并/删除/幂等、审计只含属性名、
  跨节点与未注册 404、版本门、8 种非法输入、64 上限与删除回退、4096 字节上限、
  update 项数上限、审计 detail 格式、节点删除级联、未知节点边界，内存与 SQLite
  两种实现）、`state/sqlite_test.go`（v8→v9 迁移）。
- 管理面（只读，节点才能写、管理员只能读）：
  - HTTP `GET /api/v2/machines/{id}/device-attrs`（read scope；坏 id 400、
    未知机器 404；无属性时 `attrs` 是 `{}` 而非 null，客户端不必特判状态）；
    `GET /api/v2/machines` 的每个条目增加 `deviceAttrCount`（0 时省略字段），
    让自动化不必逐台拉取就能定位有姿态数据的机器。
  - gRPC `PlatformService.GetMachineDeviceAttrs`（`state.NodeID` 解析、
    NotFound/Internal 语义与 HTTP 一致；值经 `structpb.Value` 转换）。
    `ListMachines` 的 `Machine.device_attr_count` 同 HTTP 计数。
  - Console Machines 表格增加 "Posture" 列（`N attr(s)` 或 `—`）。
  - CLI：`xunara posture list`（只列有属性的机器与数量）、
    `xunara posture show <id|stable-id>`（打印属性名与值；找不到节点报错）。
    无写入口：姿态只有节点自己能上报，管理面永远只读。
  - 测试：`control/api_v2_test.go`（401/403/404/400、字段、空 `{}`、列表计数与
    0 省略）、`control/grpc_platform_test.go`（未认证/缺 scope、NotFound、值与
    HTTP 同、ListMachines 计数、无属性空集）、`control/console_test.go`
    （单复数计数与 `—`）、`cmd/xunara/posture_test.go`（只列有属性的机器、
    不泄漏值、空库提示、stable-id 查找、未找到错误）。
- 明确不做：ACL `srcPosture` 条件（需要上游控制面的策略语义，开源代码里没有
  可以照抄的判定规则）；属性的过期/回收策略（节点可覆盖或删除，删节点级联）。

---

## M16 — Xunara Atlas 服务发现（v1，已完成）

目标：节点把自己提供的服务（名字、协议、端口）发布到控制面，其它节点与
管理员能发现它；访问控制仍由既有 ACL/grants 决定（发现 ≠ 授权）。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §22（先写 spec 再实现，
不猜 API）。

- `state`（迁移 v10）：`node_services`（name 为主键=组织内唯一，node_id 外键
  `ON DELETE CASCADE`，metadata 存 JSON）。`ServiceStore`：`ReplaceNodeServices`
  （声明式整批替换、原子、保留 created、跨节点/请求内重名
  → `ErrServiceNameTaken`）、`ListServices`/`ServicesForNode`/
  `GetServiceByName`/`NodeServiceCounts`。内存与 SQLite 同步实现，共享一致性
  套件 + v9→v10 迁移测试。
- 数据面（M16b）：`POST /api/agent/v1/services`（原生客户端协议；agent token +
  machine/node key 复述）。限额 fail-closed 且整批原子：name 小写 DNS label
  ≤63、protocol ∈ {tcp,udp}、port 1–65535、metadata ≤16 项且编码 ≤2 KiB、
  每节点 ≤32、组织 ≤512（429）。冲突（他人服务名/节点 hostname/DNS 记录）
  → 409。审计 `node.services_updated`（只记名字/协议/端口），唤醒 netmap。
- MagicDNS：`extraDNSRecords()` 追加派生 A/AAAA（`<name>.<domain>` → 发布节点
  地址）。官方客户端按名字解析、按既有 ACL 连接；撤销服务即撤销记录。
- 管理面（只读，与 M12/M13/M14 同一模式）：
  - HTTP `GET /api/v2/services`（read scope；`node=<id|stable id>` 未知匹配空集、
    `name=` 精确过滤、name 游标分页）；`GET /api/v2/machines` 增加
    `serviceCount`（0 省略）。
  - gRPC `PlatformService.ListServices`（同规则/同值）与
    `Machine.service_count`；`platform.proto` 与 `api/gen` 已重新生成。
  - Console 新增只读 Services 页（名字/协议/端口/DNS 名/发布节点/metadata），
    Machines 表格增加 Services 计数列。
  - CLI `xunara services list|show <name>`（直接读状态目录；DNS 名依赖部署
    配置的域，由平台 API 提供）。
- 原生客户端（M16d）：`xunara-agent services publish -file <file> | list |
  clear`。声明文件 `<state-dir>/services.json`（0600、原子写，只有服务端接受
  后才落盘；与凭据文件分离）；`xunara-agent run` 每 `-services-interval`
  （默认 5m）重读声明并重发——声明式收敛，服务端对未变化集合 no-op（不写库/
  不审计/不唤醒 netmap），所以刷新只在控制面丢数据（如恢复备份）时才有动作。
  客户端本地预检名称/协议/端口/metadata（镜像服务端限额，服务端仍是权威）。
- 目录导入（M16e，Consul，spec §23）：`xunara-agent services import -from consul
  [-consul-addr ...] [-dry-run]`。导入器在**节点侧**运行，控制面拿不到目录凭据，
  §22.2 的"节点是唯一写入者"边界不变。读 `GET /v1/agent/services`（字段对照
  `hashicorp/consul` 的 `api/agent.go`，含 `DefaultPort` 规则）；ACL token 只从
  `CONSUL_HTTP_TOKEN` 读取、只走 `X-Consul-Token` 头。映射 fail-closed：跳过
  Connect proxy/gateway、unix socket、peering 引入、空名/非法名/非法端口/metadata
  超限（跳过原因告警，不含值）；同名多注册协议端口一致则去重、不一致整名跳过；
  结果超过 32 条 → 导入失败（不截断，截断等于撤销）；`-dry-run` 打印声明 JSON
  且不需要已注册的 agent。客户端预检抽到 `protocol.ValidateServices`（单一来源）。
- 测试：state 一致性套件；`control/services_test.go`（发布/替换/清空/审计、
  认证三种失败、20 条非法输入、冲突、预算、DNS 记录、相同集合 no-op、原生
  客户端端到端 round trip）；`control/api_v2_test.go`、
  `control/grpc_platform_test.go`、`control/console_test.go`（页面与计数列）、
  `cmd/xunara/services_test.go`；客户端 `client/protocol`（发布/撤回/错误
  映射、声明校验）、`client/daemon`（声明文件、刷新循环、文件重读）、
  `client/catalog`（Consul 映射/跳过/告警/凭据头/错误/超限）、
  `cmd/xunara-agent/services_test.go`（文件解析、校验、渲染、导入发布与
  dry-run）。
- 明确不做（v1）：按 ACL 的可见性（与 MagicDNS 节点名一样组织内可见）、
  跨组织共享、与上游 `svc:` VIP 互通（需要上游控制面语义，不猜 API）、
  控制面代理流量。
- ~~下一步（未做）：Kubernetes 服务导入~~ 已由 M20 交付（spec §27）；
  ~~Atlas 健康状态与自动摘除~~ 已由 M19 交付（spec §26）。

---

## M17 — Passkey / WebAuthn 登录（已完成）

目标：Human Identity 增加 passkey（WebAuthn）注册与登录。Passkey 只登录人类
用户，永远不授权机器；ceremony 与 OAuth transaction/session/device
authorization 分离（AGENTS §5/§10）。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §24（先写 spec 再实现）。

- 身份层（M17a，已完成）：`identity` 迁移 v10 新增 `webauthn_credentials`
  （credential_id 全局 UNIQUE、credential 存 JSON、last_used_at）与
  `webauthn_ceremonies`（browser_session_hash、expires_at、consumed_at）；
  `Store` 内嵌 `PasskeyStore`/`PasskeyCeremonyStore`；`DeleteUser` 级联删除。
  `identity.PasskeyService`：RP 配置 fail-closed（RPID 裸域且非 IP、origin
  必须 https/loopback 且属于 RPID、UV 缺省 required、timeout 60s 强制）；
  usernameless 登录（discoverable credential）、exclusions、ceremony TTL
  5 分钟、浏览器绑定 secret（库里只存 SHA-256）、SQLite 事务内单次消费、
  sign counter/LastUsedAt 回写。测试覆盖配置校验、注册+登录端到端、错误绑定
  不产生消费以外的副作用、重放、跨 RPID/origin、handle 稳定、级联删除。
- 控制面接线（M17b，已完成）：`control.Config.Passkeys`（nil 关闭，配置错误
  启动失败）；登录页在启用时改为选择页（不再自动选中唯一 provider）并渲染
  passkey 按钮，`POST /passkey/login/begin|finish`（HttpOnly ceremony cookie，
  成功走既有 `CreateSession`，审计 `login.succeeded` detail=method=passkey）。
  Console `/console/passkeys`：任意角色管理自己的凭据（列表/添加/删除，
  JSON 端点用 CSRF header，删除仅限本人）；审计 `passkey.registered`/
  `passkey.deleted`。janitor 清理过期 ceremony。cmd/xunarad：
  `-passkey`（默认开）/`-passkey-rpid`/`-passkey-origin`/
  `-passkey-display-name`，未显式配置时从 `-server-url` 推导（不可用时告警
  并关闭，不阻塞启动）；显式配置错误启动失败；多租户 org config 按各
  `server_url` 推导。
- 收尾（M17c，已完成）：控制面浏览器流测试（software authenticator 手工
  attestation/assertion：注册+登录往返、单次消费重放 400、跨浏览器绑定、
  未配置 404/页面提示、跨账号删除拒绝、janitor 回收、审计断言）、
  cmd/xunarad 推导测试、`IDENTITY_LOGIN.md` §20 状态说明；全量
  gofmt/vet/test 与 `-race`（control/state/identity/idtoken/cmd/xunarad）通过。
- 明确不做（v1）：账号恢复、attestation 策略/AAGUID 白名单、conditional UI、
  管理员代管 passkey、登录 begin 限速（反向代理负责）。

---

## M18 — Xunara Flux 文件投递（v1，已完成）

目标：两台 `xunara-agent` 之间投递文件，控制面存储转发 + 端到端加密
（spec §25）。不触碰 TS2021/Noise/netmap；与官方 Taildrop 不互通。

- M18a（完成）：`state` 迁移 v11 `flux_transfers`（id/双方节点/名字/大小/
  sha256/状态/收件人公钥/时间戳/过期），`FluxStore`（创建、按节点列出、
  条件 UPDATE 的状态转移、配额计数、过期与终态清理、级联删除），内存与
  SQLite 同步实现 + 一致性套件。
- M18b（完成）：控制面 `/api/agent/v1/flux/transfers`（报价/接受/拒绝/取消/上传/
  下载/完成/失败；密文落盘 `<state-dir>/flux/<id>.bin` 0600 原子写；
  限额/状态机/参与方校验 fail-closed；审计 flux.*；janitor 过期与孤儿清理）。
- M18c（完成）：客户端 `client/flux`（X25519+HKDF+AES-GCM 封装、种子
  0600）+ `client/protocol`（flux 类型与九个客户端方法，凭据全部走头）+
  `xunara-agent flux send|list|deny|receive`（接收端显式确认、解密后校验
  SHA-256 才 complete；不覆盖已存在文件，改名 `name.1` 等）+ 单元与真实
  控制面端到端测试（send→accept→upload→download→complete、deny 理由回传、
  无终端拒绝隐式接受）。
- 明确不做（v1）：与官方客户端 Taildrop 互通、断点续传/分片、目录递归、
  杀毒/DLP、控制面明文可见、ACL 细粒度授权（v1 以收件人显式接受为授权；
  ACL 集成留待后续 spec）。
- 已补（M26）：部署接线。此前 `xunarad` 没有任何开关能打开 Flux，控制面端点
  在生产不可达；现在 `-flux`（默认关）与组织表 `flux_enabled` 显式启用，
  规格见 §25.7。

---

## M19 — Xunara Atlas 服务健康与自动摘除（v1，已完成）

目标：节点声明"服务是否就绪"，控制面把未就绪或失联的服务从 MagicDNS
**发现**中自动摘除，就绪后自动恢复。声明仍由节点唯一写入（§22.2）；控制面
不探测、不代理、不故障转移；健康只影响发现，不是安全边界——连接授权始终由
既有 ACL/grants 决定。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §26（先写 spec 再实现）。

- `state`（迁移 v12）：`node_service_health`（node_id 外键 `ON DELETE CASCADE`，
  name，healthy，reported_at，until，主键 `(node_id, name)`）+ 过期索引。
  `ServiceStore`：`ReportServiceHealth`（事务内校验节点存在、名字必须是本节点
  已声明且 `health=true`、重复报错；上报是完整集合，未列出者置 not ready；
  返回**转变清单**）、`ExpireServiceHealth`（healthy 且 `until < now` → 摘除）。
  内存与 SQLite 同步实现，共享一致性套件 + v11→v12 迁移测试；重新发布声明
  保留同名且仍启用健康的服务的状态（刷新不让 DNS 抖动），关闭健康或改名清空。
- 数据面：`POST /api/agent/v1/services/health`（agent token + machine/node key
  复述；整批原子，未知/未跟踪/重复/超 32 条 → 400 且状态不变）。转变时审计
  `service.healthy`/`service.unhealthy`（target=节点，detail 为
  `<name>/<proto>:<port>` + reason reported/report expired，只在转变时写），
  并唤醒 netmap 流。
- 摘除：`extraDNSRecords()` 跳过生效 unhealthy 的服务；janitor 用独立 15s
  扫描（与 1 分钟整体节奏解耦）处理过期上报，只动启用健康且当前 healthy 的行。
- TTL：`control.Config.ServiceHealthTTL`（默认 90s，30s–15m，越界启动失败）；
  `xunarad -services-health-ttl` 与组织配置 `service_health_ttl` 接线。
- 节点侧：声明中 `"health": true`；就绪来自 `<state-dir>/services-health.json`
  （缺失 = 全部 not ready，fail-closed）；`xunara-agent run` 每
  `-services-health-interval`（默认 30s）发送完整上报；文件里未声明或未启用
  健康的名字忽略并告警，解析失败本周期不上报（服务最迟在 TTL 后摘除）。
- 管理面：HTTP `/api/v2/services`、gRPC `ListServices`、Console Services 页、
  CLI `xunara services list|show` 增加 `health`/`healthReportedAt`（不跟踪的
  服务省略）；仍然只读。
- 测试：`state` 一致性套件（上报/重发不抖动/过期）；`control/service_health_test.go`
  （生命周期与审计 actor、校验失败状态不变、TTL 过期摘除、HTTP/gRPC/原生客户端
  读面）；`control/console_test.go`（Health 列）；`client/protocol`（请求形状与
  错误映射）、`client/daemon/health_test.go`（文件格式、上报构造、循环上报与
  403 停止）；`cmd/xunara/services_test.go`、`cmd/xunara-agent/services_test.go`
  （列/提示）、`cmd/xunarad/orgconfig_test.go`（TTL 解析与越界拒绝）。
- 明确不做（v1）：主动探测（控制面到不了尾网地址）、故障转移/负载均衡、健康
  历史/评分、按 ACL 的可见性、Consul 导入自动启用健康、控制面代理流量。

---

## M20 — Xunara Atlas 目录导入（v1，Kubernetes，已完成）

目标：把**本节点提供**的 Kubernetes Service 转换为 Atlas 声明（§27），与
M16e 的 Consul 导入同一模式：导入器在节点侧运行，控制面拿不到集群凭据，
节点仍是唯一写入者（§22.2）。

- 连接与凭据（fail-closed）：默认 in-cluster（`KUBERNETES_SERVICE_HOST/PORT`
  + ServiceAccount token/ca.crt/namespace，已对照 client-go `rest.InClusterConfig`
  核实）；可用 `-k8s-api/-k8s-token-file/-k8s-ca-file/-k8s-namespace` 覆盖。
  token 只从文件读、只走 `Authorization: Bearer`；`-k8s-api` 只接受 https 或
  loopback http（token 不发明文）；namespace 必须是 DNS-1123 label（防路径
  注入）；节点名必填（`-k8s-node` 或 Downward API 的 `NODE_NAME`），禁止用
  Pod hostname 猜测。
- 读取：`GET /api/v1/namespaces/{ns}/services` 与
  `GET /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices`，跟随
  `metadata.continue` 分页（页大小 200、上限 50 页 / 5000 对象，响应 16MiB）。
  已核对上游 registry strategy：EndpointSlice 没有 `spec.nodeName` field
  selector，所以按节点过滤在导入器内做（`endpoints[].nodeName`）。
- 映射（fail-closed）：只导入注解 `xunara.io/advertise: "true"` 的 Service；
  必须有本节点就绪端点（`conditions.ready != false`；null=unknown 按就绪，
  与 kube-proxy 一致）；端口取本地 slice 的 `ports[]`（协议缺省 TCP，只接受
  tcp/udp，SCTP/空端口跳过），多端口需 `xunara.io/port: <name>` 指定，否则
  整个跳过并告警；metadata 仅来自 `xunara.io/metadata` 注解的 JSON 对象，
  labels/其它注解绝不整体导入（注解常带凭据）；告警不回显注解值。
- 限额与原子性同 §23.2：>32 条整批失败不截断；发布仍走既有数据面
  （`services.json` 只在服务端接受后更新）。
- 命令面：`xunara-agent services import -from kubernetes [...] [-dry-run]`，
  RBAC 只需命名空间内 `get/list services` 与 `get/list endpointslices`。
- 测试：`client/catalog/kubernetes_test.go`（映射表：未启用/无本地端点/
  not-ready/nil-ready/udp 去重/不支持端口/多端口注解/metadata 不泄漏/
  排序/超限；真实 TLS API 伪服务端的鉴权头、命名空间路径、分页、CA 校验、
  403 不泄漏 token；配置拒绝表与 in-cluster 缺省检测）、
  `cmd/xunara-agent/services_test.go`（publish 与 dry-run 全流程、NODE_NAME
  默认、缺节点名报错）。
- 明确不做（v1）：watch/持续同步（快照导入，与 Consul 一致）、Pod/容器、
  ClusterIP 直接导入、把 EndpointSlice 就绪写入 `services-health.json`
  （健康仍只由 §26 的文件驱动）、跨命名空间批量导入。

---

## M21 — Workload Identity 签发限流（v1，已完成）

目标：补上 M13 明确留下的缺口——`/machine/id-token` 之前没有限流，任何已注册
节点都能以任意 audience 无限索取签名。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §28。

- `state`（迁移 v13）：`rate_limits(scope TEXT PRIMARY KEY, window_start,
  count)`；`RateLimitStore.AllowRate(scope, limit, window, now)`（固定窗口，
  返回 `retryAfter`）与 `PruneRateLimits(before)`。内存与 SQLite 共享同一份
  窗口语义（`consumeRate`），一致性套件覆盖窗口重置、scope 隔离、参数拒绝、
  清理与并发上限不变式；v12→v13 迁移测试。
- 控制面：签发前按 `(节点, audience)` 桶计数（窗口 1 分钟，默认 30）；
  超限 429 + `Retry-After`，不签发、不写审计（避免日志放大）。janitor 每轮
  清理窗口早于 1 小时的桶。
- 配置：`control.Config.IDTokenRateLimit`（0=默认，负数启动失败）、
  `xunarad -id-token-rate-limit`、组织配置 `id_token_rate_limit`。
- 测试：`state/ratelimit_test.go`、`control/idtoken_test.go`（两次成功、第三次
  429 且 Retry-After 合法、不同 audience/不同节点各自计数、默认值与非负校验）、
  `cmd/xunarad/orgconfig_test.go`（负值拒绝）。
- 明确不做（v1）：tailnet 级/全局限流、按 token 的配额与计量、按 audience 的
  授权策略（仍是"任意节点可为自身取任意 audience 的 token"）。

---

## M22 — Xunara Reach 远程命令执行（v1，已完成）

目标：从一台节点对另一台节点执行命令并流式回传输出；**目标节点显式审批**，
控制面只编排会话与中继输出块，不碰进程、不开隧道。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §29。

- 边界（v1 明确不做）：无 PTY、无 stdin（stdin 为空）、不经 shell（argv 逐元素
  `exec`）、不提权、无断点续跑、不穿透 NAT（与 §25 同一存储转发模式）。
- `state`（迁移 v14）：`reach_sessions`（id/双方节点/state/argv/timeout/exit
  code/error/时间戳）+ `reach_chunks`（`(session_id, stream, seq)` 主键，随会话
  级联）。CAS 状态机 `offered → accepted → running → succeeded|failed`，
  另有 denied/canceled/expired；`StartReachSession` 把截止时间换成执行窗口
  （timeout + 30s 报告宽限）。限额常量集中导出（argv ≤16 项且 ≤16KiB、每项
  ≤4KiB、timeout ≤15m、块 ≤24KiB、总输出 ≤2MiB、单次读 ≤64 块、同对节点并行
  ≤8、offer 寿命 5m）；重复 seq 返回 `ErrReachChunkDuplicate`（幂等由调用方
  负责），超总量返回 `ErrReachOutputLimit`（显式截断，绝不静默）。内存与
  SQLite 两套实现语义一致，v13→v14 迁移测试。
- 控制面 `/api/agent/v1/reach/sessions`（`control/reach.go`，`ReachEnabled`
  时挂载）：create/list/get/accept/deny/start/chunks(POST+GET 游标)/finish/
  cancel；只有两端可读（非参与者与未知 ID 同为 404），目标独占 accept/deny/
  start/chunks/finish，任一方可 cancel。创建按节点限流（复用 §28 的持久化
  限流器，10s 内 6 次，429 + `Retry-After`）；未知/自指目标 404；状态不允许
  的动作 409；argv/timeout/stream/seq/块大小在 API 边缘 fail-closed 校验
  （400/413）。认证与其它 agent 端点相同（bearer + machine/node key，POST 体
  或 `X-Xunara-*` 头二者其一）。janitor 每分钟把逾期未终态的会话置为
  `expired`（审计 actor=system）并删除终态满 1 小时的会话。
- 审计：`reach.offered/accepted/denied/started/finished/failed/canceled/
  expired`；**argv 与输出永不进审计**（只进会话记录与 CLI 输出）。
- 客户端：`client/protocol/reach.go`（类型 + 全部端点封装）、
  `client/daemon/reach.go`（目标侧执行循环：只在本地 `accept` 后取走会话，
  CAS claim 防重复执行、每会话一个 watcher 把 cancel/expiry 变成杀进程、
  输出按 ≤24KiB 分块中继并自行守住 2MiB 上限、超时/超限/启动失败都回写
  `failed`，进程重启遗留的 running 会话报 `target agent restarted`，最多
  8 个并发执行）。
- 命令面：`xunara-agent reach offer|run|list|show|accept|deny|cancel|serve`。
  `reach run` 一条命令走完 offer → 等审批 → 流式打印 stdout/stderr → 用远端
  退出码退出；`accept <id>` 打印完整 argv（知情同意）；`run` 默认启动执行循环
  (`-reach=false` 关闭)，`reach serve` 可单独常驻。控制面 `xunarad -reach`
  （默认关，组织配置 `reach_enabled`）。
- 测试：`state/reach_test.go`（生命周期 CAS、重复/越界块、输出上限、配额、
  过期与删除、形状校验、拷贝隔离、SQLite 级联、v13→v14 迁移）、
  `control/reach_test.go`（全流程 + 失败/拒绝/取消、权限矩阵、参数校验、
  块限额、限流、janitor 过期与保留、Reach 关闭 404、审计不含 argv）、
  `client/daemon/reach_test.go`（未审批不执行、双流输出中继、非零退出/超时/
  输出超限、cancel 杀进程、重启遗留会话）、`cmd/xunara-agent/reach_test.go`
  （真实控制面端到端 run + 退出码映射、拒绝路径、argv/参数解析、退出码映射、
  表格渲染）。
- 明确不做（v1）：交互式终端、sudo/runas、持久会话、控制面代理数据面、
  写操作式的 Console 页面；只读管理面在 M24 补上（规格 §31）。

---

## M23 — 组织自省（v1，已完成）

目标：任何已认证的调用方都能确认"我现在连的是哪个组织"，供多租户客户端、
自动化与排障使用。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §30（先写 spec 再
实现——这是 M7 明确留下的最后一项）。

- HTTP `GET /api/v2/organization`（read scope）：返回 `id`/`name`（单租户
  部署省略）、`domains`（路由域，恒为数组、绝不 null）、`managed`、
  `magicDnsDomain`、`serverUrl`；永不返回用户/节点/密钥/secret。
- 身份的权威来源是 Host 路由：Router 注册 OrgSite 时把
  ID/Name/Domains/managed 交给该组织的 Server（`Server.setOrganization`，
  `atomic.Pointer` 读写，平台面改名与请求读取可并行）；托管组织 PATCH
  name/domains 后自省结果同步更新，ID 不可变。请求无法指定组织——跨组织的
  凭据在别的 Server 上不会通过校验，未知 Host 仍是 404。
- gRPC `PlatformService.GetOrganizationIdentity`：语义、认证、错误映射与
  HTTP 一致（未认证 `UNAUTHENTICATED`、缺 scope `PERMISSION_DENIED`、
  未知 authority `NOT_FOUND`），组织同样由 authority 决定，请求不带 ID。
- 测试：`control/organization_test.go`（单租户最小形状与 `domains: []`、
  401/scope、双组织按 Host 各自自省、跨组织凭据 401、未知 Host 404、托管
  组织改名后身份跟随、gRPC 语义与权限）。
- 明确不做（v1）：组织级配额/计量、跨组织目录（`/api/platform/v1` 的
  ListOrganizations 只接受平台令牌）。

---

## M24 — Xunara Reach 管理面（只读，v1，已完成）

目标：管理员能回答"谁在什么时候对哪台节点跑了什么、结果如何"，供合规与
排障使用。规格见 `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §31。
只读：没有任何写入口（取消/重跑都不在 v1）。

- state：`ListAllReachSessions`（全部会话最新在前）与 `ReachOutputBytes`
  （每流字节数；SQLite 用 `SUM(LENGTH(data))`），内存与 SQLite 语义一致，
  纳入 conformance 子测试。
- HTTP `/api/v2/reach/sessions`（read scope）：列表支持 `state=`/`node=`
  过滤（未知 state 400、未知 node 空集，fail-closed）与 `(createdAt, id)`
  不透明游标；详情含 argv 与 `outputBytes`（只有计数）；`chunks` 与 agent
  端同形（`out`/`err` 游标，每流每请求 ≤64 块）；响应一律
  `Cache-Control: no-store`；Reach 未启用三个端点都是 404；坏 id 与不存在
  同为 404；永不返回密钥/agent token。
- gRPC `PlatformService.ListReachSessions`/`GetReachSession`：语义、认证、
  游标与错误映射与 HTTP 一致（未启用/未知会话 `NOT_FOUND`，坏 state/游标
  `INVALID_ARGUMENT`）；输出块只在 HTTP 暴露（2 MiB 调试文本不值得进
  类型化 API）。
- Console `/console/reach` 与 `/console/reach/{id}`：列表（state 过滤、最新
  在前、最多 200 条、argv 单行摘要）、详情（完整 argv、exit code、error、
  双流输出；HTML 转义、每流截断到 64 KiB 并显式标注、同时给出完整字节数）；
  只读、无写按钮；未启用时页面说明功能未开启（不是 404）。
- 边界（v1 明确不做）：管理面取消/重跑、输出导出下载、按 argv 全文搜索、
  长期归档。会话记录与输出就是 agent 用的那一份（janitor 1 小时后删除），
  管理面不产生第二份副本；argv/输出永不进审计/webhook/日志。
- 测试：`control/api_v2_reach_test.go`（HTTP 401/403、列表/过滤/游标、详情
  argv、chunks 游标、404、未启用 404、no-store；gRPC 认证/权限/分页/
  NotFound/未启用）、`control/console_test.go`（列表/详情渲染、argv 转义、
  state 过滤、输出截断与完整字节数、未启用说明页）。

---

## M25 — DERP 管理面（只读，v1，已完成）

目标：管理员能回答"这个组织给客户端下发了哪些 DERP 区域、节点现在落在哪个
区域"，用于排障与容量核对（spec §20 的 DERP Console）。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §32。只读：策略仍然
只由启动配置/组织表决定。

- HTTP `GET /api/v2/derp`（read scope、`Cache-Control: no-store`）：
  `policyMode`（inherit|none|regions，未配置策略渲染为 `inherit`，不是空
  字符串）、`policyRegions`（恒为数组）、`mapConfigured`（区分"部署未配置
  map，客户端保持内置默认区域"与"策略明确告诉客户端没有 DERP"）、
  `regionsServed`、`regions`（按 ID 排序，含 code/name/公开 relay
  `host:port`（去重排序）与该区域 HomeDERP 节点数）、`nodesWithoutHome`、
  `nodesWithUnservedHome`（策略收紧后的过渡态，下一次 map 请求清空并重新
  归属）。不含任何 secret。
- gRPC `PlatformService.GetDERPStatus`（api/proto 重新生成）：语义、认证与
  错误映射与 HTTP 一致（未认证 `UNAUTHENTICATED`、缺 scope
  `PERMISSION_DENIED`）；组织由 authority 决定，请求不带参数。
- Console `/console/derp`：策略摘要、区域表（ID/code/名称/relay/节点数）与
  节点归属表（hostname、stable ID、在线、HomeDERP；未归属与不再服务显式
  标注）；只读、无按钮。
- 无新状态：区域来自策略应用后的 map，节点归属来自现有节点记录；渲染器
  HTTP/gRPC/Console 三处共用，页面与端点不会不一致。
- 测试：`control/api_v2_derp_test.go`（401/403、no-store、区域与 relay 去重
  排序、节点计数与未归属/不再服务、regions/none/无 map 三种策略、gRPC
  认证/权限与字段）、`control/console_test.go`（页面渲染、只读、无 map 文案）。
- 明确不做（v1）：修改策略、按区域断连/重定位、DERP 中继流量统计（那是
  Veil 的运行指标，不在控制面）、历史趋势。

---

## M26 — Xunara Flux 部署接线（v1，已完成）

目标：Flux 控制面端点此前没有任何生产启用路径（`control.Config.Flux` 恒为
nil，端点 404），补上单组织 flag 与多组织组织表接线；规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §25.7。

- 单组织：`xunarad -flux`（默认**关**）、`-flux-dir`（默认
  `<state-dir>/flux`）、`-flux-max-size`（默认 8 MiB，硬上限 64 MiB）、
  `-flux-ttl`（默认 1h，上限 24h）。只给 dir/size/ttl 而不加 `-flux` 是配置
  错误，启动即失败；超范围的值由 `control.New` 拒绝并点名部署。
- 多组织：组织表 `flux_enabled` / `flux_dir` / `flux_max_size` / `flux_ttl`
  （同一套校验）；`flux_dir` 省略时每个组织用自己的 `<state_dir>/flux`，
  密文不跨租户共享目录。`-org-config` 模式下 flux 命令行开关与其它组织级
  flag 一样被拒绝（加入 `orgScopedFlags`）。
- 语义修正：`control.Config.Flux` 的注释此前写"Nil uses the defaults"，与
  `newFluxServer`（nil/Disabled = 关闭）矛盾；统一为 **nil 或 Disabled 都是
  关闭**，与 Reach 同为 opt-in——升级不会自行打开一个文件存储子系统。
  `examples/organizations.example.json` 增补 `flux_enabled`/`flux_ttl` 示例。
- 测试：`cmd/xunarad/flux_test.go`（关闭/设置缺开关/开启三态）、
  `orgconfig_test.go`（组织表开启、默认关闭、settings-without-enabled 拒绝、
  坏 `flux_ttl` 报错点名、`-org-config` 拒绝 flux flag）。

---

## M27 — Xunara Flux 管理面（只读，v1，已完成）

目标：管理员能回答"谁在什么时候给谁发了什么文件、结果如何"，同时不破坏
控制面零知识。规格见 `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md`
§33。只读：没有取消/删除，也**没有内容下载**。

- state：`ListAllFluxTransfers`（全部传输最新在前，管理面看双方），内存与
  SQLite 语义一致（共用一次查询/扫描辅助函数），纳入 conformance 子测试。
- HTTP `/api/v2/flux/transfers`（read scope、`Cache-Control: no-store`）：
  列表支持 `state=`/`node=` 过滤（未知 state 400、未知 node 空集，
  fail-closed）与 `(createdAt, id)` 不透明游标；详情按 ID。条目是第三人称
  视图（无 direction），且**不含** `recipientKey`、内容或任何路径——管理面
  根本没有内容端点。Flux 未启用时两个端点都是 404（与 agent 端点一致）；
  坏 id 与不存在同为 404。
- gRPC `PlatformService.ListFluxTransfers` / `GetFluxTransfer`（api/proto
  重新生成）：语义、认证、游标与错误映射与 HTTP 一致（未启用/未知传输
  `NOT_FOUND`，坏 state/游标 `INVALID_ARGUMENT`）；消息里没有任何内容或
  密钥字段。
- Console `/console/flux` 与 `/console/flux/{id}`：列表（state 过滤、最新
  在前、最多 200 条）与详情（名字、大小、状态、双方、SHA-256、reason、
  时间戳；明确说明文件内容端到端加密、不在控制面）；只读、无按钮；未启用
  时页面说明功能未开启（不是 404）。
- 复用：新增通用游标/顺序辅助（`apiV2EncodeTimeCursor`、`apiV2TimeCursor`、
  `newestFirstAfterCursor`），Reach 与 Flux 的 HTTP/gRPC 端点共用同一份
  实现，避免两套分页语义漂移。
- 测试：`state` conformance 新子测试（管理面看到全部参与方）；
  `control/api_v2_flux_test.go`（HTTP 401/403、列表/过滤/游标、详情、
  ciphertext 与 recipientKey 不泄漏、管理面无内容端点、未启用 404、
  no-store；gRPC 认证/权限/分页/NotFound/未启用）；
  `control/console_test.go`（列表/详情渲染、state 过滤、内容不渲染、只读、
  未启用说明页）。
- 明确不做（v1）：管理面取消/删除、内容下载/导出、按文件名全文搜索、
  跨组织视图、内容扫描（DLP 不在 v1，§25）。

---

## M28 — Xunara Warden 管理面（只读，v1，已完成）

目标：管理员能回答"这份策略到底写了什么、组里都有谁、自带的 tests 现在是否
通过"，同时策略仍只从磁盘加载、由 watcher 整体重载。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §34。只读：没有
编辑/热更新入口，也没有"在线编辑 ACL"的通道。

- policy：`Document.Clone`（深拷贝：含 grant capability 的 `json.RawMessage`、
  SSH `checkPeriod` 指针、`Unsupported`）与 `Engine.Document()`。管理面渲染的
  是副本，永远不会碰到 netmap 编译器正在使用的文档。
- HTTP `GET /api/v2/policy`（read scope、`Cache-Control: no-store`）：
  `configured`/`path`/`ruleCount`/`warnings`/`unsupported`/`loadError` + 各
  section（`acls`/`grants`/`groups`/`hosts`/`tagOwners`/`ssh`/`nodeAttrs`）；
  `checkPeriod` 渲染为 `"always"` 或 duration 字符串；数组恒为 `[]` 而非
  null，自动化客户端不必区分"缺失"与"空"。
- `loadError`：磁盘文件解析失败时 watcher 保留上一份可用策略，管理面明确
  说明"生效中的是哪份"，而不是 5xx。`tests` 对当前节点运行文档自带断言
  （与 `xunara policy check` 同语义）：无节点/无 tests/运行前校验失败时
  `ran=false` + `reason`；断言不满足是 `pass=false` + `failures`（数据，
  不是 HTTP 错误）。
- gRPC `PlatformService.GetPolicyStatus`（proto 重新生成）：语义、认证与
  错误映射与 HTTP 一致；grants 的 app 值以 JSON 文本传输，maps 用既有
  `StringList`。
- Console `/console/policy` 重写为 Warden 视图：规则/grants/组/hosts/
  tagOwners/SSH/nodeAttrs 表 + 自测结果 + warnings/unsupported/loadError；
  只读、无按钮（原页面只显示规则计数）。
- 测试：`policy/policy_test.go`（深拷贝独立性、engine 每次返回新副本）；
  `control/api_v2_policy_test.go`（未配置形状、完整 section、loadError、
  无节点不误报失败、歧义选择器仍是数据不是 5xx、gRPC 认证/权限/镜像）；
  `control/console_test.go` 新增 Warden 表格渲染与只读断言。
- 明确不做（v1）：编辑/热更新策略、按选择器解析当前节点（"谁能访问谁"）、
  任意流的按需评估、ACL 编辑器/语法高亮、grants `via`、ACL `srcPosture`
  条件（仍未实现，§M13/M14）。

---

## M29 — SSH 审批管理面（只读，v1，已完成）

目标：管理员能回答"谁正在尝试 SSH 到哪台机器、本地哪个账号、上次检查结果
如何"，不必等用户把 HoldAndDelegate 链接贴出来。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §35（spec §20 P2
"SSH Console"）。审批本身仍在 `/ssh/check/{authID}`（console session +
write 角色 + CSRF），管理面没有任何写入口。

- identity：`SSHCheckStore.ListSSHCheckSessions(limit)`（created_at DESC,
  id ASC 的最新在前分页来源；limit<=0 返回空），SQLite 实现复用同一份列
  定义与行扫描函数，管理面看的仍是审批流唯一那份记录。
- HTTP `GET /api/v2/ssh-check/sessions`（read scope、no-store）：派生状态
  `pending|expired|consumed|accepted|rejected`（互斥，TTL 优先于 verdict），
  同时保留原始 `verdict`（`consumed` 会掩盖判定方向）；列表条目就是详情
  （记录很小，v1 无详情端点）；节点删除后条目保留并只显示 `nodeId`。
  过滤 fail-closed：未知 `state=` 400；`node=` 接受节点 id/stable ID、匹配
  任一端，未知（包括 `0`）返回空集；`(createdAt,id)` 不透明游标，扫描上限
  1 万条（TTL 15 分钟内的自然边界，仅为坏 janitor 兜底）。
- gRPC `PlatformService.ListSSHCheckSessions`（proto 重新生成）：语义、认证、
  游标与错误映射与 HTTP 一致（坏 state/游标 `INVALID_ARGUMENT`；没有决定
  RPC）。
- Console `/console/ssh-check`（nav "SSH checks"）：状态过滤（未知值 400，
  与 API 一致）、最新 200 条、pending 高亮、判定与决定人；ID 链接到既有
  审批页，页面自身没有任何写表单。
- 测试：`identity/sshcheck_test.go`（最新在前、上限、已决定仍在列表）；
  `control/api_v2_sshcheck_test.go`（状态派生与顺序、两端详情、401/403、
  过滤 fail-closed 含 `node=0`、游标分页、gRPC 认证/镜像/错误映射）；
  `control/console_test.go`（渲染、状态过滤、无决定表单、未知 state 400）。
- 明确不做（v1）：管理面 approve/deny、删除/清理记录（janitor 按 TTL 负责）、
  按 local user/时间窗过滤、实时推送（长轮询仍在 `/machine/ssh/action`）。

---

## M30 — API 密钥 Console 管理面（v1，已完成）

目标：管理员不必登录机器执行 `xunara apikey`：在 Console 里看到自动化凭据
（Service Identity API Key）的清单、按需创建并把 token 一次性展示、即时
吊销。规格见 `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §36
（spec §20 P1 "OAuth/API Keys"）。

- Console `/console/api-keys`（nav "API keys"）：列表显示 ID/name/owner/
  scopes/创建/过期/最后使用/吊销时间，**永不显示 token**；创建（write 角色 +
  CSRF，name 必填、scope 至少一个、TTL 可选）后一次性展示 `xunara_…`；
  吊销幂等（已吊销再点不报错）；审计沿用 `apikey.created`/`apikey.revoked`，
  detail 标明 through the console。
- 身份边界不变：key 是 Service Identity（AGENTS §5）；owner 恒为当前登录
  用户，且 scope 只是上限——服务端仍要求 owner 角色允许 write，Console
  创建不出超过创建者角色的凭据。
- 不加 v2/gRPC：自动化面仍是既有的 `/api/v1/api-keys` 与 CLI（同一张
  identity 表，多包一层 API 只会引入语义漂移，spec §36 已说明）。
- 测试：`control/console_test.go`（创建一次性 token、列表不泄漏、token
  真实可用、吊销后 401、二次吊销幂等、缺 name/scope 400、member 看不到
  写控件且 POST 403）。

---

## M31 — 能力发现补齐（/api/v2/meta，已完成）

目标：`/api/v2/meta` 是"调用前发现可选能力"的端点（§27–§36 的每个管理面
都以它为准），补齐已交付能力中遗漏的字段，并修正 `webhooksEnabled` 的失真
语义。规格见 `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §37。

- 新增 `reachEnabled`（§31，`cfg.ReachEnabled`）、`fluxEnabled`（§33，Flux
  服务已构建）、`passkeysEnabled`（passkey 登录，服务已构建）；gRPC
  `PlatformService.GetMeta` 同步（proto 重新生成 `reach_enabled`/
  `flux_enabled`/`passkeys_enabled`）。
- `webhooksEnabled` 修正为"存在会投递的接收端点"：启动配置的端点，或任一
  `Enabled` 的托管端点（Console/API 创建）。此前只看启动配置，运行时创建的
  端点在 meta 里不可见；暂停的托管端点不投递、不计入。判据抽成
  `Server.webhooksEnabled()`，HTTP 与 gRPC 共用。
- meta 仍只回答"是否启用"：不列端点明细、不携带 secret；既有字段语义不变。
- 测试：`control/api_v2_test.go`（裸服务器四项 false；开启 Reach/Flux/
  Passkeys 后 true；暂停托管端点不翻转；经 `/api/v2/webhooks` 创建端点后
  无需重启即 true）；`control/grpc_platform_test.go`（配置端点场景可选面
  false；开启后三项 true；托管端点 true、暂停后 false）。

---

## M32 — Xunara Share（跨组织机器共享，已完成）

目标：把一台机器共享给**另一个组织**的某个用户，双方节点的网图只在相关节点
之间出现合成对等体，不交换真实地址、节点 ID、用户 ID、tags 或策略。产品语义
参考 MirageServer 的 MachineShare（邀请 → 接受/拒绝 → 吊销），协议只使用官方
客户端既有的共享字段（`Node.Sharer`、`Hostinfo.ShareeNode`、
`SelfNodeV4/V6MasqAddrForThisPeer`），不改兼容协议。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §38。

- 平台级 SQLite `shares.db`（`-platform-state-dir` 下，与 `platform.db` 同级）
  是本里程碑的启用开关：没有它 `/api/v2/shares` 与 Console 页都是 404/说明页，
  `meta.sharingEnabled` 为 false。参与共享的组织必须在同一 Router 进程内。
- 生命周期：`pending → accepted | rejected`，任一状态可 `revoked`（幂等）；
  `(source_org, source_node, target_org, provider, subject)` 只在未终态时唯一。
  目标身份键恒为 `(target_org, provider_id, subject)`，`local` provider 不可作为
  目标；创建进源组织审计，接受/拒绝/吊销进目标组织审计。
- `/api/v2/shares`：direction=outgoing|incoming（未知 400）；创建需 write
  scope，accept/reject 只认目标身份（否则 404，不泄漏存在性），吊销源侧需
  write 角色、目标用户可撤自己的；任一组织启用 TKA → 409。
- 网图（§38.4）：接收方节点看到被共享机器的合成节点 ID（`1<<40` 起）、合成
  用户档案（`1<<41` 起，LoginName 为不可路由的 `shared+…@xunara.invalid`）与
  本组织地址空间里的 masq 地址（IPv4 `100.127.0.0/16`、IPv6
  `fd7a:115c:a1e0:ffff::/64`，持久化、重启不丢、吊销后保留复用）；源侧节点的
  网图对接收用户节点做同样处理，并置 `Hostinfo.ShareeNode=true`。地址分配器
  跳过 masq 段，双向 `SelfNodeVxMasqAddrForThisPeer` 取对端在同一分配表里的
  地址，官方客户端即可完成 SNAT/DNAT。共享节点在策略里是无 tag 成员，
  `*`/`autogroup:member` 可匹配，`user:`/`group:` 不匹配。
- Console `/console/shares`（nav "Shares"）：outgoing/incoming 两个表、创建表单
  （机器 + 目标组织 + provider + subject）、accept/reject/revoke 按钮；创建在
  write 角色 + CSRF 下，接受/拒绝是目标用户自己的决定（任意登录角色 + CSRF），
  页面不含任何密钥材料。
- 测试：`control/share_registry_test.go`（状态机、唯一性、目标身份查询、
  重启持久化）、`control/api_v2_shares_test.go`（两端可见性、fail-closed、
  未知 direction、非目标 accept 404、重复 409、吊销后可再共享、TKA/禁用）、
  `control/shares_netmap_test.go`（合成 ID/地址稳定唯一、双向 masq 一致且不撞
  本端真实地址、`ShareeNode`、第三方不可见、吊销后消失但命名空间复用、重启
  不变、策略可见、sharer 与 owner 分离），`control/console_shares_test.go`
  （创建/接受/吊销、CSRF、只读角色、禁用页），`state`/`identity` 的 masq 段
  跳过与合成命名空间持久化。

---

## M33 — Xunara Security Center（只读，已完成）

目标：把分散在各面的安全姿态聚合成一个快照 + 一组可执行发现，管理员不必
逐页翻查就知道 tailnet 处在什么状态、下一步该修什么。只读、不新增存储、不含
密钥材料。规格见 `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §39
（spec §20 P2 "Security Center"）。

- HTTP `GET /api/v2/security`（read scope）与 Console `/console/security`
  （nav "Security"，任意角色可读）渲染同一份视图：tailnet lock、policy、
  节点（online/expired/expiringSoon/unsigned/tagged/untagged/ephemeral/
  exitNodes）、pending devices、auth keys、API keys、sharing 计数、webhooks、
  DERP 口径；全部来自既有状态，不复制 ACL 内容、不报 key 名/ID。
- findings（high/medium/low/info，按 severity→id 稳定排序）：
  `policy.absent`（allow-all）、`policy.load_error`（文件解析失败，仍在执行
  上一份好文档）、`tka.unsigned_nodes`、`nodes.expired_keys`、
  `apikeys.never_expires`、`nodes.keys_expiring`（30 天）、
  `devices.pending`。没有 0–100 评分：不用不可审计的数字替管理员做决定。
- Console 页含节点密钥到期表（到期时间升序、上限 200 行）与分组件的计数，
  不显示任何 token/secret/节点密钥；页面没有写入口。
- 不新增 meta 字段（页面永远可用）；不做 gRPC（只读管理面走 HTTP/Console，
  与 §31/§33/§35 同理）；不做实时监控/告警/扫描/合规映射（§39.4）。
- 测试：`control/security_test.go`（计数覆盖全部维度、findings 顺序与
  severity 合法、策略 load error、TKA 签名前后 finding 增减、sharing 计数、
  响应不泄漏 auth key 与设备元数据、Console 任意角色可读且无表单）。

---

## M34 — Xunara Horizon 管理面（Exit Nodes，只读，已完成）

目标：把 exit node 的供给与消费放到一个面上——哪些节点被批准为 exit node、
每台正在被哪些节点使用、哪些选择已经失效。批准/撤回仍在 Machines 页（路由
审批），出口选择永远在客户端本地。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §40（spec §20 P0
"Exit Nodes"）。

- HTTP `GET /api/v2/exit-nodes`（read scope）与 Console `/console/exit-nodes`
  （nav "Exit nodes"，任意角色可读）：exitNodes 按 nodeId 升序列出批准了默认
  路由的节点（online、**announced**、地址、DERP home、lastSeen、客户端数与
  客户端列表）；clients 按 nodeId 升序列出所有上报了 `Hostinfo.ExitNodeID`
  的节点（exitNodeStableId、可解析时的 hostname、resolved）。
- 判据：批准（ApprovedRoutes 含 0.0.0.0/0 或 ::/0）是控制面授权事实；是否
  正在广播（`IsExitNode`）单独报告，"已批准但不再广播"显示为异常而不是消失。
  选择失效（撤回/删除/未知 stable ID）保持可见并标 unresolved，不静默丢弃；
  没有选择的节点不进入 clients。
- 只读、无表单、无写入口；不返回节点密钥或地址以外的网络细节。
- 不做：远程选择/取消 exit node、流量统计/按流日志、自动选择与故障转移、
  per-app 分流（§40.3）。
- 测试：`control/exit_nodes_test.go`（批准/未批准/撤回、使用关系归组、
  unresolved、无选择不出现、HTTP 401/200/member、Console 渲染与无表单）。

---

## M35 — 设备授权管理面（v1，已完成）

目标：把"等待批准的设备"从浏览器页面变成可审计、可自动化的 API 面。设备授权
是机器身份的准入环节：客户端在注册时提交 `(machine key, node key)` 对，人在此
确认"这台机器可以被接入"，而不是把自己的身份变成机器身份。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §41（spec §20 P1
"Device/User Approval"；User 侧即 OIDC 首次登录自动建用户 + 角色管理，不新增
存储）。

- HTTP `GET /api/v2/devices`（read scope）：pending 且未过期的授权，最新在前，
  上限 500 条（超出 `truncated=true`，截断最旧）；字段 `id/hostname/os/
  ephemeral/requestedTags/created/expires`，**不含 machine key / node key**
  （v1 形状不变）。
- HTTP `POST /api/v2/devices/{id}/approve|deny`（write scope + 可写角色）：
  复用 `approveDevice`/`denyDevice`——批准创建/原地轮换节点并唤醒注册，拒绝记录
  状态并唤醒注册；未知 404、过期 410、反向决策 409、重复同向 200（幂等）；
  审计 actor 是会话或 `user:N/apikey:key-X`。
- 审批只携带授权 ID，key 对从存储行读取，调用者无法替换 key（§5/§10/§11）。
- Console `/console/devices` 不变，只与 API 共用列表构造与决策函数。
- 不做：批量审批/规则引擎/自动批准、key 材料返回或接受、以他人身份批准或
  转移所有权、用户审批队列/邀请制/邮箱验证、gRPC（§41.3）。
- 测试：`control/devices_test.go`（匿名 401、member 可读、列表字段闭包与不泄漏
  key、read/member 决策 403、批准创建节点与归属、幂等、审计归属、拒绝后不再
  出现在列表、404/410/409、截断保留最新）。

---

## M36 — Xunara Relay 管理面（Peer Relay，只读，v1，已完成）

目标：把 peer relay（上游 mesh extension）的供给与授权放在一个面上——哪些节点
愿意作为 underlay UDP relay、哪些 ACL grant 允许谁从谁那里分配 relay 端点、
两者是否对得上。只读；relay server 与 relay 使用都是客户端本地决定。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §42（spec §20 P3
"Mesh Extensions"）。

- 协议面复用既有能力（本里程碑不改变 wire 输出，只加验证）：relay grant（`app`
  含 `tailscale.com/cap/relay`）→ `FilterRule.CapGrant` + `relay-target`
  companion（`grants.go` 已有）；供给 = `Hostinfo.PeerRelay`；策略开关 =
  `nodeAttrs` 的 `disable-relay-server` / `disable-relay-client`（既有透传）。
- `policy/relay.go`：`Engine.RelayGrants(nodes)` 把 relay grant 解析成节点对
  （`dst: autogroup:self` 按源展开），供管理面使用。
- HTTP `GET /api/v2/relays`（read scope）与 Console `/console/relays`
  （nav "Relays"，任意角色可读）：relays（愿意供给 ∪ 被 grant 点名，按 nodeId
  升序，含 announced/disabled/clientDisabled/targeted）与 grants（源 → 目标）；
  不返回密钥、relay 端点或 VNI。
- 不做：远程启用/禁用 relay server/client、远程选择 relay/端点分配、流量统计、
  自动生成授权、gRPC（§42.3）。
- 测试：`policy/relay_test.go`（CapGrant 与 companion、非 relay 行不报告、
  selector 解析、self 展开、空关系丢弃）、`control/relays_test.go`（五种姿态、
  禁用可见性、HTTP 401/200/member、Console 无表单、真实客户端路径下
  grant/CapMap/PeerRelay 供给可见）。

---

## M37 — Xunara Serve / Funnel 管理面（只读）+ Flow Logs 结论（v1，已完成）

目标：为 spec §20 P2 的最后两项给出交付物——Serve/Funnel 的只读管理面，以及
Flow Logs 的明确结论。规格见
`Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md` §43/§44。

- HTTP `GET /api/v2/serve`（read scope）与 Console `/console/serve`
  （nav "Serve"，任意角色可读）：`certificates`（是否配置 DNS provider）、
  `certDomains`（附加证书域名）、`funnelSupported`（本构建恒 false）、
  `nodes`（`https` 授权 ∪ Funnel 报告 ∪ ingress 需求，按 nodeId 升序，含
  serve/funnel/wantsIngress/certDomains）；不返回证书或 ACME 挑战值。
- 判据：`https` nodeAttr → `CapabilityHTTPS`；证书可用性来自 `certDomainsFor`
  （无 provider 时为空数组）；Funnel 报告（`Hostinfo.IngressEnabled` /
  `WireIngress`）按事实显示为异常——策略加载拒绝 `funnel` 属性，本构建不运营
  公网 ingress。
- Flow Logs（§44）：明确不做。客户端 netlog 需要控制面下发
  `data-plane-audit-logs` 能力 + `DataPlaneAuditLogID`/`DomainAuditLogID` 并把
  流量元数据交给 Tailscale 的 logtail；Xunara 从不设置这两个 ID，因此不存在
  发往第三方收集器的路径。自建上报属于 Xunara Pulse 的新规格，不在 v1。
- 不做：远程启停 serve/Funnel、下发 serve 配置、公网 ingress、证书内容查看、
  流量统计、gRPC（§43.3）。
- 测试：`control/serve_test.go`（四种姿态、有无 DNS provider 的证书口径、HTTP
  401/200/member、Console 无表单跨角色可读）。

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
