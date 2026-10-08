# 部署 xunarad（控制面）

面向单个 systemd 主机的最小正规部署：一个非特权账号、一份只读二进制、一个状态
目录、日志交给 journald。命令行里不放任何 secret。

## 目录布局

| 路径 | 内容 |
|---|---|
| `/opt/xunara/bin/xunarad` | 控制面二进制（root:root 0755），`xunarad.previous` 是上一个版本 |
| `/etc/xunara/xunarad.env` | 环境变量与 secret（root:root 0600），`xunarad.env.example` 是模板 |
| `/etc/systemd/system/xunarad.service` | 单元文件，**所有启动参数都在这里** |
| `/var/lib/xunara` | 状态目录（`xunara:xunara` 0700，systemd `StateDirectory`） |

日志走 journald：`journalctl -u xunarad -f`。
（新加的用户需要重新登录才会进入 `systemd-journal` 组。）

单元里的 `-server-url`、监听端口与功能开关按本机部署填写；换主机或换域名时改
`ExecStart` 那一段（`deploy/systemd/xunarad.service`），并同步仓库中的这份文件。

## 安装 / 升级

```sh
# 构建（版本号写进 /version、控制台页脚与 `xunarad -version`）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X github.com/xunara/xunara/control.Version=$(git describe --tags --always --dirty)" \
  -o /tmp/xunarad ./cmd/xunarad

scp /tmp/xunarad root@host:/tmp/xunarad
ssh root@host 'XUNARA_PREFIX=/opt/xunara /path/to/deploy/install.sh /tmp/xunarad'
```

`install.sh` 可重复执行，就是升级路径：先备份旧二进制，再安装单元与状态目录，
最后 `systemctl enable --now`。回滚：

```sh
sudo install -m 0755 /opt/xunara/bin/xunarad.previous /opt/xunara/bin/xunarad
sudo systemctl restart xunarad
```

## 改配置

改 `/etc/systemd/system/xunarad.service` 里的 `ExecStart` 参数（监听地址、
`-server-url`、策略、DERP、Reach/Flux 开关等），然后：

```sh
sudo systemctl daemon-reload && sudo systemctl restart xunarad
```

Secret 只写进 `/etc/xunara/xunarad.env`（OIDC client secret、平台 token、webhook
签名密钥、DNS webhook token）。这些变量由 `*-env` 标志读取，不会出现在 `ps` 里。

## 首次初始化（必做）

全新的部署**没有**管理员密码：打开 `/console` 只会被送到登录页。第一次必须用
服务自己写出的一次性令牌创建管理员：

```sh
sudo cat /var/lib/xunara/setup-token     # 32 字节随机，0600，日志里只有路径
```

浏览器打开 `http://<host>:9090/`（首页 → 「初始化管理员」，或直接 `/setup`），
填入该令牌、登录名与密码（至少 12 个字符）。提交成功后令牌文件立即删除，
`/setup` 变为跳转登录页，账号成为 `owner`，审计记录 `admin.bootstrap`。

之后：

- 登录：`/login`（登录名 + 密码；GET 永远不会自动登录）；
- 邀请注册：控制台「Users → Invitations」创建邀请，把生成的
  `/signup?invite=...` 链接发给对方；链接只显示一次，服务器只存哈希。

若令牌文件被删掉或忘记密码且没有其他管理员：停服，删除
`/var/lib/xunara/local_credentials` 中对应的行（或整张表）后重启，服务会重新
写出一枚新的 `setup-token`。

## 状态、备份与升级注意

- 状态全在 `/var/lib/xunara`：节点、用户、Session、预认证密钥、审计、策略快照，
  Flux 的密文也在其下。备份该目录即可（先 `systemctl stop xunarad` 保证一致）。
- Session 存在状态目录里，不是进程内存：重启不掉登录，也是多实例的前提。

## 同机工具（可选安装）

`install.sh` 可以顺带安装两个二进制到同一前缀：

```sh
sudo deploy/install.sh /tmp/xunarad /tmp/xunara /tmp/xunara-agent
```

- `xunara`（管理 CLI）直接读写状态目录，因此必须以便于服务账号的身份运行，
  例如创建一把可复用预认证密钥（给节点做实测）：

  ```sh
  sudo -u xunara /opt/xunara/bin/xunara preauthkey create \
      -state-dir /var/lib/xunara -user 1 -reusable -expiry 24h
  sudo -u xunara /opt/xunara/bin/xunara user list -state-dir /var/lib/xunara
  ```

  预认证密钥与一次性凭据只在终端显示一次，不要贴进聊天工具或工单。

- `xunara-agent`（原生客户端）在网络可达的任何机器上运行，把预认证密钥放在
  环境变量里（不放命令行，`ps` 对同机所有用户可见）：

  ```sh
  XUNARA_AGENT_AUTH_KEY=<key> /opt/xunara/bin/xunara-agent enroll \
      -server http://<host>:9090 -state-dir ~/.xunara-agent
  /opt/xunara/bin/xunara-agent run -state-dir ~/.xunara-agent
  ```

  官方 Tailscale 客户端则不需要 agent：`tailscale up --login-server http://<host>:9090`
  会走 TS2021 注册流程，设备在控制台的「设备授权」页批准后加入网络。

## HTTPS 与通行密钥

通行密钥（WebAuthn）要求安全上下文，浏览器只认 `https://` 与 `localhost`。当前
部署是明文 `http://<host>:9090`，所以单元里是 `-passkey=false`；浏览器仍可以
用密码/身份提供方登录。

一旦前面有了 TLS（反向代理或直接监听 443，证书可用 ACME HTTP-01 或 DNS-01）：

```sh
sudo sed -i 's|-passkey=false|-passkey=true \|\n    -server-url https://<域名>|' /etc/systemd/system/xunarad.service
sudo systemctl daemon-reload && sudo systemctl restart xunarad
```

把 `-server-url` 改成 https 的域名后，RP ID 与 origin 会自动跟随；WebAuthn 的
RP ID 是域名，因此**不要**用 IP 部署通行密钥。

## 多租户与平台 API

- 多租户：用 `-org-config` 指定组织清单（与单组织的标志互斥，见
  `Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md`）。
- 平台 API（HTTP `/api/platform`、gRPC `xunara.v2.Platform*`）是 fail-closed：
  没配 `XUNARA_PLATFORM_ADMIN_TOKEN` 时一律拒绝。需要时把 token 写进
  `/etc/xunara/xunarad.env`，并且**只监听内网**（把 `-grpc-listen` 改成
  `127.0.0.1:9091` 或放进防火墙白名单）。

## 升级前检查

```sh
sudo systemctl stop xunarad
sudo tar czf /root/xunara-state-$(date +%F).tar.gz -C /var/lib xunara
sudo systemctl start xunarad
```

跨版本升级后确认：`systemctl status xunarad`、`journalctl -u xunarad -n 50`、
`curl -fsS http://127.0.0.1:9090/health`、首页能打开 `/`、`/console` 未登录时
跳转到 `/login`。
