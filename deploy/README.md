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

## 状态、备份与升级注意

- 状态全在 `/var/lib/xunara`：节点、用户、Session、预认证密钥、审计、策略快照，
  Flux 的密文也在其下。备份该目录即可（先 `systemctl stop xunarad` 保证一致）。
- Session 存在状态目录里，不是进程内存：重启不掉登录，也是多实例的前提。

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
`curl -fsS http://127.0.0.1:9090/health`、控制台能打开 `/console`。
