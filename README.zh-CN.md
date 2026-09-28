# proxlet

[English](README.md) | [简体中文](README.zh-CN.md)

`proxlet` 是一个轻量的命令行代理服务工具，可快速创建代理入口，并可选择
通过上游代理转发流量。

## 特性

- 支持 HTTP、HTTPS、SOCKS5、SOCKS5h 与 fakehttp 代理客户端。
- 提供混合模式，可在同一端口接收 HTTP 与 SOCKS5 客户端连接。
- 支持通过 HTTP、HTTPS、SOCKS5、SOCKS5h、fakehttp 与 SSH 进行代理链转发。
- 提供用户名/密码认证与来源 IP 白名单。
- 通过内置 daemon 参数在后台运行。
- 监听遇到瞬时错误时继续接受连接, 不会因此退出。
- 拨号和握手使用 `--connect-timeout` 限制时间, 默认 10 秒. 已建立的隧道不受这个截止时间影响.
- 以单个可执行文件发布，便于部署。

## 安装

### 下载发布版本

从 [Releases](https://github.com/cyhfvg/proxlet/releases/latest)
页面下载预构建压缩包。

### 从源码构建

安装稳定版 Rust 工具链后运行：

```bash
git clone https://github.com/cyhfvg/proxlet.git
cd proxlet
cargo build --release
```

构建后的可执行文件位于 `target/release/proxlet`。

## 快速开始

使用默认地址 `127.0.0.1:1080` 启动 HTTP 代理：

```bash
proxlet
```

在同一端口接受 HTTP 与 SOCKS5 客户端：

```bash
proxlet --type mixed --lhost 0.0.0.0 --lport 1080
```

## 使用方法

### 选择代理类型

```bash
proxlet --type http
proxlet --type socks5
proxlet --type socks5h
proxlet --type mixed
proxlet --type fakehttp
```

可选类型包括 `http`、`https`、`socks5`、`socks5h`、`mixed` 和 `fakehttp`，
默认值为 `http`。

HTTP 正向代理请求转发一次后关闭连接. `Host` 改成目标 authority, hop-by-hop
头不转发. `CONNECT` 隧道不变. 目标 host 含控制字符时会被拒绝, 不会拼进上游 `CONNECT` 请求.

### 为 HTTPS 模式创建证书文件

生成本地使用的证书文件，然后启动 HTTPS 代理：

```bash
./create_cert_key.sh
proxlet --type https --tls-cert certs/proxlet-cert.pem --tls-key certs/proxlet-key.pem
```

连接该 HTTPS 代理的客户端需要信任 `certs/proxlet-ca.pem`。为其他主机生成
文件时，请添加代理使用的主机名或 IP 地址：

```bash
./create_cert_key.sh --san DNS:proxy.example.com --san IP:192.0.2.10
```

### 通过上游代理转发

```bash
proxlet --proxy 'socks5h://username:password@127.0.0.1:1080'
proxlet --proxy 'fakehttp://strong-password@127.0.0.1:8080'
proxlet --proxy 'ssh://username:password@127.0.0.1:22'
proxlet --proxy 'ssh://username@127.0.0.1:22?key=/home/username/.ssh/id_ed25519'
```

`socks5h` 上游会把主机名交给上游代理解析。IP 字面量仍按 SOCKS5 的 IPv4 或
IPv6 地址发送，不会被当成域名。

SSH 上游可使用 `ssh://username:password@host:port` 进行密码认证，也可添加
`?key=/path/to/private_key` 进行公钥认证。如果 URL 同时包含密码和 `key`，
该密码会作为私钥口令使用。

SSH 上游会复用一条已认证 session，每个目标只打开一条 `direct-tcpip` 通道。
会话断开后会重新连接，私钥只加载一次。HTTPS 上游仍然是每个目标一条
`CONNECT`；TLS session 由共享的 rustls client config 复用。

fakehttp 代理链需要两个 `proxlet` 协作：上游实例以 fakehttp 模式监听，下游实例
通过 `fakehttp://secret@host:port` 连接它，同时在本机继续提供浏览器可用的普通
HTTP 或 SOCKS 代理入口：

```bash
# 在上游主机执行
proxlet --lhost 10.10.50.20 --lport 8080 --type fakehttp \
  --aes-secret 'strong-password123'

# 在下游主机执行
proxlet --lhost 127.0.0.1 --lport 9090 --type http \
  --proxy 'fakehttp://strong-password123@10.10.50.20:8080'
```

fakehttp 的设计目标是让两个 `proxlet` 端点之间的链路看起来像普通纯 HTTP
请求/响应流量。它本身不是浏览器可直接配置的 HTTP 代理协议；浏览器和应用
应连接下游 `proxlet` 暴露的本地 HTTP 或 SOCKS 代理入口，再由下游实例转换为
fakehttp tunnel。

fakehttp 在握手后使用 HTTP/1.1 chunked body 承载 tunnel payload。URL 路径固定，
真正的隧道目标放在第一个 body chunk 中。指定 `--aes-secret` 后，该 hello 帧会被
AES-256-GCM 加密并与握手字段（Host、帧大小、编码方式）绑定认证；客户端提供随机
nonce，服务端回应随机 salt，重放的握手会被拒绝。上下游两个 `proxlet` 实例需要
使用相同版本的 fakehttp 实现。

指定 `--aes-secret` 后，fakehttp tunnel 内的 payload 会按帧使用 AES-256-GCM
加密。密钥材料由 secret 加上每次连接的客户端 nonce 与服务端 salt 派生，因此
下游 URL 只需要提供相同的 secret 即可解密。
可使用 `--max-frame-size <KB>` 设置加密帧 payload 大小，可选值为 `8`、`16`、
`32`、`64`，默认值为 `16`。当两个 proxlet 设置不同值时，fakehttp 会为该连接
协商使用较小值。

若需要通过 HTTPS 代理连接两个 `proxlet` 实例，请先使用证书启动上游实例，
再将上游实例的 CA 证书提供给下游实例：

```bash
# 在上游主机执行
./create_cert_key.sh --san IP:192.0.2.10
proxlet --type https --lhost 0.0.0.0 --lport 1080 \
  --tls-cert certs/proxlet-cert.pem --tls-key certs/proxlet-key.pem \
  --user relay --auth 'strong-password'

# 安全取得 certs/proxlet-ca.pem 后，在下游主机执行
proxlet --proxy 'https://relay:strong-password@192.0.2.10:1080' \
  --proxy-ca certs/proxlet-ca.pem
```

### 限制访问

同时指定用户名和一个密码来源即可启用认证。只给用户名，或只给密码来源，会启动失败。`--auth` 仍可用，但密码会出现在进程参数里，启动时会警告这一点。优先使用 mode 0600 的文件或 `PROXLET_AUTH`：

```bash
install -m 600 /dev/null proxlet.auth
printf '%s\n' 'strong-password' > proxlet.auth
proxlet --type mixed --user alice --auth-file proxlet.auth
```

`--aes-secret`、`--aes-secret-file` 和 `PROXLET_AES_SECRET` 只对 `--type fakehttp` 有效。该模式拒绝 `--user` 和 `--auth`。fakehttp 监听或 `fakehttp://` 上游没有 secret 时仍会启动，并警告隧道 payload 是明文。上游 URL 若含密码，使用 `--proxy-file` 或 `PROXLET_PROXY`，避免进入进程参数。Unix 上该文件不能被同组或其他用户读取。非 Unix 构建不检查 ACL。

允许指定的客户端地址或网段：

```bash
proxlet --allow-ip '127.0.0.1'
proxlet --allow-ip '127.0.0.1,127.0.0.2'
proxlet --allow-ip '127.0.0.1/8'
```

### 在后台运行

使用 `--daemon` 可让 `proxlet` 在后台启动，不再占用当前终端。父进程会等到
子进程监听成功后才返回，并打印监听地址和 PID。启动失败时父进程以非 0 退出
并打印原因，不会留下监听进程。

`--log-file` 和 `--pid-file` 都要求同时使用 `--daemon`。没有 `--log-file`
时，子进程日志会被丢弃。pid 文件只在监听成功后写入。

每次监听尝试还会向 stdout 写一行访问日志，`--log-file` 会一并收下:

```text
access <UTC 时间> <客户端 IP> <协议> <目标> <结果>
```

`result` 为 `ok`、`auth-failed`、`rejected`、`bad-request`、`not-proxy` 或
`error`。这一行包含客户端 IP 和目标，不包含用户名、密码或
`Proxy-Authorization`。没有目标时写 `-`。

```bash
proxlet --daemon --type mixed --lport 1080 --log-file proxlet.log --pid-file proxlet.pid
```

在 Linux 上查询进程时不要打印参数：

```bash
ps -p <PID> -o pid,user,lstart
ss -ltnp 'sport = :1080'
```

不要使用 `ps -f` 或 `pgrep -af`。它们会打印进程参数，包括通过 `--auth`、`--aes-secret` 或 `--proxy` 传入的密码。

在 Linux 上关闭实例：

```bash
kill <PID>
```

若等待后进程仍未退出，可强制关闭：

```bash
kill -KILL <PID>
```

在 Windows 命令提示符中，查询运行中的实例或指定 PID：

```bat
tasklist /FI "IMAGENAME eq proxlet.exe"
tasklist /FI "PID eq <PID>"
```

在 Windows 命令提示符中关闭实例：

```bat
taskkill /PID <PID>
```

必要时可强制关闭：

```bat
taskkill /F /PID <PID>
```

对应的 PowerShell 命令如下：

```powershell
Get-Process proxlet
Get-Process -Id <PID>
Stop-Process -Id <PID>
Stop-Process -Id <PID> -Force
```

## 参数

| 参数 | 说明 |
| --- | --- |
| `-d, --daemon` | 在后台运行，不占用终端输入输出。父进程在子进程监听成功后才返回 |
| `--log-file <FILE>` | 把 daemon 的 stdout 追加到该文件。要求 `--daemon`。未指定时子进程日志被丢弃 |
| `--pid-file <FILE>` | 监听成功后写入后台进程 PID。要求 `--daemon` |
| `--allow-ip <allow-src-ip>...` | 允许访问的客户端 IP 地址或 CIDR 网段 |
| `-l, --lhost <lhost>` | 监听主机，默认值：`127.0.0.1` |
| `-p, --lport <lport>` | 监听端口，默认值：`1080` |
| `-u, --user <username>` | 认证用户名。必须同时提供 `--auth`、`--auth-file` 或 `PROXLET_AUTH`。`--type fakehttp` 拒绝该参数 |
| `-a, --auth <password>` | 认证密码。必须同时提供 `--user`。会出现在进程参数里，优先使用 `--auth-file` |
| `--auth-file <FILE>` | 密码文件，mode 0600。必须同时提供 `--user`。与 `--auth` 和 `PROXLET_AUTH` 互斥 |
| `-t, --type <type>` | 代理类型，默认值：`http` |
| `--proxy <SCHEMA_URL>` | 上游代理 URL。URL 含 secret 时优先使用 `--proxy-file` |
| `--proxy-file <FILE>` | 上游代理 URL 文件，mode 0600。与 `--proxy` 和 `PROXLET_PROXY` 互斥 |
| `--connect-timeout <SECS>` | DNS、TCP 拨号和握手超时, 单位秒, 必须大于 0, 默认值: `10`. 已建立的隧道不会因此空闲断开 |
| `--aes-secret <SECRET>` | 仅 `--type fakehttp` 使用的 AES secret。其他监听类型会启动失败。会出现在进程参数里，优先使用 `--aes-secret-file` |
| `--aes-secret-file <FILE>` | AES secret 文件，mode 0600。仅 `--type fakehttp` 有效。与 `--aes-secret` 和 `PROXLET_AES_SECRET` 互斥 |
| `--max-frame-size <KB>` | fakehttp 加密帧 payload 大小，单位 KiB，可选 `8`、`16`、`32`、`64`，默认值：`16` |
| `--proxy-ca <FILE>` | 用于验证 HTTPS 上游代理的 CA 证书包。要求 `--proxy`、`--proxy-file` 或 `PROXLET_PROXY` |
| `--tls-cert <FILE>` | HTTPS 模式使用的证书文件 |
| `--tls-key <FILE>` | HTTPS 模式使用的私钥文件 |

运行 `proxlet --help` 可查看完整的命令行帮助。

## 安全提示

仅可在您拥有或已获得明确授权的环境中使用 `proxlet`。使用者有责任遵守
适用的政策与法律法规。

暴露在外的代理服务可能被未授权人员滥用。仅在确有需要时监听公共网络接口；
对本机以外提供服务前，请配置认证和/或来源 IP 白名单，并在不再需要时及时
撤销访问。

## 参与贡献

欢迎提交 Issue 与 Pull Request。进行行为变更时，请尽可能包含对应测试。

## 许可证

本项目基于 [BSD 3-Clause License](LICENSE) 发布。
