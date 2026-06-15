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

SSH 上游可使用 `ssh://username:password@host:port` 进行密码认证，也可添加
`?key=/path/to/private_key` 进行公钥认证。如果 URL 同时包含密码和 `key`，
该密码会作为私钥口令使用。

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

指定 `--aes-secret` 后，fakehttp tunnel 内的 payload 会按帧使用 AES-256-GCM
加密。密钥材料、salt、nonce base 与每帧 nonce 都由 secret 和 HTTP 外壳里的
session token 按固定算法派生，因此下游 URL 只需要提供相同的 secret 即可解密。
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

同时指定用户名与密码即可启用认证：

```bash
proxlet --type mixed --user alice --auth 'strong-password'
```

允许指定的客户端地址或网段：

```bash
proxlet --allow-ip '127.0.0.1'
proxlet --allow-ip '127.0.0.1,127.0.0.2'
proxlet --allow-ip '127.0.0.1/8'
```

### 在后台运行

使用 `--daemon` 可让 `proxlet` 在后台启动，不再占用当前终端。命令会打印
后台进程的 PID。daemon 模式不会创建 PID 文件，也不会向启动它的终端写入
日志。

```bash
proxlet --daemon --type mixed --lport 1080
```

在 Linux 上，使用启动时显示的 PID 查询进程：

```bash
ps -p <PID> -f
```

若已没有保存 PID，可按命令行查找运行中的实例：

```bash
pgrep -af proxlet
```

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
| `-d, --daemon` | 在后台运行，不占用终端输入输出 |
| `--allow-ip <allow-src-ip>...` | 允许访问的客户端 IP 地址或 CIDR 网段 |
| `-l, --lhost <lhost>` | 监听主机，默认值：`127.0.0.1` |
| `-p, --lport <lport>` | 监听端口，默认值：`1080` |
| `-u, --user <username>` | 认证用户名 |
| `-a, --auth <password>` | 认证密码 |
| `-t, --type <type>` | 代理类型，默认值：`http` |
| `--proxy <SCHEMA_URL>` | 上游代理 URL |
| `--aes-secret <SECRET>` | fakehttp 监听模式使用的 AES 加密 secret |
| `--max-frame-size <KB>` | fakehttp 加密帧 payload 大小，单位 KiB，可选 `8`、`16`、`32`、`64`，默认值：`16` |
| `--proxy-ca <FILE>` | 用于验证 HTTPS 上游代理的 CA 证书包 |
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
