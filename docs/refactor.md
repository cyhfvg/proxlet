# proxlet 重构与修复清单

审查日期: 2026-09-28
对照: `docs/TODO.md` 最后更新 2026-08-16, 版本 v0.1.6
范围: `src/`, `tests/`, `benches/proxy.rs`, `create_cert_key.sh`, `scripts/local_build.sh`, `README.md`
方法: 读源码和文档. 未改代码, 未跑全量测试. 行号以审查时文件为准.

状态标记 (重构进行中, 见 git log):

- [x] P0-1, P1-8, P1-11, P1-12, P2-16, P2-17: fakehttp v2 认证握手已落地.
- [x] P1-15: relay 入口先 flush 两端, chunked 与 crypto 短写不再对外报全部已接受.
- [x] P1-1: HTTP 正向代理一次转发后关闭, Host 改为目标, 剥离 hop-by-hop, 不把后续请求拷到第一个 origin.
- [x] P1-2: accept 瞬时错误记日志并退避, 只有监听套接字关闭才退出.
- [x] P1-5: 拨号和握手按 `--connect-timeout` 超时, 默认 10 秒; 握手期读头改为块读并交还多读字节.
- [x] P1-3: daemon 父进程等到监听成功才返回, 并支持 `--log-file` 与 `--pid-file`.
- [x] P1-10: 访问日志写到 stdout, 含时间, 来源 IP, 协议, 目标和结果; 认证失败不记密码.
- [x] P1-4: 只给 `--user` 或只给 `--auth` 时启动失败, 并写明缺的是哪一个; 启动日志打印认证是否启用.
- [x] P1-6: `--auth`、`--aes-secret` 和带 userinfo 的 `--proxy` 可改用 mode 0600 文件或 `PROXLET_AUTH` / `PROXLET_AES_SECRET` / `PROXLET_PROXY`; 明文 flag 启动时警告, 不打印 secret.
- [x] P1-7: 非 fakehttp 监听上的 AES secret, 以及 fakehttp 上的 `--user`/`--auth`, 启动失败; 明文 fakehttp 启动时警告; 策略不匹配写明缺的是监听端还是客户端.
- [x] P1-14: HTTP CONNECT 拼接前拒绝 host 里的 CR, LF, NUL 和其他控制字符; 错误不回显 host.
- [x] P1-9: SSH 上游复用已认证 session, 每个目标只开 direct-tcpip; 断线后重连. 私钥 `spawn_blocking` 加载一次并缓存. HTTPS 上游仍是每目标一条 CONNECT, TLS session 由共享 rustls `ClientConfig` 复用.
- [x] P1-13: `socks5h` 对能解析成 `IpAddr` 的 host 发 ATYP 1 或 4; 只有域名才发 ATYP 3.
- [x] P2-6: 接受的客户端套接字和拨号成功的 TCP 都设置 `TCP_NODELAY`. 缓冲区大小没有改.
- [x] P2-23: 增加每方向 256KiB 的生产 `relay` bench. 同一次短测量里默认 8KiB 是 770-812 us (约 629 MiB/s), 64KiB 是 429-973 us, 区间重叠, 所以没有改成 `copy_bidirectional_with_sizes`.
- [x] P2-10: 配置了口令的上游 SOCKS 只提供方法 `0x02`. 选中的方法不是提供的那个就失败, 错误带方法号.
- [x] P2-1: 非 `CONNECT` 的 `https://` absolute-form 在拨号前返回 400. 不向 443 写明文 HTTP.
- [x] P2-12: 上游 HTTP CONNECT 按状态码字段判断 200. 带 `Content-Length` 或 `Transfer-Encoding` 的 200 被拒绝, 不把 body 当隧道数据.
- [x] P2-11: SOCKS 用户名和密码按字节比较. 非 UTF-8 口令或域名先写失败应答. 连接被拒绝映射 `0x05`.
- [x] P2-15: `scripts/local_build.sh --help` 写 proxlet. Windows 注释 target 与 release workflow 的 `x86_64-pc-windows-msvc` 对齐.
- [x] P2-5: `--help` 与 README 写明 `socks5` 和 `socks5h` 监听端相同. 远程 DNS 只看上游 URL.
- [x] P2-3: host 含 `:` 且没有方括号时拒绝, 不再把整串当 host 并套默认端口.

结论: 有. 最严重的是 fakehttp 握手不在 AEAD 里, 改 URL 就能把已解密流量重定向. 默认 HTTP 模式在连接复用下会传错主机. 缓冲型写端进 relay 前不 flush, HTTPS 监听可能把 200 留在用户态. 效率上先改逐字节读头和 SSH 每连接握手.

下面只列有代码位置的问题. 不写补丁.

## 已记录, 不重复开项

这些已经在 `docs/TODO.md` 或 Known Scope 里. 这里只补代码位置, 不当成新发现.

| 已记录项 | 现状 |
| --- | --- |
| graceful shutdown | `src/main.rs` 没有信号处理器. `Cargo.toml` 开了 tokio `signal`, 源码未使用. `src/server.rs:74` 的 task 是 detach 的, 退出时无法等待. |
| connection-count | `src/server.rs:74` `tokio::spawn` 无 semaphore. 白名单拒绝发生在 spawn 之前 (`src/server.rs:62-69`), 通过的连接没有上限. |
| idle-timeout | `relay` 和隧道建立后的正文拷贝仍没有截止时间. 拨号, 握手和握手期读头已有 `--connect-timeout`, 见 P1-5. |
| allowlist 集成测试 | 仍缺. 单测只覆盖 CLI 解析 (`tests/cli.rs`). |
| 多平台 release 动态库检查 | 仍缺. `.github/workflows/release.yml` 构建 musl, MSVC, ARM64 三个 target, 只有 `cargo build --release`, 没有测试或运行校验步骤. |
| SOCKS `UDP ASSOCIATE` / `BIND` | 未实现. 不是回归. |
| SSH agent | 未实现. 不是回归. |
| SSH host key 直接信任 | `src/connector/ssh.rs:37` 始终 `Ok(true)`. 设计如此, 不单列待修 bug. |
| fakehttp 单连接双向隧道 | 中间盒把请求体缓冲到结束再转发响应时会死锁. 架构限制, 不单列待修 bug. |
| nmap 仍可能通过 CONNECT / absolute-URI 识别代理 | 已知取舍. 407 路径见 P2-7. |

## 核对后不作为缺陷

- 单条连接、同一 `CipherDirection` 内 nonce 不重用. `src/fakehttp/crypto/cipher.rs:106-118` 按方向派生 base nonce, counter XOR 进 `nonce[4..]`, 溢出返回错误, 不回绕. 两个方向的 base nonce 不同. 跨连接重放同一 session 是另一件事, 见 P1-11.
- `MAX_PENDING_OUTPUT_FRAMES` 已在 `src/fakehttp/crypto.rs:489-490` 的 `poll_write` 里限流, 不是空常量.
- release profile 已经是 `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`. 没有 bench 证据前不要再加一套编译优化. `panic = "abort"` 的运维代价见 P2-9.
- `create_cert_key.sh` 的私钥权限是对的: `umask 077`, 再 `chmod 600` 私钥. 缺口是失败信息被丢掉, 见 P2-8.
- 默认监听 `127.0.0.1:1080`. 开放代理只在用户改绑定地址且不加认证时出现.
- rustls `ServerName` 接受 IP. HTTPS 上游打到 IP 不是代码拒绝. 证书必须带对应 IP SAN, 这是部署约束, 不是连接器 bug.
- `load_tls` 只在 `run` 启动时执行一次 (`src/server.rs:45`), 不是每连接重读证书.
- mixed 首字节分发只有一个读者 (`src/server.rs:147-170`). `0x05` 经参数交给 SOCKS, `0x16` 由 `PrefixStream` 回放给 TLS, 其余作为 HTTP 的 `initial` 字节. 没有双读或竞态窗口.

## P0

### P0-1. fakehttp 握手不在 AEAD 里, 改路径就能重定向已解密流量

- 类别: 安全
- 位置: `src/fakehttp.rs:99-128`, `src/fakehttp.rs:227-242`, `src/fakehttp/crypto/cipher.rs:64-68`
- 证据: 目标是 `POST /api/v1/stream/{session}/{base64url(authority)}`. 服务端切开 path 后立刻 `connector.connect`, 然后才包加密流. GCM 的 AAD 是空字节串 `b""`. key 和 nonce 只由 secret, session, direction 派生, 不覆盖 path, Host, `X-Proxlet-Max-Frame-Size`. chunk 边界也在密文外面.
- 影响: 不掌握 secret 的路径改写者只要留下 session, 换掉 target token, 服务端仍能解密客户端字节, 并把它们送到攻击者指定的 host:port. 明文协议会直接泄露. TLS 目标通常会在应用层证书校验失败. 同一攻击者可以在 chunk 边界注入 `0\r\n\r\n`; chunked 层在长度为 0 时直接结束, 这一层没有 AEAD, 截断会被看成干净结束.
- 建议: 用 secret 对 request-target, Host, 帧大小做 HMAC, 或把这些字段放进每帧 AAD. 校验通过前不要 `connect`. 结束信号放进 AEAD, 不要只依赖 chunked 的 0 块. 被动泄露见 P1-8, 不要当成两条独立修复.

## P1

### P1-1. HTTP 正向代理只处理一个请求, 然后原样转发

- 类别: bug
- 位置: `src/http.rs:84-91`, `src/http.rs:275-295`
- 证据: 非 `CONNECT` 把改写后的头写入 origin, 随后 `relay(client, remote)`. 后续字节原样拷到同一个 origin. `origin_form_header` 只去掉 `Proxy-Authorization` 和 `Proxy-Connection`, 不处理 `Connection` / `Keep-Alive` / `TE` / `Trailer` / `Upgrade`, 也不强制 `Connection: close`, 也不把 `Host` 改成目标 authority.
- 影响: HTTP/1.1 客户端复用连接时, 第二个请求可能是另一个主机的 absolute-form, 会打到第一个 origin, 后续请求里的 Cookie 和 Authorization 也会送到那里. 浏览器, `curl --proxy` 和 Go `http.Client` 的连接复用都会踩到. `CONNECT` 路径本身是对的.
- 建议: 同一连接上循环解析请求, 直到对端关闭; 或者对客户端和 origin 都发送 `Connection: close`, 并且不要转发 keep-alive. 转发时按 `Connection` 头剥离 hop-by-hop, 并保证 `Host` 与目标一致. 这是同一处修复.
- 测试: 现有测试没有「同一客户端连接上的第二个请求」.

### P1-2. `accept` 失败会让整个进程退出

- 类别: bug
- 位置: `src/server.rs:58-59`
- 证据: `listener.accept().await?`. 瞬时错误直接结束 `run`.
- 影响: `EMFILE`, `ENFILE`, 以及部分平台的 `ECONNABORTED` / `ENOBUFS`, 会把长期运行的代理打掉. 和连接上限是相关但不同的缺口: 上限见已记录项, 这里是错误处理.
- 建议: 监听套接字关闭才退出. 资源类瞬时错误记日志并短暂退避后继续 `accept`.

### P1-3. daemon 在子进程监听前就报成功, 失败完全不可见

- 类别: bug, 易用性
- 位置: `src/main.rs:23-27`, `src/daemon.rs:30-42`, `src/daemon.rs:58-62`
- 证据: 父进程 `Cli::parse()` 之后就 `spawn()`, 打印 PID, 返回 `Ok(())`. 子进程 stdin/stdout/stderr 都是 `Stdio::null()`. `--type https` 缺证书, 端口占用, 上游 scheme 非法, TLS/CA 打不开, 都发生在子进程的 `into_config` / `Connector::new` / `load_tls` / `bind`, 错误进 `/dev/null`. 子进程成功启动后, 监听地址行和 mixed HTTPS 禁用警告 (`src/server.rs:49-56`) 也走 stdout, 同样进 `/dev/null`, 用户只看得到父进程的 PID 行. 没有 pid 文件, 没有单实例锁, 没有就绪通知.
- 影响: 用户看到 PID 就认为服务已起来. 重复启动会再打印一个 PID, 第二个实例绑定失败后消失. systemd `Type=simple` 会把父进程退出当成服务结束, 默认 `KillMode=control-group` 还会把子进程一起杀掉; 没有 pid 文件, `Type=forking` 也对不上. README 只写了不写 pid 文件, 没写成功消息可能是假的 (`README.md:163-165`).
- 建议: 父进程先做配置, 上游 URL, TLS/CA 文件存在性检查, 再脱离. 子进程绑定成功后用管道通知父进程. 失败时父进程非 0 退出并打印原因. 提供 `--log-file`. 不要靠字符串比较剔除 daemon 标志, 用已解析的 `Cli` 重建子进程参数并强制 `daemon=false`.
- 相关: `background_args` 只过滤与 `--daemon` 或 `-d` 完全相等的参数 (`src/daemon.rs:58-62`). 测试也只覆盖这两个完整 token (`src/daemon.rs:140-147`). clap 默认允许短选项合并, `proxlet -dl 0.0.0.0` 的 argv token 是 `-dl`, 不会被剔除, 子进程会再次 daemonize. 这条是从过滤逻辑推出的, 本次没有拉起进程复现.

### P1-4. 只给 `--user` 或只给 `--auth` 时认证被静默关闭

- 类别: bug, 安全
- 位置: `src/cli.rs:43-49`, `src/cli.rs:275-278`, `src/server.rs:49-56`
- 证据: 只有 `(Some, Some)` 才生成 `Auth`, 其余分支是 `None`, 不 `bail`, 不打印. `--help` 写了两个都要有, 启动日志只打印地址和类型, 不打印认证是否生效.
- 影响: `proxlet --lhost 0.0.0.0 --user alice` 看起来开了认证, 实际是开放代理.
- 建议: 只给一半时直接失败, 写明缺的是哪一个. 启动时打印 `authentication enabled` 或 `authentication disabled`.

### P1-5. 没有连接超时, 头读取可以无限占住 task

- 类别: bug, 效率
- 位置: `src/connector.rs:254-257`, `src/connector.rs:231-236`, `src/http.rs:110-120`, `src/fakehttp.rs:293-303`, `src/connector/protocol.rs:32-50`, `src/connector/protocol.rs:207-218`, `src/connector/ssh.rs:61-64`
- 证据: `TcpStream::connect` 没有 timeout. TLS 握手, HTTP CONNECT 读响应, SOCKS 读响应, SSH `client::connect` 同样没有. 三处 HTTP 头都是 1 字节 `read_exact` 循环, 上限 64KiB (`src/http.rs:19`, `src/fakehttp.rs:28`) 或 16KiB (`src/connector/protocol.rs:44`). `Cargo.toml` 开了 tokio `time`, 源码未使用. 已记录的 idle-timeout 覆盖隧道建立之后; 拨号和握手没有超时是额外缺口.
- 影响: 黑洞路由, 半开握手, 或慢客户端可以占住一个 task 和一对套接字. `TcpStream::connect` 按解析顺序尝试, 第一个地址 SYN 无应答会等到操作系统放弃后才试下一个. 逐字节读还会把一次握手变成上千次唤醒.
- 建议: TCP connect, TLS, HTTP/SOCKS 握手, SSH 认证都加可配置超时, 给一个 10 秒量级的默认值. 多地址要按地址超时或 Happy Eyeballs, 不要只套一个总超时. 头读取改成带缓冲的块读取, 扫到 `\r\n\r\n` 为止, 多读的隧道字节交还给后续 relay. 连接上限仍按 TODO 做.

### P1-6. 密码留在 argv, daemon 子进程原样继承

- 类别: 安全, 易用性
- 位置: `src/cli.rs:43-45`, `src/cli.rs:56-65`, `README.md:171-180`
- 证据: `--auth`, `--aes-secret`, `--proxy user:pass@` 都在进程参数里. clap 没有 env 特性, 也没有文件入口. README 排查步骤是 `ps -p <PID> -f` 和 `pgrep -af proxlet`, 会把完整命令行打出来. Linux 上 `/proc/<pid>/cmdline` 对本机用户可读.
- 影响: 共享主机上的本地用户能看到代理密码, fakehttp secret, SSH 口令. shell history 也会留下明文.
- 建议: 增加仅当前用户可读的 `--auth-file` / `--aes-secret-file`, 或等价的环境变量. 文档改成按可执行文件或监听端口查进程, 不要把 `ps -f` / `pgrep -af` 当成正常运维步骤.

### P1-7. `--aes-secret` 和 `--user`/`--auth` 在错误模式下被静默忽略

- 类别: 安全, 易用性
- 位置: `src/cli.rs:63-65`, `src/server.rs:105-126`, `src/fakehttp.rs:100-107`
- 证据: `--aes-secret` 只在 `ProxyType::FakeHttp` 分支使用. HTTP/SOCKS/HTTPS/mixed 监听忽略它, 没有警告. fakehttp 监听不接收 `config.auth`. 双方都没有 secret 时是明文隧道; 只有策略不匹配才 404, 错误文案是 `fakehttp encryption policy mismatch`, 不说明该加哪一侧的 secret.
- 影响: `proxlet --type http --aes-secret ...` 不会加密. `proxlet --type fakehttp --lhost 0.0.0.0 --user alice --auth secret` 仍是无认证监听. 忘了配 secret 的两端会静默明文.
- 建议: secret 出现在非 fakehttp 监听上就失败. fakehttp 下如果给了 `--user`/`--auth`, 启动失败并说明该模式只认 `--aes-secret`. 双方都不带 secret 时, 除非显式允许明文, 否则启动警告或拒绝. 不匹配错误要写明缺的是监听端还是客户端.

### P1-8. fakehttp 把目标明文放进 URL path

- 类别: 安全
- 位置: `src/fakehttp.rs:227-242`
- 证据: `POST /api/v1/stream/{session}/{base64(authority)}`, 另有 `User-Agent: Mozilla/5.0`, `Content-Encoding: aes-256-gcm`, `X-Proxlet-Max-Frame-Size`. 响应写 `Server: nginx`, 正文却是 `application/octet-stream` 加 chunked. `session_token` (`src/fakehttp.rs:260-276`) 含时间, 计数器, pid, target, 但目标本身已经在 path 里.
- 影响: 被动观察就能解码目的地, 也能认出 proxlet. 主动改写路径把解密流量重定向, 见 P0-1. 缓冲完整请求体的中间盒会死锁, 那是已知架构限制, 不另开.
- 建议: 和 P0-1 一起改. URL 用固定路径, 目标放进已认证的首帧, 去掉产品名头. 不要把这条隧道当成能穿过会缓冲 body 的中间盒.

### P1-9. 每个目标都新建上游连接; SSH 还在 async 路径上同步读私钥

- 类别: 效率
- 位置: `src/connector.rs:169-212`, `src/connector/ssh.rs:56-78`
- 证据: `Connector::connect` 每次 `connect_tcp`, HTTPS 上游再做完整 TLS, SSH 上游再 `ssh_connect`. `load_secret_key` 在 async 函数里, 无 session 复用, 无 key 缓存, 也不是 `spawn_blocking`. `nodelay: true` 只写在 SSH config (`src/connector/ssh.rs:58`). `channel.into_stream()` 之后会话没有显式 `disconnect`.
- 影响: 链式代理的成本由握手决定, 不是由转发决定. SSH 上游每个目标都是一次完整握手. 私钥读取和解密堵住 worker, 加密私钥的 KDF 也在这条路径上. 缺的是会话复用, 不是 channel 被提前释放.
- 建议: 按上游 endpoint 缓存一个已认证的 SSH handle, 每个目标只开 `direct-tcpip`, 断线再重连. 私钥只在建会话时用 `spawn_blocking` 加载一次. HTTPS 上游如果仍是 HTTP/1.1 CONNECT, 每个目标仍要一条隧道, 但到上游代理的 TLS session 可以复用. 做之前先补链式上游和 SSH 的 bench; `benches/proxy.rs` 现在只覆盖直连 round-trip.

### P1-10. 没有访问日志, HTTP 认证失败连 stderr 都不进

- 类别: 易用性, 安全
- 位置: `src/server.rs:62-77`, `src/http.rs:44-56`, `src/http.rs:64-72`, `src/socks.rs:91-93`
- 证据: 没有日志框架, 没有 level, 没有文件. 运行时记录只有白名单拒绝, 以及 `serve_client` 返回 `Err` 时的 `eprintln!`. HTTP 头解析失败写 404 后 `return Ok(())`. HTTP Basic 失败写 407 后也是 `Ok(())`, 所以不会进那条日志. SOCKS 密码错误会 `bail!` 并被记下. 成功转发不记录客户端, 目标, 结果. daemon 把 stderr 丢掉之后, 前台仅有的记录也没了.
- 影响: 前台看不到 HTTP 暴力破解或客户端密码配错. daemon 模式下连白名单拒绝也消失.
- 建议: 认证失败统一记来源 IP, 不记密码. 加一行访问日志: 时间, 客户端 IP, 协议, 目标, 结果. 解析失败至少在服务端记一条, 客户端响应仍可以保持伪装.

### P1-11. 客户端自选 session 决定全部 nonce, 重放会重用 GCM nonce

- 类别: 安全
- 位置: `src/fakehttp/crypto/cipher.rs:38-45`, `src/fakehttp/crypto/cipher.rs:164-175`, `src/fakehttp.rs:109-128`, `src/fakehttp.rs:260-276`
- 证据: `derive_key` 不含 direction, 两个方向共用一把 AES-256 钥. base nonce 含 direction, 所以单条连接的两个方向不会撞. counter 从 0 起, 同一 `CipherDirection` 内 XOR 是双射, 不会自己回绕. session 来自请求路径, 服务端不检查是否见过, 响应里也没有服务端随机数. `session_token` 用 `SystemTime` (失败则当 0), 进程内计数器, pid.
- 影响: 重放捕获到的请求时, 服务端会用同一 session 从 server-to-client 计数器 0 再加密一段新的目标响应. 两段不同明文共用 `(key, nonce)` 后, 可以 XOR 出该 session 的密钥流并伪造帧. 长期 secret 不会因此被原像恢复. 和 P0-1 叠在一起时, 攻击者可以改目标, 迫使新响应和捕获到的旧响应不同. 诚实连接撞车更窄: 重启后计数器归零, 容器 pid 常为 1, 时钟回到同一纳秒且目标相同时才会撞. 那是残余风险, 不是主问题.
- 建议: 响应里带服务端随机 salt, 混入 HKDF. 服务端拒绝重复 session. 两个方向用不同密钥, 或在 nonce 高位固定方向位. 不要用可回拨的 `SystemTime` 当唯一性来源.

### P1-12. 配了 secret 仍先连目标, 第一帧之前无法证明对方有密钥

- 类别: 安全
- 位置: `src/fakehttp.rs:99-128`
- 证据: `wants_crypto()` 只看有没有 `Content-Encoding: aes-256-gcm`, 不证明对方知道 secret. 策略匹配后立刻 `connector.connect`, 写 200, 然后才 `encrypt_stream`. 双方都没有 secret 时走明文, 见 P1-7.
- 影响: 任何能连上监听端口的人, 即使不知道 secret, 也可以让服务端向 URL 里的 host:port 发起 TCP 连接. 这是探测和连接放大. 错误 secret 要等第一帧解密失败才断开, 目标连接已经建立.
- 建议: 先校验握手 MAC, 或读并验证第一个带 tag 的帧, 再拨号. 和 P0-1 是同一处修复.

### P1-13. `socks5h` 把 IP 字面量当域名发出去

- 类别: bug
- 位置: `src/connector/protocol.rs:104-109`
- 证据: `remote_dns == true` 时无条件发 ATYP `0x03` 加 host 字节. `127.0.0.1` 和 `::1` 也走这条路, 不分 ATYP `0x01` / `0x04`.
- 影响: 上游把 `::1` 当域名去解析, 连字面量 IP 失败. 集成测试只用 `socks5h` 加 `localhost`, 抓不到这个.
- 建议: host 能 `parse::<IpAddr>` 就发 ATYP 1 或 4. 只有真正的域名才用 ATYP 3.

### P1-14. HTTP CONNECT 把未清洗的 authority 拼进请求

- 类别: 安全
- 位置: `src/connector/protocol.rs:32-40`, `src/connector.rs:80-83`, `src/socks.rs:127`, `src/socks.rs:177-181`
- 证据: 请求是 `format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target.authority(), ...)`. `authority()` 只处理冒号, 不拒绝 CR, LF, NUL. HTTP 监听器的请求行按空白和 CRLF 切开, 原始 HTTP 请求行进不了 CR/LF. SOCKS ATYP `0x03` 经 `String::from_utf8` 后原样进 `Target`, `\r\n` 是合法 UTF-8. fakehttp path 解码后同样没有控制字符检查.
- 影响: SOCKS 或 fakehttp 客户端经 HTTP 上游转发时, 可以在 Host 行里注入额外头, 包括另一个 `Proxy-Authorization`. 正式的 `Proxy-Authorization` 是后加的, 上游若取第一个同名头, 注入的那个生效.
- 建议: 拼请求前拒绝 host 里的 CR, LF, NUL 和其他 CTL. base64 只覆盖凭证, 不覆盖 authority.

### P1-15. 进 relay 前不 flush, 缓冲型写端会把已接受的字节留在用户态

- 类别: bug
- 位置: `src/http.rs:84-91`, `src/connector.rs:274-278`, `src/fakehttp/chunked.rs:274-276`, `src/fakehttp/crypto.rs:502-504`
- 证据: CONNECT 的 200 和 origin-form 都是 `write_all` 后直接 `relay`, 没有 `flush`. chunked 和 crypto 的 `poll_write` 在内层返回 `Pending` 时仍 `Poll::Ready(Ok(accepted))`, 剩余留在用户态队列. tokio 1.52.3 的 `copy_bidirectional` 只在自己写过数据后才 `poll_flush`, 不会冲掉进入 relay 之前已经接受的字节. tokio-rustls 0.26 的 `TlsStream::poll_write` 写明不保证最后一段已经发出, 必须手动 `flush`.
- 影响: 直连 `TcpStream` 的小写入通常已经进内核, 这条不是每次必现. HTTPS 监听的 CONNECT 200, 以及走 fakehttp 或 HTTPS 上游的无 body 请求, 在短写或发送缓冲满时会停在用户态. 客户端等响应, relay 等双向数据, 连接挂死. 本次没有搭进程复现.
- 建议: `relay` 入口先对两端 `flush`. chunked 和 crypto 在 `Pending` 或短写时不得对外报全部字节已接受.

## P2

### P2-1. `https://` absolute-form 被当成明文 HTTP 转发

- 类别: bug
- 位置: `src/http.rs:196-201`, `src/http.rs:250-259`, `src/http.rs:84-90`
- 证据: `is_proxy_request` 接受 `https://`. `target()` 用 443. 非 `CONNECT` 把 origin-form 写到裸 TCP.
- 影响: 浏览器通常走 `CONNECT`, 所以不是默认路径. 但代码明确接受 `GET https://example.com/ HTTP/1.1`, 然后向 443 端口写明文 HTTP.
- 建议: 非 `CONNECT` 的 `https://` 直接拒绝. 不要在这条路径上做 origin TLS.

### P2-2. 监听地址和 socks5 本地解析只取第一个结果

- 类别: bug, 易用性
- 位置: `src/cli.rs:271-274`, `src/connector/protocol.rs:111-114`
- 证据: `lookup_host(...).next()`. `localhost` 有 A 和 AAAA 时只绑一个族. 上游 `socks5` (不是 `socks5h`) 本地解析后也只取第一个地址, 失败不回退. 直连 `TcpStream::connect` 会试完全部地址. `socks5h` 把主机名交给上游, 但 IP 字面量会被当成域名, 见 P1-13.
- 影响: `--lhost localhost` 可能只监听 `127.0.0.1` 或 `::1` 其中一个. 双栈主机上 getaddrinfo 常常先返回不可达的 IPv6; 直连最终能落到 IPv4, `socks5://` 上游只把这个 IPv6 交给代理, 代理连不上就失败. 这是常见的「直连好, 走 socks5 上游就坏」.
- 建议: 启动时打印实际绑定的地址, 解析出多个地址时警告未使用的结果. socks5 本地解析收集全部地址并按序尝试, 失败错误带上 host 和已试地址.

### P2-3. 未加括号的 IPv6 authority 不会按端口拆开

- 类别: bug
- 位置: `src/http.rs:313-330`
- 证据: 括号形式能解析. `rsplit_once` 要求 host 不含 `:`, 否则整串当 host, 端口用默认值. `CONNECT 2001:db8::1:443` 会变成 host `2001:db8::1:443`, 端口 443.
- 影响: 规范要求 IPv6 加括号, 所以这是兼容边界, 不是默认路径.
- 建议: host 含 `:` 且没有括号时直接拒绝, 不要静默套默认端口.

### P2-4. Basic 方案名大小写敏感, 口令比较非常量时间

- 类别: bug, 安全
- 位置: `src/http.rs:221-227`, `src/socks.rs:91`
- 证据: `strip_prefix("Basic ")`. RFC 7617 的 scheme 不区分大小写. 比较是 `==`. SOCKS 用户名和密码是 `!=`.
- 影响: `basic` / `BASIC` 会被拒绝. 网络暴露的代理上, 比较耗时理论上能区分口令前缀. 本地代理上这是次要问题.
- 建议: scheme 用 ASCII 大小写不敏感解析. 口令比较用常量时间比较.

### P2-5. `--type socks5` 与 `socks5h` 监听行为相同, 帮助文案相反

- 类别: 易用性
- 位置: `src/cli.rs:96-99`, `src/server.rs:114-115`
- 证据: 帮助写 Socks5 是 local DNS, Socks5h 是 remote DNS when used as an upstream. 监听端两个变体都调用 `socks::serve`. 远端 DNS 只由上游 URL 的 scheme 决定 (`src/connector.rs:183-193` 把 `remote_dns` 传给 `socks_connect`).
- 影响: 用户选 `--type socks5h` 以为 DNS 留在远端. 实际取决于客户端发的地址类型, 以及 `--proxy` 的 scheme.
- 建议: `--help` 和 README 改成同一句: 监听端两者相同; 远程 DNS 只看上游 URL.

### P2-6. 接受的 TCP 和 `connect_tcp` 没有 `TCP_NODELAY`

- 类别: 效率
- 位置: `src/connector.rs:254-257`; SSH 侧对照 `src/connector/ssh.rs:58`
- 证据: 源码里没有对接受套接字或普通 `TcpStream` 调用 `set_nodelay`. 只有 SSH config 开了 nodelay.
- 影响: 交互流量和小包会吃 Nagle 延迟. 高吞吐大块转发不一定受益, 所以这是 P2.
- 建议: 接受后和拨号成功后设置 `TCP_NODELAY`. 用现有 bench 看小包延迟, 不要凭感觉再改缓冲区.

### P2-7. 伪装把真实错误藏掉, 开启认证后又发出会被识别的 407

- 类别: 易用性, 安全
- 位置: `src/http.rs:44-56`, `src/http.rs:64-72`, `src/http.rs:78-80`, `src/camouflage.rs:3-5`
- 证据: 解析失败返回 404 且 `Ok(())`. `request.target()?` (`src/http.rs:75`) 失败时不写状态行, 连接直接进入错误返回. 连接失败对外是 503, 不是 502. `camouflage.rs` 写明 nmap 会把 407 和 502 分类成 `http-proxy`, 但认证失败仍然发送 407.
- 影响: 坏端口或非法 authority 的代理请求, 客户端只看到连接被拆, 不是 400. 依赖 502 的客户端会把上游故障当成 Web 服务器暂时不可用. 打开认证后, 发代理请求的扫描器又看到 407. 服务端同时没有日志, 排障只能猜.
- 相关: `tests/listener_upstream_integration.rs:63-77` 的测试名叫 `returns_bad_gateway`, 实际断言 `HTTP/1.1 503 Service Temporarily Unavailable`. 测试名把 502 语义和伪装 503 钉在一起, 修这条时会先撞上这个测试.
- 建议: 扫描器伪装只覆盖非代理请求. 已经认定是代理请求的失败要写标准状态, 并把原因记到 P1-10 的日志里, 不要把真实状态码写回扫描器路径. 如果伪装是目标, 认证失败也不要发标准 407, 或者把这个指纹写进 README 的已知限制.

### P2-8. 证书脚本吞掉 openssl 错误, README 没强调不要分发 CA 私钥

- 类别: 易用性, 安全
- 位置: `create_cert_key.sh:176-206`, `README.md:69-76`
- 证据: `genpkey` / `req` / `x509` 都把 stdout 和 stderr 重定向到 `/dev/null`. `set -e` 下失败直接退出, 用户看不到原因. README 只说信任 `certs/proxlet-ca.pem`, 没写不要把 `proxlet-ca-key.pem` 或整个 `certs/` 发给客户端. `scripts/pre_commit_check.sh:72` 的 `bash -n` 只检查 `local_build.sh` 和它自己, `create_cert_key.sh` 不在语法检查里.
- 影响: SAN 写错, openssl 不支持 `-addext`, 磁盘满时, 脚本像是无声失败. 按目录拷贝会泄露 CA 私钥, 对方可以签任意代理证书.
- 建议: 失败时把 openssl stderr 打出来. README 和脚本结尾写明只分发 `proxlet-ca.pem`.

### P2-9. 运维基本面不足, 错误文案经常不能指导修正

- 类别: 易用性
- 位置: `src/server.rs:49-56`, `src/cli.rs:271-272`, `README.md:48`, `Cargo.toml` release `panic = "abort"`
- 证据:
  - 没有配置文件. 长命令行和 shell history 是同一套 secret 问题的另一面.
  - 没有 pid 文件, 没有重复启动锁, 没有健康检查. 优雅退出已在 TODO, 不另开.
  - `README.md:48` 的快速开始是 `proxlet --type mixed --lhost 0.0.0.0 --lport 1080`, 没有认证也没有 allow-list. 中文 README 的同一示例在 `README.zh-CN.md:47`. 进程绑到非回环且无防护时不警告.
  - mixed 缺证书只打一行并继续 (`src/server.rs:54-56`); `--type https` 缺证书则 `bail` (`src/cli.rs:268-270`). daemon 下那一行提示也看不见. `--help` 把 mixed 写成 HTTP, HTTPS, and SOCKS5, README 特性列表又没把 HTTPS 说全.
  - `lookup_host(...).await?` 失败时不会带上后面的 `could not resolve listen host`.
  - SSH 私钥要等第一次连接才报 `could not load SSH private key` (`src/connector/ssh.rs:75-76`).
  - `panic = "abort"` 让任意 task panic 拉死整个进程; daemon 下连 panic 信息也没有.
- 影响: 照抄快速开始会在所有接口上开无认证混合代理. 用户看到错误也不知道改哪个文件或参数. 崩溃后没有现场.
- 建议: 非回环且没有 auth 也没有 allow-ip 时, 启动打印明确警告. mixed 的 `--help` 和 README 改成同一句: 没证书就只有 HTTP/SOCKS5. 文件错误带路径. scheme 错误列出允许的值. TLS 校验失败提示 `--proxy-ca`. SSH 私钥在启动时打开一次. `--pid-file` 和 `--log-file` 先于配置文件. 配置文件可以后做.

### P2-10. 上游 SOCKS 有口令时仍提供无认证方法

- 类别: 安全
- 位置: `src/connector/protocol.rs:78-90`
- 证据: credentials 存在时 methods 是 `[0x00, 0x02]`. 只有版本不对或方法 `0xff` 才失败. 选中 `0x02` 才发送用户名密码. 上游选 `0x00`, 或任何非 `0x02` 且非 `0xff` 的方法, 就直接发 CONNECT.
- 影响: 同时开放无认证和用户名密码的上游会选 `0x00`, 配错的密码仍能走通. 上游若选了未知方法, 后续 CONNECT 字节会和对端失步, 错误也不带方法号.
- 建议: 配置了口令时只提供 `0x02`. 选中的方法不是 `0x02` 就报错并带上方法号. 无凭证时才提供 `0x00`.

### P2-11. SOCKS 用户名和密码必须是 UTF-8

- 类别: bug
- 位置: `src/socks.rs:50`, `src/socks.rs:164-181`
- 证据: `read_string` 用 `String::from_utf8`. RFC 1929 是字节串. 拨号失败一律 `write_reply(..., 0x04)`, 不区分拒绝连接. 非 UTF-8 在 `?` 处返回, 不写认证失败应答.
- 影响: 非 UTF-8 口令或域名会被拆连接, 客户端看不到失败应答. 拨号失败也一律显示主机不可达.
- 建议: 用户名, 密码, 域名按字节比较和传递. 失败时先写规范 REP 再关闭. `ErrorKind::ConnectionRefused` 映射 `0x05`.

### P2-12. 上游 HTTP 200 判断过宽, 成功响应若带 body 会和隧道错位

- 类别: bug
- 位置: `src/connector/protocol.rs:49`, `src/fakehttp.rs:183`
- 证据: 成功条件是 `status.contains(" 200 ")`. 读完头就进入隧道, 不看 `Content-Length`.
- 影响: 正常 `HTTP/1.1 200 Connection Established` 没问题. 若上游在 200 后附带 body, 隧道第一跳会吃到那段 body. 本次没有用真实上游证明这条一定发生, 先当边界风险.
- 建议: 解析状态码字段, 不要做子串匹配. 200 且带 body 时拒绝, 不要把 body 当隧道数据.

### P2-13. fakehttp chunk 热路径有额外分配和拷贝; chunk 声明长度没有业务上限

- 类别: 效率
- 位置: `src/fakehttp/chunked.rs:11`, `src/fakehttp/chunked.rs:99-110`, `src/fakehttp/chunked.rs:131-137`, `src/fakehttp/crypto.rs:263-265`, `src/fakehttp/crypto/cipher.rs:136-176`
- 证据: 每个 chunk `format!("{count:X}\r\n")` 分配一次. 解密在原地完成后又 `extend_from_slice` 到 `plaintext_in`, 多一次拷贝. KDF 是单次 SHA-256 加 `.concat()`, 不是 HKDF, 也没有口令拉伸. README 示例 secret 是人可读密码. chunk size 行最长 64 字节, 但 16 位十六进制仍能变成很大的 `usize`; 读取是增量的, 不会一次分配那么大. 零 chunk 置 `Done` 时不读 writer 发出的尾部 `\r\n` (`0\r\n\r\n`).
- 影响: 分配和拷贝在 fakehttp 热路径上, 但是次于 P1-9 的握手成本. 弱 KDF 让低熵 secret 可被离线猜测. 超大 chunk 声明配合无超时可以拖住连接. 尾部 CRLF 留在缓冲区, 隧道结束时影响小.
- 建议: chunk 长度用栈缓冲格式化. 解密后直接从 `encrypted_in` 拷给调用方, 去掉中间 `plaintext_in` 往返. secret 当口令时改用 HKDF 或带拉伸的 KDF, 并在文档写最低熵要求. chunk 声明长度加上限. 零 chunk 把终止 CRLF 读完.

### P2-14. mixed 首字节把非 0x05/0x16 都当 HTTP

- 类别: 易用性
- 位置: `src/server.rs:153-168`
- 证据: `0x05` 进 SOCKS, `0x16` 进 TLS, 其余把该字节交给 HTTP. SOCKS4 的 `0x04` 会进 HTTP, 然后伪装 404.
- 影响: 未对外承诺 SOCKS4. 只是客户端会看到一个不像 SOCKS 的失败.
- 建议: 不打算支持就在 README 写明 mixed 不接受 SOCKS4. 不要为了这个加协议.

### P2-15. 构建脚本帮助写的是另一个项目

- 类别: 易用性
- 位置: `scripts/local_build.sh:16`, `scripts/local_build.sh:33`
- 证据: 用法说明是 `Build the brute binary`. 注释里的 Windows target 是 `x86_64-pc-windows-gnu`.
- 影响: `--help` 会让人以为脚本属于别的仓库. 按注释打出的 Windows 二进制可能和 release target 不一致.
- 建议: 改成 proxlet. 注释与 `.github/workflows/release.yml` 的 target 对齐.

### P2-16. 帧大小头缺失时双方各自回落到 16KiB

- 类别: bug
- 位置: `src/fakehttp.rs:90-93`, `src/fakehttp.rs:186-189`, `src/fakehttp/crypto.rs:241-247`
- 证据: 请求头或响应头缺失时, 双方都用 `DEFAULT_MAX_FRAME_SIZE` (16KiB) 再与本地上限取 min. 解密端拒绝 `len > max_frame_size + 16`. 直连且头都在时, 取 min 后是一致的.
- 影响: 中间盒去掉 `X-Proxlet-Max-Frame-Size` 时, 一侧可以按 32KiB 或 64KiB 发帧, 另一侧按 16KiB 拒绝, 隧道在第一个大帧上断开. 反向改大响应头也能让客户端发出服务端不接受的帧. 头本身也未认证, 见 P0-1.
- 建议: 缺头就失败关闭, 不要回落默认值. 协商结果放进握手 MAC. 响应值不得大于请求值.

### P2-17. `poll_shutdown` 在仍有待写块时可能不发终止 chunk

- 类别: bug
- 位置: `src/fakehttp/chunked.rs:287-295`
- 证据: 只有 `pending_write_out() == 0` 才 `queue_shutdown_chunk()`. 进入时若还有未写完的数据块, 同一次 poll 里 flush 完成后会直接 `inner.poll_shutdown`, 终止块不再入队. 读端把没有 `0` 块的 TCP 关闭当成 `UnexpectedEof`, 不是干净 EOF.
- 影响: 当前 relay 用的 `copy_bidirectional` 会先 flush 再 shutdown, 这条路径上终止块通常发得出去. 任何不先 flush 就 shutdown 的调用, 对端会报错并让两个方向一起失败. 本次没有用非 flush 调用复现.
- 建议: shutdown 分两段: 先写完已有数据, 再入队终止块, 写完后才关内层.

### P2-18. SSH `?key=` 里的 `+` 会被解码成空格; 空用户名会丢掉密码

- 类别: bug, 易用性
- 位置: `src/connector/upstream.rs:171-175`, `src/connector/upstream.rs:230-236`, `src/connector/upstream.rs:131-132`
- 证据: `ssh_identity_path` 用 `url.query_pairs()`. 这是 `application/x-www-form-urlencoded`, `+` 变空格. `ssh://user@host:22?key=/tmp/my+key` 会去打开 `/tmp/my key`. `credentials()` 在 `username()` 为空时直接返回 `None`, 不再看密码. `port_or_known_default()` 不认识 `ssh` / `socks5` / `fakehttp`, `ssh://user@host` 和 `socks5://host` 会报 `upstream proxy URL has no port`, 不填 22 或 1080.
- 影响: 路径含 `+` 时静默加载错文件. 只写密码的 userinfo 被当成没配凭证, 上游会匿名去连. 省掉端口的 URL 启动失败, 错误不提示默认端口.
- 建议: query 只做 percent-decode, 保留 `+`. 空用户名但有密码时报错. ssh 默认 22, socks5/socks5h 默认 1080. userinfo 不要解两次.

### P2-19. absolute-form 经 WHATWG `Url` 解析后路径被改写

- 类别: bug
- 位置: `src/http.rs:275-285`
- 证据: origin-form 用 `Url::parse` 再取 `path()` 和 `query()`, 不是客户端原始 request-target. 依赖的 `url` 2.5.8 对 http/https 把 `\` 写成 `/`, 并折叠点段. 其测试数据里 `http://example.com/foo/%2e./%2e%2e/.%2e/%2e.bar` 变成 `http://example.com/%2e.bar`.
- 影响: 源站看到的路径和客户端发出的 request-target 不一致. 前置过滤看到的字节和源站不一致. 正常浏览器请求通常不带反斜杠或 `%2e%2e`, 所以不是默认路径.
- 建议: 只拆 scheme 和 authority 用来拨号. path 和 query 原样转发.

### P2-20. 头值里的裸 LF 会在重写时留在 origin 请求里

- 类别: 安全
- 位置: `src/http.rs:149`, `src/http.rs:163-165`, `src/http.rs:286-291`
- 证据: 头按 `\r\n` 切分, 不拒绝值里的裸 `\n` 或单独 `\r`. 重写是 `format!("{name}: {value}\r\n")`. `Host: example.com\nX-Evil: 1\r\n` 会被当成一个头, 写出时值里的 LF 原样进入 origin 请求.
- 影响: 只认 CRLF 的源站仍看成一个头. 把裸 LF 当换行的源站会看到客户端原文本里不存在的头. 这是变换代理上的请求走私, 不是默认客户端路径. HTTP 请求行本身进不了 CR/LF, 那条注入见 P1-14.
- 建议: 拒绝名或值中含 CR, LF, NUL 的头, 回 400 并关闭. 不要重写后转发.

### P2-21. HTTP 上游对明文 HTTP 也先发 CONNECT

- 类别: bug
- 位置: `src/connector.rs:172-175`, `src/http.rs:88-90`
- 证据: 任何目标走 HTTP 或 HTTPS 上游都先 `establish_http_tunnel`. 客户端 `GET http://host/path` 因此变成向上游 `CONNECT host:80`, 隧道建立后再写 origin-form.
- 影响: 只允许 CONNECT 443 的上游会拒绝全部明文 HTTP 转发. 多一次握手. 客户端自己的 CONNECT 再套上游 CONNECT 是对的.
- 建议: 客户端非 CONNECT 且上游是 HTTP 时, 把 absolute-form 直接转给上游, 不要先打 CONNECT. 做的时候仍要处理 P1-1 的连接复用.

### P2-22. `::` 监听时 IPv4 映射地址对不上 allow-list

- 类别: 易用性
- 位置: `src/cli.rs:181-185`, `src/server.rs:62-66`
- 证据: 单地址是 `allowed == ip`, CIDR 是 `IpNet::contains`, 都不把 `::ffff:a.b.c.d` 折成 IPv4. 拒绝时 drop socket, 没有 fd 泄漏.
- 影响: 监听 `::` 且系统未开 V6ONLY 时, IPv4 客户端以映射地址出现, 配置里的 `a.b.c.d` 匹配失败. 失败方向是误拒, 不是绕过.
- 建议: 比较前把 IPv4-mapped IPv6 折成 IPv4, 或在启动日志里说明必须同时写两种形式.

### P2-23. relay 固定 8KiB, 现有 bench 测不到转发吞吐

- 类别: 效率
- 位置: `src/connector.rs:274-278`
- 证据: `copy_bidirectional` 使用 tokio 1.52.3 的 `DEFAULT_BUF_SIZE`, 每方向 8KiB. `benches/proxy.rs` 每次迭代都含建连, 负载只有很小的响应.
- 影响: 大流量隧道的 syscall 次数偏高. 现有 bench 不能用来判断缓冲区或逐字节读头的改进. 这低于 P1-9 的握手成本.
- 建议: 先补一条至少数百 KiB 的双向拷贝 bench, 再决定要不要换成 `copy_bidirectional_with_sizes`. 不要凭感觉改.

## 建议处理顺序

这是阅读顺序, 不是实现承诺.

1. P0-1, 以及 P1-11, P1-12, P1-8. fakehttp 现在不能把加密当成目标绑定或接入控制.
2. P1-1 和 P1-15. 默认 HTTP 模式会传错主机; HTTPS 监听和 fakehttp 上游可能在 200 或请求发出前挂死.
3. P1-2 和 P1-5. 否则一个瞬时错误或一个慢连接就能打掉服务. 连接上限和 idle-timeout 继续跟 TODO, 但 connect timeout 要单独加.
4. P1-3 和 P1-10. 没有就绪确认和日志, 后面的故障都看不见.
5. P1-4, P1-6, P1-7, P1-14. 认证静默失败, 密码留在 argv, 以及 HTTP 上游头注入.
6. P1-9, P1-13, 再加 P2-6. 先有链式 bench, 再做 SSH session 复用, IP 字面量和 `TCP_NODELAY`.
7. P2 里的协议边界和文案, 按使用者是否踩到排. P2-19 和 P2-20 只在变换代理路径上有安全意义.

## 测试缺口

附在对应条目下, 不单独灌水. 现有覆盖主要是 `tests/cli.rs`, `tests/http.rs`, `tests/socks.rs`, `tests/connector.rs` (6 行), `tests/listener_upstream_integration.rs`.

缺这些可观察行为:

- 同一 HTTP 客户端连接上的第二个请求不能打到第一个 origin.
- fakehttp 改写 path 里的 target 后, 服务端在校验失败前不得 `connect`, 也不得解密转发.
- 重放同一 fakehttp session 必须被拒绝, 不能从 server-to-client 计数器 0 再加密一段新响应.
- `https://` absolute-form 被拒绝, 而不是明文写到 443.
- 只给 `--user` 或只给 `--auth` 时进程失败.
- `--aes-secret` 配在非 fakehttp 监听上时进程失败.
- `socks5h` 转发 `127.0.0.1` / `::1` 时使用 ATYP 1 或 4, 不是 ATYP 3.
- SOCKS 域名含 CR/LF 时, HTTP 上游 CONNECT 不得发出注入头.
- `accept` 返回资源类错误时进程继续监听.
- HTTPS 监听写出 CONNECT 200 后, 客户端继续发送之前, 对端必须已经收到这 200.
- `GET http://example.com/foo/%2e%2e/secret` 转发到源站时 path 仍是原始 request-target, 不是折叠后的 `/secret`.
- daemon 子进程绑定失败时, 父进程必须以非 0 退出并打印原因, 不能只打印 PID.
- allowlist 集成覆盖仍按 TODO, 不在这里再开一条.
