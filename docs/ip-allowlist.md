# sing-box 来源 IP 白名单

本文介绍如何使用 `sing-box acl` 只允许指定的 IP/CIDR 使用服务器上的代理服务，
以及它的生效范围、局限和排查方法。

> 白名单直接写系统防火墙规则。启用前请先执行 `sing-box acl add <你的客户端 IP>`，
> 并留意启用后 5 分钟的自动回滚保护。

## 1. 用途与边界

适用场景：

- 自用或小圈子使用，只允许固定的几个出口 IP 连接。
- 把被扫描、被撞库的暴露面收缩到已知来源。
- 配合多配置同时运行，限制整机代理端口的可达来源。

**不适用**的认知误区：

| 你可能以为 | 实际情况 |
| --- | --- |
| 白名单能挡住扫描器 | 能。规则在防火墙层丢弃，未认证流量不会进入 sing-box 进程 |
| 可以按域名/配置区分 | 不能。防火墙按端口生效，同一端口上的多个配置共享同一条白名单 |
| 可以限制被 Cloudflare 代理的域名 | 不能。此时来源 IP 是 CDN 节点，不是真实客户端 |
| 可以限制本机其他程序 | 白名单只管来源 IP，不区分本机进程；本机访问由 `listen: 127.0.0.1` 控制 |

### 为什么不用 sing-box 自身的路由规则

sing-box 的路由规则里确实有 `source_ip_cidr`，但它在**入站完成传输层握手、TLS 握手
和协议认证之后**才参与匹配，属于授权细化而不是准入控制：未认证的扫描流量照样能完成
握手、消耗 CPU、并暴露服务指纹。Trojan 和 Hysteria2 的认证失败还会走 fallback /
masquerade 路径，根本不会进入路由。因此白名单必须落在系统防火墙上，由内核在连接建立
前丢弃非白名单来源的包。

## 2. 快速开始

```bash
# 1. 添加允许的来源（可重复执行，支持 IPv4/IPv6 与 CIDR）
sing-box acl add 203.0.113.7
sing-box acl add 198.51.100.0/24
sing-box acl add 2001:db8::/32

# 2. 查看将要保护哪些端口
sing-box acl status

# 3. 启用
sing-box acl on

# 4. 确认客户端仍可连接后，取消自动回滚
sing-box acl confirm
```

关闭与清理：

```bash
sing-box acl off        # 移除防火墙规则并停用开机服务，保留白名单列表
sing-box acl on         # 使用原列表重新启用
sing-box acl uninstall  # 连同配置目录一起清除
```

## 3. 命令

| 命令 | 说明 |
| --- | --- |
| `acl on [--yes]` | 启用白名单，写入防火墙规则并注册开机服务 |
| `acl off` | 关闭并移除全部规则 |
| `acl add <ip \| cidr>` | 添加允许来源 |
| `acl del <ip \| cidr>` | 移除来源 |
| `acl list` | 查看列表 |
| `acl clear` | 清空列表 |
| `acl status` | 状态、后端、保护端口、开机服务 |
| `acl sync` | 按当前配置重新生成并应用规则 |
| `acl confirm` | 取消启用时的自动回滚 |
| `acl backend <auto \| nft \| iptables-legacy>` | 指定防火墙后端 |
| `acl uninstall` | 卸载白名单并删除配置目录 |

状态文件为 `/etc/sing-box/acl/config.json`（权限 600），渲染后的规则保存在同目录，
仅 root 可读。

### 端口变化会自动同步

新增、删除配置或执行 `fix-all` 之后，脚本会按新的入站端口重新应用规则。批量删除时
只会同步一次。也可以随时手工执行 `sing-box acl sync`。

### 5 分钟自动回滚

`on` 和 `sync` 之后会启动一个倒计时：如果 5 分钟内没有执行 `sing-box acl confirm`，
规则会被自动移除并把白名单置为关闭。这是为了在配错白名单、把自己锁在服务器外面时
无需救援即可恢复。已经确认过配置的场景可以用 `acl sync` 前先确认客户端可用性来跳过，
或直接执行 `acl confirm`。

## 4. 保护哪些端口

启用时按 `conf/*.json` 逐个入站解析：

| 入站情况 | 处理 |
| --- | --- |
| `listen` 为 `::`、`0.0.0.0` 或未设置 | 保护该 `listen_port`（TCP + UDP） |
| `listen` 为 `127.0.0.1` / `::1` / `localhost` | 跳过。这类入站只接受本机（通常是 Caddy）连接，对它设来源限制无效且会切断 Caddy |
| `tun` / `redirect` / `tproxy` | 跳过，不监听 TCP/UDP 端口 |
| 存在 Caddy 自动 TLS 站点 | 额外保护 `https_port`（默认 443），并在同端口上覆盖 UDP（HTTP/3） |
| Caddy 的 `http_port`（默认 80） | **始终不保护**，保证 ACME 校验可达 |

规则形态（nftables 后端）：

```text
table inet nftables_singbox_acl {
    chain input {
        type filter hook input priority filter; policy accept;
        ct state established,related accept
        iifname "lo" accept
        tcp dport { 443 8443 } ip saddr { 203.0.113.7 } accept
        ...
        tcp dport { 443 8443 } drop
        udp dport { 443 8443 } drop
    }
}
```

关键点：

- **独立表**：只新增 `inet nftables_singbox_acl`，不改动用户既有规则，也从不执行
  `flush ruleset`。
- **`policy accept`**：基链策略保持 accept，只有明确列出的端口会被 drop，因此不可能
  因为本模块而影响 SSH 或未列出的服务。
- **`iifname "lo"` 与 established 放行**：保证 Caddy→sing-box 的回环连接和已有的
  长连接不会被打断。
- **TCP 与 UDP 同时覆盖**：Hysteria2、TUIC、QUIC 都走 UDP，只放行 TCP 会出现
  "TCP 能连、UDP 连不上"的怪现象。

## 5. 后端与系统防火墙

| 后端 | 说明 |
| --- | --- |
| `nft`（默认优先） | 独立表，单次事务原子生效，卸载一条命令删除 |
| `iptables-legacy` | 独立链 `SB_ACL`，同时写入 IPv4 和 IPv6，插到 INPUT 首位 |

`acl backend` 可显式指定；`auto` 会优先使用 `nft`。

**检测到 firewalld 或 ufw 时脚本会拒绝写入**，除非显式加 `--yes`。这两个前端会声明
对 netfilter 规则的独占管理权，第三方规则可能在它们重载时被清除：

- firewalld：`FlushAllOnReload` 默认开启，重载会丢弃运行时的第三方规则。
- ufw：`MANAGE_BUILTINS=yes` 时，stop/reload 会清空内建链。

需要在这种主机上使用时，请按 `acl on` 输出的提示，用 `firewall-cmd --permanent` 或
`ufw` 自行放行。同样地，若检测到其他防火墙表存在 `policy drop` 的 input 链，脚本也会
提示并中止——因为 nftables 的 `accept` 不是最终裁决，白名单客户端仍可能被那些规则丢弃。

## 6. 与 Caddy 自动 TLS 共存

Caddy 使用 HTTP-01 与 TLS-ALPN-01 两种校验，且 Let's Encrypt **不公布校验节点 IP**
（HTTP-01 只能走 80，TLS-ALPN-01 必须走 443）。因此：

- 80 端口始终保持开放，HTTP-01 可以正常完成，证书照常签发。
- 443 端口被白名单保护后，TLS-ALPN-01 会失败，Caddy 会回退到 HTTP-01（它会在多次
  尝试后优先选择成功率更高的方式），表现为偶发的校验重试。
- 如果希望彻底避免重试，可以改用 DNS-01 校验（`tls { dns ... }`），它不需要开放任何
  入站端口；此时也可以把 80 端口一并纳入白名单。

需要按域名而不是按端口限制访问时，防火墙做不到：同一个 443 端口上的多个站点共享同一
份来源限制。这种需求应使用 Caddy 的 `remote_ip` 匹配器在站点层实现。

## 7. 已知限制

- **CDN / 中转**：域名走 Cloudflare 等代理时，服务端看到的来源是 CDN 节点，白名单按
  真实客户端 IP 配置将无法命中。需要改用 Caddy 层按 `CF-Connecting-IP` 等头部判断，
  并自行承担伪造头部的风险。
- **按配置区分**：同一端口上的多个配置共享白名单。
- **容器端口**：Docker 发布的端口经 `nat` 表转发后走 FORWARD，不经过 INPUT，本模块
  的规则对它们无效；如需限制请使用 `DOCKER-USER`。
- **IP 会变**：移动网络、家宽重拨、QUIC 连接迁移都会改变来源地址，需要及时更新列表。
  建议按网段而不是单个 IP 添加。
- **不替代认证**：白名单是网络层收敛，仍需保留强 UUID/密码。

## 8. 排查

| 现象 | 排查方向 |
| --- | --- |
| 启用后全部客户端超时 | 5 分钟内未确认会自动回滚；否则用 `sing-box acl off` 或控制台恢复 |
| TCP 能连、UDP 不通 | 确认 UDP 端口在白名单内，检查中间网络是否屏蔽 UDP |
| 生效后自己也被挡 | 用 `sing-box acl add <当前出口 IP>` 后 `sing-box acl sync`；注意出口 IP 可能与预期不同 |
| 重启后规则消失 | `sing-box acl status` 看开机服务状态；确认系统未运行会 `flush ruleset` 的 nftables 服务 |
| 规则被系统工具清掉 | 检查是否有 firewalld / ufw 在重载；两者都会覆盖第三方规则 |
| 证书续签失败 | 确认 80 端口未被白名单保护，或改用 DNS-01 |

检查规则是否真的存在：

```bash
nft list table inet nftables_singbox_acl     # nft 后端
iptables -S SB_ACL; ip6tables -S SB_ACL      # iptables 后端
sing-box acl status
```

## 9. 安全与恢复

- 规则只针对明确列出的端口，不会影响 SSH、DNS、NTP 等未列出的服务。
- 服务端自身的出站 DNS/NTP 查询属于 OUTPUT 方向，不受影响。
- 若怀疑被锁在外面：云厂商控制台（VNC/串口）登录后执行 `sing-box acl off`，或等待
  自动回滚。也可以直接 `nft delete table inet nftables_singbox_acl` 应急恢复。
- 卸载脚本（`sing-box uninstall`）会先移除白名单规则和开机服务，再删除配置目录。
