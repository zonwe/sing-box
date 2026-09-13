# 介绍

最好用的 sing-box 一键安装脚本 & 管理脚本

# 特点

- 快速安装
- 无敌好用
- 零学习成本
- 自动化 TLS
- 简化所有流程
- 兼容 sing-box 命令
- 强大的快捷参数
- 支持所有常用协议
- 一键添加 VLESS-REALITY (默认)
- 一键添加 TUIC
- 一键添加 Trojan
- 一键添加 Hysteria2
- 一键添加 AnyTLS
- 一键添加 Shadowsocks 2022
- 一键添加 VMess-(TCP/HTTP/QUIC)
- 一键添加 VMess-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 VLESS-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 Trojan-(WS/H2/HTTPUpgrade)-TLS
- 一键启用 BBR
- 默认启用流量审计服务与 Web 仪表盘
- 按配置文件统计指定时间段的流量、来源 IP、用户和连接数
- 按来源 IP、配置文件和 UUID/用户统计明细流量
- 审计数据筛选、CSV/JSON 导出与自动保留
- 一键更改伪装网站
- 一键更改 (端口/UUID/密码/域名/路径/加密方式/SNI/等...)
- 还有更多...

# 设计理念

设计理念为：**高效率，超快速，极易用**

脚本基于作者的自身使用需求，以 **多配置同时运行** 为核心设计

并且专门优化了，添加、更改、查看、删除、这四项常用功能

你只需要一条命令即可完成 添加、更改、查看、删除、等操作

例如，添加一个配置仅需不到 1 秒！瞬间完成添加！其他操作亦是如此！

脚本的参数非常高效率并且超级易用，请掌握参数的使用

# 一键安装

## 全新服务器

在受支持的 Linux 服务器上以 `root` 身份执行：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/WangzyaaaA/sing-box/main/install.sh)
```

无需克隆整个仓库。安装器会从本仓库的 GitHub Release 下载所需脚本，并继续使用原来的
`/usr/local/bin/sing-box` 和 `/usr/local/bin/sb` 命令入口。全新安装会自动启用流量审计，
默认仅监听 `127.0.0.1:9091`，安装结束时会显示访问地址和随机令牌。

如需自定义审计监听地址或端口：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/WangzyaaaA/sing-box/main/install.sh) --audit-listen 0.0.0.0 --audit-port 9091
```

`0.0.0.0` 会将无 TLS 的页面暴露到网络，请配合防火墙或反向代理限制访问。如不需要审计：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/WangzyaaaA/sing-box/main/install.sh) --no-audit
```

## 已安装原版脚本

如果服务器已经使用 `233boy/sing-box` 安装，执行下面的一条命令即可更新管理脚本并启用审计：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/WangzyaaaA/sing-box/main/install.sh) --script-update && sing-box audit enable
```

如需迁移时直接监听指定地址和端口，可把最后一段改为：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/WangzyaaaA/sing-box/main/install.sh) --script-update && sing-box audit enable 0.0.0.0 9091
```

这个操作只覆盖 `/etc/sing-box/sh` 中的管理脚本，不重装 sing-box，不修改现有代理配置，
也不会删除已有审计数据库。若原配置尚未启用 Clash API，`audit enable` 会添加仅监听本机的
管理接口并重启一次 sing-box。迁移后可继续使用 `sing-box update.sh` 获取本仓库的新版本。

下载默认验证 HTTPS 证书，安装器会先准备 `ca-certificates`。脚本更新会检查包结构、Bash
语法和可用的 SHA-256 摘要，核心更新会先用新核心检查当前配置；通过后再替换文件。
更新前正在运行的服务会重启并检查状态，失败时尝试恢复原版本；已停止的服务保持停止。
审计运行期间更新脚本也会重启审计服务，使页面和后端一起生效。旧发布包没有摘要时，
会明确提示并使用 TLS 与包结构校验；证书错误应修复系统时间或 CA 配置后重试。

# 文档

普通分支 push 和 Pull Request 会运行 Bash／JavaScript 语法检查及隔离回归测试，不会发布。
发布时需先更新 `sing-box.sh` 中的 `is_sh_ver`，再创建名称完全一致的新版本 tag（例如
`v1.19`）；检查通过后会发布 `code.tar.gz` 和 `code.tar.gz.sha256`，已有 Release 不会被覆盖。
本地回归测试需要 Bash、Python 3 和 jq，运行 `python3 -B -m unittest discover -s tests -v`；
测试只使用临时目录、模拟服务和回环 HTTP 接口。

- 流量审计：[部署与使用文档](docs/traffic-audit.md)
- 原脚本安装及使用：https://233boy.com/sing-box/sing-box-script/

# 帮助

使用：`sing-box help`

```
sing-box script v1.0 by 233boy
Usage: sing-box [options]... [args]...

基本:
   v, version                                      显示当前版本
   ip                                              返回当前主机的 IP
   pbk                                             同等于 sing-box generate reality-keypair
   get-port                                        返回一个可用的端口
   ss2022                                          返回一个可用于 Shadowsocks 2022 的密码

一般:
   a, add [protocol] [args... | auto]              添加配置
   c, change [name] [option] [args... | auto]      更改配置
   d, del [name]                                   删除配置**
   i, info [name]                                  查看配置
   qr [name]                                       二维码信息
   url [name]                                      URL 信息
   log                                             查看日志
   audit [...]                                     流量审计、Web 展示与数据导出
更改:
   full [name] [...]                               更改多个参数
   id [name] [uuid | auto]                         更改 UUID
   host [name] [domain]                            更改域名
   port [name] [port | auto]                       更改端口
   path [name] [path | auto]                       更改路径
   passwd [name] [password | auto]                 更改密码
   key [name] [Private key | auto] [Public key]    更改密钥
   method [name] [method | auto]                   更改加密方式
   sni [name] [ ip | domain]                       更改 serverName
   new [name] [...]                                更改协议
   web [name] [domain]                             更改伪装网站

进阶:
   dns [...]                                       设置 DNS
   dd, ddel [name...]                              删除多个配置**
   fix [name]                                      修复一个配置
   fix-all                                         修复全部配置
   fix-caddyfile                                   修复 Caddyfile
   fix-config.json                                 修复 config.json
   import                                          导入 sing-box/v2ray 脚本配置

管理:
   un, uninstall                                   卸载
   u, update [core | sh | caddy] [ver]             更新
   U, update.sh                                    更新脚本
   s, status                                       运行状态
   start, stop, restart [caddy | audit]            启动, 停止, 重启
   t, test                                         测试运行
   reinstall                                       重装脚本

测试:
   debug [name]                                    显示一些 debug 信息, 仅供参考
   gen [...]                                       同等于 add, 但只显示 JSON 内容, 不创建文件, 测试使用
   no-auto-tls [...]                               同等于 add, 但禁止自动配置 TLS, 可用于 *TLS 相关协议
其他:
   bbr                                             启用 BBR, 如果支持
   bin [...]                                       运行 sing-box 命令, 例如: sing-box bin help
   [...] [...]                                     兼容绝大多数的 sing-box 命令, 例如: sing-box generate uuid
   h, help                                         显示此帮助界面

谨慎使用 del, ddel, 此选项会直接删除配置; 无需确认
反馈问题) https://github.com/WangzyaaaA/sing-box/issues
文档(doc) https://233boy.com/sing-box/sing-box-script/
```

# 流量审计

添加、更改或修复配置时，脚本会先校验完整配置，通过后再替换文件；最近一次被替换的
配置保存在 `/etc/sing-box/backups/`，仅 root 可读取。审计导出使用临时文件，下载或保存
失败时保留已有目标文件。备份可能包含凭据，请按原配置的权限要求保存。
`fix-all` 会先逐项修复并校验配置，最后进行整体校验，通过后才重启服务。

完整说明请参阅：[流量审计部署与使用](docs/traffic-audit.md)。

流量审计是全新安装时默认启用的独立服务，默认只监听 `127.0.0.1:9091`。它通过 sing-box 的本机
Clash API 采集连接与上下行字节，使用 SQLite 持久化，并提供响应式 Web 页面、筛选、
分页以及 CSV/JSON 导出。仪表盘以趋势、热门目标、配置占比、访问热力和流量路径等图表为主，
原始明细按需展开。连接流量按采集周期保存增量，既可按配置文件汇总，也可按来源
IP、配置文件及可识别的 UUID/用户汇总，并可选择预设或自定义时间段。默认保留 90 天
数据。启用审计时会按需安装 Python 3；使用安装参数 `--no-audit` 时不会安装该依赖。

速率按最近一次成功采集的字节增量和实际间隔计算，支持 1–60 秒采集间隔。网络或 SQLite
异常会显示为采集异常并自动退避重试；健康接口同时提供采集线程及连接状态。

```bash
# 全新安装会自动启用；已有配置重复执行时可同时更新监听地址和端口
sing-box audit enable
sing-box audit enable 0.0.0.0 9091

# 查看状态、页面地址和令牌
sing-box audit status
sing-box audit url
sing-box audit token

# 导出最近 7 天的数据
sing-box audit export csv 7d
sing-box audit export json 7d /root/audit.json

# 按 IP / 配置汇总最近 7 天用量
sing-box audit report csv 7d
sing-box audit report json 7d /root/audit-usage.json

# 按配置文件汇总最近 7 天用量
sing-box audit config-report csv 7d
sing-box audit config-report json 7d /root/audit-config-usage.json

# 调整保留天数或采集间隔
sing-box audit set retention 30
sing-box audit set interval 5

# 停止但保留数据；或彻底卸载并删除数据
sing-box audit disable
sing-box audit uninstall
```

从远程电脑访问默认监听地址时，建议使用 SSH 端口转发：

```bash
ssh -L 9091:127.0.0.1:9091 root@服务器IP
```

然后打开 `http://127.0.0.1:9091/` 并输入 `sing-box audit token` 显示的令牌。
如确需监听所有网卡，可使用 `sing-box audit enable 0.0.0.0 9091`，但应在防火墙或
反向代理处限制来源并配置 TLS。审计记录包含来源 IP、目标地址和用户标识，请依据当地
法规设置保留期限并控制访问权限。
