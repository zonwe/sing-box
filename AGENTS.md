# AGENTS.md

本文件适用于整个仓库。修改子目录中的文件时，也应遵守这里的约定。

## 项目定位

这是 233boy/sing-box 的 Bash 安装与管理脚本仓库，不是 SagerNet/sing-box 核心源码。
脚本面向 Ubuntu、Debian、CentOS、SUSE 和 Alpine，支持 systemd/OpenRC 以及
amd64/arm64。

主要入口和模块：

- `install.sh`：以 root 身份安装依赖、下载 sing-box/jq/本仓库脚本，并写入系统目录。
- `sing-box.sh`：安装后的命令入口；`is_sh_ver` 同时被发布工作流读取。
- `src/init.sh`：初始化公共变量、辅助函数并加载核心模块。
- `src/core.sh`：配置的添加、修改、查看、删除、导入和更新等主要逻辑。
- `src/systemd.sh`：systemd/OpenRC 服务安装与依赖处理。
- `src/caddy.sh`、`src/dns.sh`、`src/download.sh`、`src/log.sh` 等：各自负责独立功能。
- `.github/workflows/release.yml`：按 `is_sh_ver` 打包并发布 `code.tar.gz`。

## 修改原则

- 保持现有 CLI、短参数、协议名、配置名以及中文输出兼容；除非任务明确要求，
  不要移除或重命名用户可见行为。
- 修改前先追踪入口、`load` 关系和共享全局变量。这个项目大量依赖 source 后的
  全局状态，不要把变量误判为未使用，也不要随意改成局部变量。
- 优先做小而集中的修改。不要顺手格式化整个 `src/core.sh` 或大范围重写旧逻辑。
- 沿用 Bash 风格：4 空格缩进、`name() { ...; }` 函数、`[[ ... ]]` 条件、
  `case` 处理分支，变量和函数使用小写 snake_case。
- 新代码应合理引用变量和路径，使用 `local` 限制新函数中的临时变量；但修复旧代码时
  要先确认原有单词拆分、通配符展开或全局赋值是否是有意行为。
- 不要仅为“更严格”而全局启用 `set -e`、`set -u` 或 `pipefail`；现有控制流可能依赖
  命令失败后的显式检查或未设置变量。
- 不要无必要地增加运行时依赖。若必须增加，应同步处理所有支持的包管理器和 Alpine。
- 下载逻辑必须同时考虑 amd64/arm64、失败重试、临时文件和已有代理行为。
- 修改 JSON 生成逻辑时，保持最终配置可被目标 sing-box 版本解析；优先复用现有 jq
  和配置辅助逻辑。
- 涉及端口、UUID、密码、密钥、域名、TLS、Caddy 或 DNS 的修改，不得在日志、测试夹具
  或提交内容中写入真实凭据和生产数据。

## 高风险区域

- 安装、卸载、删除配置、覆盖配置、更新服务和防火墙/内核设置都可能修改真实系统。
  不要在开发机上直接执行这些路径。
- 不要为了测试而向 `/etc/sing-box`、`/usr/local/bin`、`/var/log` 或系统服务目录写入内容。
- 不要直接运行 `install.sh`、`sing-box uninstall`、`sing-box del`、`sing-box ddel`、
  BBR、服务安装或更新流程，除非用户明确授权且环境是可丢弃的 Linux VM/容器。
- 测试删除逻辑时使用隔离的临时目录和伪造配置，并再次核对目标路径，禁止使用宽泛的
  `rm -rf`。
- `sing-box.sh` 中的 `is_sh_ver` 会驱动 GitHub Release。普通修复不要顺带改版本号；
  只有发布任务才更新它，并确认对应 tag 规则。

## 验证

每次修改至少执行与改动匹配的静态检查：

```bash
bash -n install.sh sing-box.sh src/*.sh
```

如果环境已安装 ShellCheck，再检查改动涉及的脚本：

```bash
shellcheck path/to/changed-script.sh
```

仓库中的旧代码可能已有 ShellCheck 告警；应修复本次引入的问题，不要在无关文件中做
大规模告警清理。涉及 JSON 生成时，还应对生成结果运行：

```bash
jq empty generated-config.json
sing-box check -c generated-config.json
```

需要端到端验证时，使用支持目标 init 系统的一次性 Linux VM，至少覆盖任务涉及的发行版、
架构或 systemd/OpenRC 分支。优先使用 `gen` 或其他不落盘路径检查配置；任何会访问网络、
安装包、创建服务、申请证书或改动系统状态的测试，都应先明确说明影响。

## 文档与交付

- 用户可见参数、帮助文本或行为发生变化时，同步更新 `README.md` 和/或 `src/help.sh`。
- 帮助示例应可复制执行，并与实际别名和参数顺序一致。
- 交付时说明改了哪些文件、做了哪些检查，以及哪些 root/网络/服务场景未在本机执行。
- 提交信息使用「类型: 中文描述」的中文格式，结尾统一加「哼」；正文分点列出改动，
  不要在提交信息里写入令牌、密钥或真实域名等敏感信息。
