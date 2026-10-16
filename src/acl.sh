#!/bin/bash

# 来源 IP 白名单: 只允许指定 IP/CIDR 使用代理服务.
#
# 由 sing-box 核心在握手/认证之后执行的路由规则无法阻止未认证流量, 因此白名单
# 必须落在系统防火墙上: 本模块自建独立表(SINGBOX_ACL)或独立链(SB_ACL), 只对自己
# 保护的端口下 drop, 绝不修改用户既有规则, 也绝不执行 flush ruleset.

acl_table=nftables_singbox_acl
acl_chain=SB_ACL
acl_state_dir=$is_core_dir/acl
acl_state=$acl_state_dir/config.json
acl_rules=$acl_state_dir/rules.nft
acl_service=sing-box-acl
acl_comment='singbox-acl'
acl_rollback_delay=300

acl_state_load() {
    acl_enabled=false
    acl_backend=auto
    acl_allow=()
    [[ -f $acl_state ]] || return 0
    acl_enabled=$(jq -r '.enabled // false' "$acl_state" 2>/dev/null)
    acl_backend=$(jq -r '.backend // "auto"' "$acl_state" 2>/dev/null)
    acl_tmp_allow=
    while read -r acl_tmp_allow; do
        acl_tmp_allow=$(acl_trim "$acl_tmp_allow")
        [[ $acl_tmp_allow ]] && acl_allow+=("$acl_tmp_allow")
    done < <(jq -r '(.allow // [])[]' "$acl_state" 2>/dev/null)
    unset acl_tmp_allow
    [[ $acl_backend ]] || acl_backend=auto
}

acl_state_save() {
    local content tmp
    mkdir -p "$acl_state_dir" && chmod 700 "$acl_state_dir" || return 1
    content=$(jq -n --argjson enabled "$acl_enabled" --arg backend "$acl_backend" \
        --args '{enabled: $enabled, backend: $backend, allow: [$ARGS.positional]}' "${acl_allow[@]}") || return 1
    tmp=$(mktemp "$acl_state_dir/.config.XXXXXX") || return 1
    printf '%s\n' "$content" >"$tmp" || {
        rm -f "$tmp"
        return 1
    }
    chmod 600 "$tmp" && mv -f "$tmp" "$acl_state"
}

acl_require_root() {
    [[ $EUID != 0 ]] && err "此操作需要 root 权限."
}

acl_trim() {
    local value=$1
    value=${value//$'\r'/}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    printf '%s' "$value"
}

# ipv4 | ipv6 | none
acl_addr_family() {
    local value=$1 part
    [[ $value ]] || {
        echo none
        return
    }
    if [[ $(grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$' <<<"$value") ]]; then
        IFS=/ read -r value part <<<"$value"
        [[ $part && ( $part -lt 0 || $part -gt 32 ) ]] && {
            echo invalid
            return
        }
        IFS=. read -r -a acl_tmp_octets <<<"$value"
        for part in "${acl_tmp_octets[@]}"; do
            [[ $part =~ ^[0-9]{1,3}$ && ${#part} -le 3 && $part -le 255 ]] || {
                unset acl_tmp_octets
                echo invalid
                return
            }
        done
        unset acl_tmp_octets
        echo ipv4
        return
    fi
    if [[ $value == *:* && $(grep -E '^[0-9a-fA-F:]+(\/[0-9]{1,3})?$' <<<"$value") ]]; then
        IFS=/ read -r value part <<<"$value"
        [[ $part && ( $part -lt 0 || $part -gt 128 ) ]] && {
            echo invalid
            return
        }
        echo ipv6
        return
    fi
    echo invalid
}

acl_validate_cidr() {
    local value=$1 family
    family=$(acl_addr_family "$value")
    case $family in
    ipv4 | ipv6)
        return 0
        ;;
    *)
        err "($value) 不是有效的 IP 或 CIDR, 例如: 203.0.113.7 或 198.51.100.0/24"
        ;;
    esac
}

acl_index_of() {
    local value=$1 i=0
    for i in ${!acl_allow[@]}; do
        [[ ${acl_allow[$i]} == "$value" ]] && {
            echo "$i"
            return 0
        }
    done
    return 1
}

acl_add_entry() {
    local value
    value=$(acl_trim "$1")
    [[ $value ]] || err "请指定 IP 或 CIDR, 例如: $is_core acl add 203.0.113.7"
    acl_validate_cidr "$value"
    acl_index_of "$value" &>/dev/null && {
        msg "\n($value) 已在白名单中.\n"
        return
    }
    acl_allow+=("$value")
    msg "\n已加入白名单: $(_green "$value")"
}

acl_del_entry() {
    local value index
    value=$(acl_trim "$1")
    [[ $value ]] || err "请指定需要移除的 IP 或 CIDR."
    index=$(acl_index_of "$value") || err "白名单中不存在 ($value)."
    unset 'acl_allow[index]'
    acl_allow=("${acl_allow[@]}")
    msg "\n已从白名单移除: $(_yellow "$value")"
}

# 返回当前生效的防火墙后端: nft | iptables-legacy | none
acl_backend_detect() {
    if [[ $acl_backend != auto ]]; then
        type -P "$acl_backend" &>/dev/null && {
            echo "$acl_backend"
            return
        }
        err "找不到已配置的防火墙后端: $acl_backend"
    fi
    if type -P nft &>/dev/null && [[ ! $(grep -qs '' /proc/net/ip_tables_names) ]]; then
        # 同时存在 iptables-nft 时 nft 依然可用, 两者都写入 nf_tables.
        echo nft
        return
    fi
    if type -P nft &>/dev/null; then
        echo nft
        return
    fi
    if type -P iptables &>/dev/null; then
        echo iptables-legacy
        return
    fi
    echo none
}

acl_backend_label() {
    case $1 in
    nft) echo "nftables (独立表 inet $acl_table)" ;;
    iptables-legacy) echo "iptables (独立链 $acl_chain)" ;;
    *) echo "未检测到 nft 或 iptables" ;;
    esac
}

acl_frontend_detect() {
    acl_frontend=
    if type -P firewall-cmd &>/dev/null && [[ $(firewall-cmd --state 2>/dev/null) == running ]]; then
        acl_frontend=firewalld
        return
    fi
    if type -P ufw &>/dev/null && [[ $(ufw status 2>/dev/null | head -n1) == *active* ]]; then
        acl_frontend=ufw
        return
    fi
}

acl_check_conflicts() {
    local assume_yes=$1 backend=$2 hook
    acl_frontend_detect
    case $acl_frontend in
    firewalld | ufw)
        if [[ $assume_yes ]]; then
            warn "检测到 $acl_frontend 正在管理系统防火墙, 仍按你的要求继续; 该前端重载防火墙时可能覆盖本模块规则."
            return 0
        fi
        warn "检测到 $acl_frontend 正在管理系统防火墙."
        msg "为避免两套规则互相覆盖, 本脚本不自动写入防火墙规则."
        msg "$acl_frontend 会声明对 netfilter 规则的独占管理权, 使用其他工具写入可能被其重载时清除."
        msg "\n请手工放行你的客户端 IP/CIDR, 然后使用其他方式限制访问:"
        if [[ $acl_frontend == firewalld ]]; then
            msg "\n  firewall-cmd --permanent --zone=public --add-rich-rule='rule family=\"ipv4\" priority=\"-10\" source address=\"203.0.113.7\" port port=\"443\" protocol=\"tcp\" accept'"
            msg "  firewall-cmd --permanent --zone=public --add-rich-rule='rule family=\"ipv4\" priority=\"10\" port port=\"443\" protocol=\"tcp\" drop'"
            msg "  firewall-cmd --reload\n"
        else
            msg "\n  ufw allow from 203.0.113.7 to any port 443 proto tcp"
            msg "  ufw deny 443/tcp\n"
        fi
        err "已取消, 未写入任何防火墙规则; 强制继续: $is_core acl on --yes"
        ;;
    esac
    [[ $backend == nft ]] || return 0
    # 其他工具在 input hook 上的 drop 策略会让本模块的 accept 失效 (accept 不是最终裁决).
    hook=$(nft -a list chains 2>/dev/null | grep -E 'hook input' | grep -v "table inet $acl_table" | awk '{for (i = 1; i <= NF; i++) if ($i == "policy") print $(i + 1)}' | sort -u)
    [[ $hook == *drop* ]] && {
        [[ $assume_yes ]] && {
            warn "存在 policy drop 的 input 链, 白名单客户端可能仍被其他防火墙规则拒绝."
            return 0
        }
        warn "检测到其他防火墙表存在 policy drop 的 input 链."
        msg "本模块的 accept 不是最终裁决, 白名单客户端仍可能被那些规则丢弃."
        err "请先调整或停用该系统防火墙; 了解风险后强制继续: $is_core acl on --yes"
    }
    return 0
}

# 解析出需要保护的端口, 结果放入 acl_ports
acl_collect_ports() {
    acl_ports=()
    acl_ports_skipped=()
    local file type listen port
    for file in "$is_conf_dir"/*.json; do
        [[ -f $file ]] || continue
        type=$(jq -r '.inbounds[0].type // empty' "$file" 2>/dev/null)
        port=$(jq -r '.inbounds[0].listen_port // empty' "$file" 2>/dev/null)
        listen=$(jq -r '.inbounds[0].listen // empty' "$file" 2>/dev/null)
        [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || continue
        case $type in
        tun | redirect | tproxy) continue ;;
        esac
        if [[ $listen == 127.* || $listen == localhost || $listen == ::1 ]]; then
            # 这类入站只接受本机(通常是 Caddy)连接, 在它上面套来源白名单是无效且有害的.
            acl_ports_skipped+=("$port")
            continue
        fi
        acl_ports+=("$port")
    done
    # Caddy 前置的配置由 Caddy 监听公开端口, 保护这些端口才有意义.
    # HTTP 端口必须保持开放, 否则 Let's Encrypt 的 HTTP-01 校验无法完成, 证书续签会失败.
    if [[ $is_caddy && $is_https_port ]]; then
        acl_ports+=("$is_https_port")
    fi
    [[ ${#acl_ports[@]} -eq 0 ]] || IFS=$'\n' readarray -t acl_ports <<<"$(printf '%s\n' "${acl_ports[@]}" | sort -n -u)"
    [[ ${#acl_ports_skipped[@]} -eq 0 ]] || IFS=$'\n' readarray -t acl_ports_skipped <<<"$(printf '%s\n' "${acl_ports_skipped[@]}" | sort -n -u)"
    return 0
}

acl_ports_ok() {
    [[ ${#acl_ports[@]} -gt 0 ]] || err "没有找到需要保护的监听端口; 请先添加至少一个配置: $is_core add"
    [[ ${#acl_allow[@]} -gt 0 ]] || err "白名单为空, 请先添加 allow 条目: $is_core acl add <ip | cidr>"
}

acl_print_ports() {
    msg "保护端口: $(_green "${acl_ports[*]}") (TCP + UDP)"
    [[ ${#acl_ports_skipped[@]} -gt 0 ]] && {
        msg "跳过端口: ${acl_ports_skipped[*]} (监听在回环地址, 由 Caddy 前置)"
        [[ $is_caddy && $is_https_port ]] && msg "已包含 Caddy HTTPS 端口: $(_green "$is_https_port")"
        msg "\e[41m注意\e[0m: 80 端口保持对全网开放, 否则 ACME 的 HTTP-01 校验会失败, 证书无法续签."
    }
}

acl_join_ports() {
    local IFS=,
    echo "$*"
}

# 生成 nftables 规则文件内容
acl_render_nft() {
    local cidr family allow4 allow6 ports
    ports=$(acl_join_ports "${acl_ports[@]}")
    for cidr in "${acl_allow[@]}"; do
        family=$(acl_addr_family "$cidr")
        case $family in
        ipv4) allow4+=("$cidr") ;;
        ipv6) allow6+=("$cidr") ;;
        esac
    done
    {
        echo "# generated by $is_core acl"
        echo "table inet $acl_table {"
        echo "    chain input {"
        echo "        type filter hook input priority filter; policy accept;"
        echo "        ct state established,related accept"
        echo "        iifname \"lo\" accept"
        echo "        tcp dport { $ports } ip saddr { ${allow4[*]} } accept"
        echo "        tcp dport { $ports } ip6 saddr { ${allow6[*]} } accept"
        echo "        udp dport { $ports } ip saddr { ${allow4[*]} } accept"
        echo "        udp dport { $ports } ip6 saddr { ${allow6[*]} } accept"
        echo "        tcp dport { $ports } drop"
        echo "        udp dport { $ports } drop"
        echo "    }"
        echo "}"
    }
}

# 生成 iptables/ip6tables 规则文件内容 (单栈, 由 ipver 决定)
acl_render_iptables() {
    local ipver=$1 cidr family ports entry
    ports=$(acl_join_ports "${acl_ports[@]}" | tr ' ' '\n')
    {
        echo "*filter"
        echo ":$acl_chain - [0:0]"
        echo "-A $acl_chain -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo "-A $acl_chain -i lo -j ACCEPT"
        for cidr in "${acl_allow[@]}"; do
            family=$(acl_addr_family "$cidr")
            [[ $ipver == 4 && $family != ipv4 ]] && continue
            [[ $ipver == 6 && $family != ipv6 ]] && continue
            # iptables 的 -s a,b 会展开成多条规则, 这里每条 CIDR 单独一行; multiport 上限 15 个端口.
            for entry in $(printf '%s\n' $ports | xargs -n15); do
                echo "-A $acl_chain -s $cidr -p tcp -m multiport --dports $entry -j ACCEPT"
                echo "-A $acl_chain -s $cidr -p udp -m multiport --dports $entry -j ACCEPT"
            done
        done
        for entry in $(printf '%s\n' $ports | xargs -n15); do
            echo "-A $acl_chain -p tcp -m multiport --dports $entry -j DROP"
            echo "-A $acl_chain -p udp -m multiport --dports $entry -j DROP"
        done
        echo "-A $acl_chain -j RETURN"
        echo "COMMIT"
    }
}

acl_write_rules() {
    local content=$1 tmp
    tmp=$(mktemp "$acl_state_dir/.rules.XXXXXX") || return 1
    printf '%s\n' "$content" >"$tmp" || {
        rm -f "$tmp"
        return 1
    }
    chmod 600 "$tmp" && mv -f "$tmp" "$acl_rules"
}

acl_nft_apply() {
    local content
    content=$(acl_render_nft) || return 1
    # 先做语法校验, 避免把半成品规则送进内核.
    printf '%s\n' "$content" | nft -c -f - &>/dev/null || {
        err "生成的 nftables 规则未通过语法校验, 未改动防火墙."
        return 1
    }
    acl_write_rules "$content" || return 1
    # 独立表整体重建: 不存在则新增, 存在则删除后重建, 单次事务原子生效.
    {
        nft list table inet "$acl_table" &>/dev/null && echo "delete table inet $acl_table"
        cat "$acl_rules"
    } | nft -f - || {
        err "写入 nftables 规则失败, 请检查 nft 是否可用."
        return 1
    }
}

acl_nft_remove() {
    nft list table inet "$acl_table" &>/dev/null || return 0
    nft delete table inet "$acl_table" &>/dev/null || return 0
}

acl_iptables_chain_ok() {
    local exit_code
    "$1" -w -C $acl_chain -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT &>/dev/null
    exit_code=$?
    # 退出码 1 表示链不存在; 2 表示参数错误, 必须中止而不是当作"不存在".
    [[ $exit_code == 0 || $exit_code == 1 ]] || err "$1 无法检查规则链 (退出码 $exit_code), 未改动防火墙."
}

acl_iptables_apply() {
    local ipver=$1 content tmp
    content=$(acl_render_iptables "$ipver") || return 1
    tmp=$(mktemp "$acl_state_dir/.iptables.XXXXXX") || return 1
    printf '%s\n' "$content" >"$tmp" || {
        rm -f "$tmp"
        return 1
    }
    if [[ $ipver == 4 ]]; then
        iptables -w -N $acl_chain &>/dev/null
        acl_iptables_chain_ok iptables
        # -n 只重建声明的链, 不动 INPUT 和其他链, 且是单次事务.
        iptables-restore -w -n <"$tmp" || {
            rm -f "$tmp"
            err "写入 iptables 规则失败."
            return 1
        }
        acl_iptables_jump iptables
    else
        ip6tables -w -N $acl_chain &>/dev/null
        acl_iptables_chain_ok ip6tables
        ip6tables-restore -w -n <"$tmp" || {
            rm -f "$tmp"
            err "写入 ip6tables 规则失败."
            return 1
        }
        acl_iptables_jump ip6tables
    fi
    rm -f "$tmp"
}

acl_iptables_jump() {
    local tool=$1
    # 清掉历史跳转(可能是重复写入), 再插到 INPUT 首位.
    while "$tool" -w -S INPUT 2>/dev/null | grep -q -- "-j $acl_chain"; do
        "$tool" -w -D INPUT -j $acl_chain &>/dev/null || break
    done
    "$tool" -w -I INPUT 1 -m comment --comment "$acl_comment" -j $acl_chain || err "无法把 $acl_chain 插入 INPUT 链."
}

acl_iptables_remove() {
    local tool
    for tool in iptables ip6tables; do
        type -P "$tool" &>/dev/null || continue
        while "$tool" -w -S INPUT 2>/dev/null | grep -q -- "-j $acl_chain"; do
            "$tool" -w -D INPUT -j $acl_chain &>/dev/null || break
        done
        # 必须显式指定链名: 不带参数的 -F/-X 会清空整个表/删除所有自定义链.
        "$tool" -w -F $acl_chain &>/dev/null
        "$tool" -w -X $acl_chain &>/dev/null
    done
    return 0
}

acl_apply_locked() {
    local backend assume_yes=$1
    acl_state_load
    acl_collect_ports
    acl_ports_ok || return 1
    acl_check_conflicts "$assume_yes" || return 1
    backend=$(acl_backend_detect)
    [[ $backend == none ]] && err "未检测到 nft 或 iptables, 无法写入防火墙规则."
    acl_print_ports
    if [[ $backend == nft ]]; then
        acl_nft_apply || return 1
    else
        acl_iptables_apply 4 || return 1
        acl_iptables_apply 6 || return 1
    fi
    printf '%s\n' "$(date +%s) ${acl_ports[*]}" >"$acl_state_dir/applied.tmp" && mv -f "$acl_state_dir/applied.tmp" "$acl_state_dir/applied"
    chmod 600 "$acl_state_dir/applied" 2>/dev/null
    _green "\n白名单规则已生效: ${#acl_allow[@]} 条来源, 端口 ${acl_ports[*]}\n"
}

acl_apply() {
    local assume_yes=$1 result
    acl_require_root
    mkdir -p "$acl_state_dir" && chmod 700 "$acl_state_dir" || return 1
    # 串行化应用过程, 避免开机单元与手动 sync 并发写入.
    while ! mkdir "$acl_state_dir/.lock" &>/dev/null; do
        [[ -f $acl_state_dir/.lock/pid ]] && [[ ! -d /proc/$(cat "$acl_state_dir/.lock/pid" 2>/dev/null) ]] && {
            rm -rf "$acl_state_dir/.lock"
            continue
        }
        sleep 1
    done
    echo $$ >"$acl_state_dir/.lock/pid"
    # 子 shell 中执行, 保证任何提前退出都会释放锁
    (acl_apply_locked "$assume_yes")
    result=$?
    rm -rf "$acl_state_dir/.lock"
    return $result
}

acl_remove() {
    local backend
    acl_require_root
    acl_backend=$(jq -r '.backend // "auto"' "$acl_state" 2>/dev/null)
    [[ $acl_backend ]] || acl_backend=auto
    backend=$(acl_backend_detect)
    if [[ $backend == nft ]]; then
        acl_nft_remove
    fi
    type -P iptables &>/dev/null && acl_iptables_remove
    rm -f "$acl_state_dir/applied"
    return 0
}

acl_applied_ports() {
    [[ -f $acl_state_dir/applied ]] && cut -d' ' -f2- "$acl_state_dir/applied"
}

acl_service_install() {
    if [[ $is_systemd ]]; then
        cat >/lib/systemd/system/$acl_service.service <<EOF
[Unit]
Description=$is_core_name source IP allowlist
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target sing-box.service
Wants=network-pre.target
PartOf=sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $is_sh_dir/src/acl.sh apply
ExecReload=/bin/bash $is_sh_dir/src/acl.sh apply

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload &>/dev/null
    elif [[ $is_openrc ]]; then
        cat >/etc/init.d/$acl_service <<EOF
#!/sbin/openrc-run

name="$is_core_name source IP allowlist"
description="$is_core_name source IP allowlist"

start() {
    ebegin "Applying $is_core_name allowlist"
    /bin/bash $is_sh_dir/src/acl.sh apply
    eend \$?
}

stop() {
    ebegin "Removing $is_core_name allowlist"
    /bin/bash $is_sh_dir/src/acl.sh flush
    eend \$?
}

depend() {
    need localmount
    after sysctl
    before net
    provide firewall
}
EOF
        chmod +x /etc/init.d/$acl_service
    fi
}

acl_service_action() {
    local action=$1 quiet=$2 result
    if [[ $is_systemd ]]; then
        systemctl "$action" "$acl_service" &>/dev/null
    elif [[ $is_openrc ]]; then
        case $action in
        enable) rc-update add "$acl_service" default &>/dev/null ;;
        disable) rc-update del "$acl_service" default &>/dev/null ;;
        *) rc-service "$acl_service" "$action" &>/dev/null ;;
        esac
    else
        return 1
    fi
    result=$?
    [[ $quiet ]] && return $result
    return $result
}

acl_service_is_active() {
    if [[ $is_systemd ]]; then
        [[ $(systemctl is-active "$acl_service" 2>/dev/null) == active ]]
    elif [[ $is_openrc ]]; then
        rc-service "$acl_service" status &>/dev/null
    else
        return 1
    fi
}

acl_service_remove() {
    acl_service_action stop quiet
    acl_service_action disable quiet
    if [[ $is_systemd ]]; then
        rm -f /lib/systemd/system/$acl_service.service
        systemctl daemon-reload &>/dev/null
    elif [[ $is_openrc ]]; then
        rm -f /etc/init.d/$acl_service
    fi
}

acl_rollback_file() {
    echo "$acl_state_dir/rollback"
}

acl_rollback_active() {
    [[ -f $(acl_rollback_file) ]]
}

acl_rollback_cancel() {
    rm -f "$(acl_rollback_file)"
}

# 5 分钟内未确认则自动撤销, 避免把自己锁在服务器外面.
acl_rollback_arm() {
    local file
    file=$(acl_rollback_file)
    mkdir -p "$acl_state_dir" && chmod 700 "$acl_state_dir" || return 1
    printf '%s\n' "$acl_rollback_delay" >"$file" || return 1
    chmod 600 "$file"
    (
        setsid bash -c "
            sleep $acl_rollback_delay
            if [[ -f '$file' ]]; then
                bash '$is_sh_dir/src/acl.sh' flush &>/dev/null
                rm -f '$file'
            fi
        " &>/dev/null &
    ) &>/dev/null
}

acl_sync_bg() {
    [[ -f $acl_state ]] || return 0
    [[ $(jq -r '.enabled // false' "$acl_state" 2>/dev/null) == true ]] || return 0
    # 直接以 standalone 方式运行, 避免后台子 shell 再次走主入口.
    bash "$is_sh_dir/src/acl.sh" apply &>/dev/null &
}

acl_usage() {
    msg "\n来源 IP 白名单:"
    msg "   $is_core acl on [--yes]               启用白名单 (使用当前 allow 列表)"
    msg "   $is_core acl off                      关闭白名单并移除规则"
    msg "   $is_core acl add <ip | cidr>          添加允许的来源"
    msg "   $is_core acl del <ip | cidr>          移除来源"
    msg "   $is_core acl list                     查看 allow 列表"
    msg "   $is_core acl clear                    清空 allow 列表"
    msg "   $is_core acl status                   查看状态、后端与保护端口"
    msg "   $is_core acl sync                     按当前配置重新生成并应用规则"
    msg "   $is_core acl confirm                  取消启用时的自动回滚"
    msg "   $is_core acl backend <auto | nft | iptables-legacy>  指定防火墙后端\n"
    msg "\e[41m注意\e[0m: 白名单只放行列表中的来源; 使用 Caddy 自动 TLS 时 80 端口保持开放,"
    msg "否则 ACME 的 HTTP-01 校验会失败, 证书无法续签."
    msg "启用后如无法连接服务器, 5 分钟内未执行 $(_green "$is_core acl confirm") 会自动回滚.\n"
}

acl_status_show() {
    local backend frontend state ports applied
    acl_state_load
    acl_collect_ports
    backend=$(acl_backend_detect)
    acl_frontend_detect
    frontend=${acl_frontend:-无}
    if [[ $acl_enabled == true ]]; then
        state=$(_green 已启用)
    else
        state=$(_red_bg 未启用)
    fi
    msg "\n来源 IP 白名单: $state"
    msg "防火墙后端: $(acl_backend_label "$backend")"
    [[ $acl_frontend ]] && msg "系统防火墙: $(_yellow "$acl_frontend") (本模块规则可能被其重载清除)"
    if [[ ${#acl_allow[@]} -gt 0 ]]; then
        msg "允许来源: ${acl_allow[*]}"
    else
        msg "允许来源: $(_red 空) (启用前请先 $is_core acl add <ip>)"
    fi
    ports=${acl_ports[*]}
    [[ $ports ]] && msg "保护端口: $ports (TCP + UDP)"
    [[ ${#acl_ports_skipped[@]} -gt 0 ]] && msg "跳过端口: ${acl_ports_skipped[*]} (监听在回环地址)"
    applied=$(acl_applied_ports)
    [[ $applied ]] && msg "最近应用: $applied"
    if [[ $is_systemd || $is_openrc ]]; then
        if acl_service_is_active; then
            msg "开机服务: $(_green "已启用 ($acl_service)")"
        else
            msg "开机服务: $(_red "未启用 ($acl_service)")"
        fi
    fi
    acl_rollback_active && warn "存在待确认的自动回滚, 请在 $acl_rollback_delay 秒内执行: $is_core acl confirm"
    if [[ $is_caddy ]]; then
        msg "\nCaddy 前置的配置只能按端口保护, 无法按域名区分; 80 端口保持开放以完成 ACME 校验."
    fi
    msg ""
}

acl_enable() {
    local assume_yes=$1 was_enabled=$acl_enabled
    acl_require_root
    acl_state_load
    was_enabled=$acl_enabled
    [[ ${#acl_allow[@]} -gt 0 ]] || err "白名单为空, 请先添加: $is_core acl add <ip | cidr>"
    acl_enabled=true
    acl_state_save || err "保存白名单状态失败."
    # acl_apply 内部会做冲突检查, 规则写入成功后才注册开机服务, 避免留下开着规则的空服务.
    if ! acl_apply "$assume_yes"; then
        acl_enabled=$was_enabled
        acl_state_save
        err "规则应用失败, 白名单未启用."
    fi
    acl_service_install
    acl_service_action enable quiet
    acl_rollback_arm
    _green "\n白名单已启用."
    msg "请确认代理客户端仍然可以连接."
    msg "确认无误后执行: $(_green "$is_core acl confirm") 取消自动回滚."
    msg "如已无法连接服务器, 无需操作; $acl_rollback_delay 秒后会自动回滚.\n"
}

acl_disable() {
    acl_require_root
    acl_state_load
    acl_rollback_cancel
    acl_enabled=false
    acl_state_save || err "保存白名单状态失败."
    acl_service_action stop quiet
    acl_service_action disable quiet
    acl_remove
    _green "\n白名单已关闭, 防火墙规则已移除.\n"
    msg "配置仍然保留, 重新启用: $is_core acl on\n"
}

acl_sync() {
    local assume_yes=$1
    acl_require_root
    acl_state_load
    [[ $acl_enabled == true ]] || err "白名单尚未启用, 请先执行: $is_core acl on"
    acl_apply "$assume_yes" || return 1
    acl_service_action restart quiet
    acl_rollback_arm
    msg "确认无误后执行: $(_green "$is_core acl confirm") 取消自动回滚."
}

acl_confirm() {
    acl_require_root
    acl_rollback_active || {
        msg "\n没有待确认的自动回滚.\n"
        return
    }
    acl_rollback_cancel
    _green "\n已确认, 白名单保持启用.\n"
}

acl_clear() {
    acl_state_load
    acl_allow=()
    acl_state_save || err "保存白名单状态失败."
    if [[ $acl_enabled == true ]]; then
        warn "白名单仍处于启用状态, 但没有允许来源."
        msg "如需继续使用, 请执行: $is_core acl add <ip> && $is_core acl sync"
    fi
    _green "\n已清空白名单.\n"
}

acl_backend_set() {
    local value=$1
    case $value in
    auto | nft | iptables-legacy) ;;
    *)
        err "后端仅支持 auto | nft | iptables-legacy"
        ;;
    esac
    acl_state_load
    acl_backend=$value
    local backend
    backend=$(acl_backend_detect)
    [[ $backend == none && $value != auto ]] && err "找不到指定的后端: $value"
    acl_state_save || err "保存白名单状态失败."
    _green "\n防火墙后端已设置为: $value\n"
    msg "重新应用规则: $is_core acl sync\n"
}

acl_uninstall() {
    local parent=$1
    acl_state_load
    acl_rollback_cancel
    acl_service_remove
    acl_remove
    rm -rf "$acl_state_dir"
    [[ ! $parent ]] && {
        _green "\n白名单已卸载, 配置和规则均已移除.\n"
    }
    return 0
}

# standalone 入口: systemd/OpenRC 在开机时直接调用本脚本
if [[ ! $is_core ]]; then
    err() {
        echo -e "\e[41m错误!\e[0m $@" >&2
        exit 1
    }
    warn() {
        echo -e "\e[41m警告!\e[0m $@" >&2
    }
    _green() {
        echo -e "\e[92m$@\e[0m"
    }
    _yellow() {
        echo -e "\e[33m$@\e[0m"
    }
    _red() {
        echo -e "\e[31m$@\e[0m"
    }
    _red_bg() {
        echo -e "\e[41m$@\e[0m"
    }
    msg() {
        echo -e "$@"
    }
    acl_self_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    is_core_dir=/etc/sing-box
    is_core=sing-box
    is_core_name=sing-box
    is_conf_dir=$is_core_dir/conf
    is_sh_dir=$is_core_dir/sh
    is_systemd=$(type -P systemctl)
    is_openrc=$(type -P rc-service)
    [[ $acl_self_dir != "$is_sh_dir/src" ]] && is_sh_dir=${acl_self_dir%/src}
    case ${1,,} in
    apply)
        acl_apply
        ;;
    flush | remove)
        acl_remove
        ;;
    *)
        err "用法: $0 [apply | flush]"
        ;;
    esac
    exit 0
fi

_acl_main() {
    local action=$1
    shift 2>/dev/null
    acl_state_load
    case ${action,,} in
    add)
        acl_require_root
        acl_add_entry "$1"
        acl_state_save || err "保存白名单状态失败."
        [[ $acl_enabled == true ]] && acl_sync_bg
        ;;
    del | remove)
        acl_require_root
        acl_del_entry "$1"
        acl_state_save || err "保存白名单状态失败."
        [[ $acl_enabled == true ]] && acl_sync_bg
        ;;
    list | ls)
        if [[ ${#acl_allow[@]} -gt 0 ]]; then
            msg "\n白名单 ($(_green "${#acl_allow[@]}") 条):"
            for acl_tmp_entry in "${acl_allow[@]}"; do
                msg "   $acl_tmp_entry"
            done
            msg ""
        else
            msg "\n白名单为空, 添加: $is_core acl add <ip | cidr>\n"
        fi
        unset acl_tmp_entry
        ;;
    clear)
        acl_require_root
        acl_clear
        ;;
    on | enable)
        [[ $1 == --yes ]] && acl_enable 1 || acl_enable
        ;;
    off | disable)
        acl_disable
        ;;
    sync)
        [[ $1 == --yes ]] && acl_sync 1 || acl_sync
        ;;
    confirm)
        acl_confirm
        ;;
    status | s)
        acl_status_show
        ;;
    backend)
        acl_require_root
        acl_backend_set "$1"
        ;;
    uninstall | remove-all)
        acl_require_root
        acl_uninstall
        ;;
    h | help | --help | '')
        acl_usage
        ;;
    *)
        err "无法识别 acl 参数 ($action), 请使用: $is_core acl help"
        ;;
    esac
}
