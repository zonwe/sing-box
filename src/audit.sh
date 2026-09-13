#!/bin/bash

audit_usage() {
    msg "\n流量审计:"
    msg "   $is_core audit enable [listen] [port]          启用审计或更新监听 (默认 127.0.0.1:9091)"
    msg "   $is_core audit status                          查看服务与采集状态"
    msg "   $is_core audit url                             显示前端访问地址"
    msg "   $is_core audit token                           显示前端访问令牌"
    msg "   $is_core audit start|stop|restart              管理审计服务"
    msg "   $is_core audit set <option> <value>             修改 listen/port/retention/interval/token"
    msg "   $is_core audit export [csv|json] [range] [file] 导出数据 (range: 1h/6h/24h/7d/30d/all)"
    msg "   $is_core audit report [csv|json] [range] [file] 按 IP/配置汇总并导出用量"
    msg "   $is_core audit config-report [csv|json] [range] [file] 按配置文件汇总并导出用量"
    msg "   $is_core audit purge <days>                    删除指定天数以前的数据"
    msg "   $is_core audit disable                         停止并禁用服务, 保留配置和数据"
    msg "   $is_core audit uninstall [-y]                  卸载审计服务并删除全部审计数据\n"
}

audit_require_root() {
    [[ $EUID != 0 ]] && err "此操作需要 root 权限."
}

audit_random_token() {
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

audit_config_get() {
    jq -r "$1 // empty" "$is_audit_config" 2>/dev/null
}

audit_validate_port() {
    [[ $(is_test port "$1") ]] || err "端口必须在 1 到 65535 之间."
}

audit_validate_listen() {
    [[ $1 == localhost ]] && return
    [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || err "监听地址仅支持 IPv4 或 localhost: $1"
    local octet
    local old_ifs=$IFS
    IFS=.
    for octet in $1; do
        ((10#$octet <= 255)) || {
            IFS=$old_ifs
            err "监听地址格式无效: $1"
        }
    done
    IFS=$old_ifs
}

audit_install_python() {
    if type -P python3 &>/dev/null && python3 -c 'import sqlite3' &>/dev/null; then
        return
    fi
    msg "\n正在安装流量审计依赖: python3"
    case $cmd in
    *apk)
        apk update &>/dev/null
        apk add python3 &>/dev/null
        ;;
    *zypper)
        zypper --non-interactive refresh &>/dev/null
        zypper --non-interactive install python3 &>/dev/null
        ;;
    *yum)
        yum install -y python3 &>/dev/null || {
            yum install -y epel-release &>/dev/null
            yum install -y python3 &>/dev/null
        }
        ;;
    *apt-get)
        apt-get update &>/dev/null
        apt-get install -y python3 &>/dev/null
        ;;
    *)
        err "无法识别包管理器, 请手动安装 python3 (需包含 sqlite3 模块)."
        ;;
    esac
    if ! type -P python3 &>/dev/null || ! python3 -c 'import sqlite3' &>/dev/null; then
        err "安装 python3 失败, 请手动安装后重试."
    fi
}

audit_service_action() {
    local action=$1
    local quiet=$2
    if [[ $is_systemd ]]; then
        systemctl "$action" "$is_audit_name" 2>/dev/null
    elif [[ $is_openrc ]]; then
        case $action in
        enable)
            rc-update add "$is_audit_name" default 2>/dev/null
            ;;
        disable)
            rc-update del "$is_audit_name" default 2>/dev/null
            ;;
        *)
            rc-service "$is_audit_name" "$action" 2>/dev/null
            ;;
        esac
    fi
    local result=$?
    [[ $quiet ]] && return $result
    if [[ $result == 0 ]]; then
        _green "\n审计服务已${action}.\n"
    else
        err "审计服务执行 $action 失败, 请使用 $is_core audit status 查看状态."
    fi
}

audit_controller_url() {
    local controller=$1
    controller=${controller#http://}
    controller=${controller#https://}
    case $controller in
    0.0.0.0:*)
        controller=127.0.0.1:${controller##*:}
        ;;
    :*)
        controller=127.0.0.1$controller
        ;;
    esac
    msg "http://$controller"
}

audit_enable() {
    audit_require_root
    local requested_listen=$1
    local requested_port=$2
    local listen=${requested_listen:-127.0.0.1}
    local port=${requested_port:-9091}
    local controller controller_secret collector_url web_token managed_clash_api=false
    local config_tmp config_backup config_changed core_backup core_changed current_listen current_port

    if [[ -f $is_audit_config ]]; then
        current_listen=$(audit_config_get '.listen')
        current_port=$(audit_config_get '.port')
        [[ ! $requested_listen ]] && listen=$current_listen
        [[ ! $requested_port ]] && port=$current_port
    fi

    audit_validate_listen "$listen"
    audit_validate_port "$port"
    audit_install_python
    [[ -f $is_audit_server ]] || err "找不到审计服务程序: $is_audit_server"

    if [[ -f $is_audit_config ]]; then
        msg "\n检测到已有审计配置, 将重新安装并启动服务."
        if [[ $requested_listen || $requested_port ]]; then
            if [[ $port != "$current_port" && $(is_test port_used "$port") ]]; then
                err "前端端口 ($port) 已被占用, 请指定其他端口: $is_core audit enable $listen <port>"
            fi
            config_backup=$(mktemp)
            config_tmp=$(mktemp)
            cp -f "$is_audit_config" "$config_backup"
            if ! jq --arg listen "$listen" --argjson port "$port" \
                '.listen = $listen | .port = $port' "$is_audit_config" >"$config_tmp"; then
                rm -f "$config_tmp" "$config_backup"
                err "更新审计监听配置失败."
            fi
            mv -f "$config_tmp" "$is_audit_config"
            chmod 600 "$is_audit_config"
            if ! python3 "$is_audit_server" --config "$is_audit_config" --check &>/dev/null; then
                mv -f "$config_backup" "$is_audit_config"
                err "新配置验证失败, 已恢复原配置."
            fi
            config_changed=1
        fi
        load systemd.sh
        install_service "$is_audit_name" &>/dev/null
        audit_service_action enable quiet
        if ! audit_service_action restart quiet && ! audit_service_action start quiet; then
            if [[ $config_changed ]]; then
                mv -f "$config_backup" "$is_audit_config"
                audit_service_action restart quiet
                err "审计服务无法使用新监听配置启动, 已恢复原配置."
            fi
            err "审计服务启动失败, 请运行: $is_core audit status"
        fi
        sleep 1
        if [[ ! $(pgrep -f "$is_audit_server --config $is_audit_config") ]]; then
            if [[ $config_changed ]]; then
                mv -f "$config_backup" "$is_audit_config"
                audit_service_action restart quiet
                err "审计服务无法使用新监听配置启动, 已恢复原配置."
            fi
            err "审计服务启动失败, 请运行: $is_core audit status"
        fi
        [[ $config_changed ]] && {
            rm -f "$config_backup"
            _green "\n审计监听已更新: $listen:$port\n"
        }
        audit_status
        return
    fi

    if [[ $(is_test port_used "$port") ]]; then
        err "前端端口 ($port) 已被占用, 请指定其他端口: $is_core audit enable $listen <port>"
    fi

    controller=$(jq -r '.experimental.clash_api.external_controller // empty' "$is_config_json")
    controller_secret=$(jq -r '.experimental.clash_api.secret // empty' "$is_config_json")
    if [[ ! $controller ]]; then
        controller=127.0.0.1:9090
        if [[ $(is_test port_used 9090) ]]; then
            get_port
            controller=127.0.0.1:$tmp_port
        fi
        controller_secret=$(audit_random_token)
        [[ $controller_secret ]] || err "生成 sing-box API 令牌失败."
        core_backup=$(mktemp)
        cp -f "$is_config_json" "$core_backup"
        config_tmp=$(mktemp)
        jq --arg controller "$controller" --arg secret "$controller_secret" '
            .experimental = (.experimental // {}) |
            .experimental.clash_api = ((.experimental.clash_api // {}) + {
                external_controller: $controller,
                secret: $secret
            })
        ' "$is_config_json" >"$config_tmp" || {
            rm -f "$config_tmp" "$core_backup"
            err "更新 sing-box 管理 API 配置失败."
        }
        mv -f "$config_tmp" "$is_config_json"
        if ! "$is_core_bin" check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
            mv -f "$core_backup" "$is_config_json"
            err "sing-box 不接受 Clash API 配置; 当前核心可能未包含 with_clash_api 支持."
        fi
        rm -f "$core_backup"
        managed_clash_api=true
        core_changed=1
    elif [[ $controller == 0.0.0.0:* && ! $controller_secret ]]; then
        warn "现有 sing-box 管理 API 暴露在 0.0.0.0 且未设置 secret; 请尽快加固该配置."
    fi

    collector_url=$(audit_controller_url "$controller")
    web_token=$(audit_random_token)
    [[ $web_token ]] || err "生成前端访问令牌失败."
    mkdir -p "$is_audit_dir" "$is_audit_data_dir"
    chmod 750 "$is_audit_dir" "$is_audit_data_dir"
    config_tmp=$(mktemp)
    jq -n \
        --arg listen "$listen" \
        --argjson port "$port" \
        --arg database "$is_audit_database" \
        --arg config_dir "$is_conf_dir" \
        --arg collector_url "$collector_url" \
        --arg collector_secret "$controller_secret" \
        --arg web_token "$web_token" \
        --arg managed_controller "$controller" \
        --argjson managed_clash_api "$managed_clash_api" \
        '{
            version: 1,
            listen: $listen,
            port: $port,
            database: $database,
            config_dir: $config_dir,
            collector_url: $collector_url,
            collector_secret: $collector_secret,
            web_token: $web_token,
            poll_interval: 1,
            retention_days: 90,
            managed_clash_api: $managed_clash_api,
            managed_controller: $managed_controller
        }' >"$config_tmp" || err "生成审计配置失败."
    mv -f "$config_tmp" "$is_audit_config"
    chmod 600 "$is_audit_config"

    if ! python3 "$is_audit_server" --config "$is_audit_config" --check &>/dev/null; then
        err "审计服务配置验证失败."
    fi

    load systemd.sh
    install_service "$is_audit_name" &>/dev/null
    [[ $core_changed ]] && manage restart &>/dev/null
    audit_service_action restart quiet || audit_service_action start quiet
    sleep 1
    [[ $(pgrep -f "$is_audit_server --config $is_audit_config") ]] || err "审计服务启动失败, 请运行: $is_core audit status"
    _green "\n流量审计已启用."
    audit_url
    msg "访问令牌: $(_yellow "$web_token")"
    [[ $listen == 127.0.0.1 || $listen == localhost ]] && msg "远程访问建议使用 SSH 端口转发, 不要直接暴露无 TLS 的页面."
    msg
}

audit_url() {
    [[ -f $is_audit_config ]] || err "流量审计尚未启用, 请先运行: $is_core audit enable"
    local listen port show_host
    listen=$(audit_config_get '.listen')
    port=$(audit_config_get '.port')
    show_host=$listen
    [[ $listen == 0.0.0.0 ]] && show_host=服务器IP
    msg "\n审计页面: $(_green "http://$show_host:$port/")\n"
}

audit_token() {
    [[ -f $is_audit_config ]] || err "流量审计尚未启用."
    msg "\n审计访问令牌: $(_yellow "$(audit_config_get '.web_token')")\n"
}

audit_status() {
    if [[ ! -f $is_audit_config ]]; then
        msg "\n流量审计: $(_red_bg 未启用)"
        msg "启用命令: $is_core audit enable\n"
        return
    fi
    local service_status health health_host listen port summary token
    if [[ $is_systemd ]]; then
        service_status=$(systemctl is-active "$is_audit_name" 2>/dev/null)
    elif [[ $is_openrc ]]; then
        service_status=$(rc-service "$is_audit_name" status 2>/dev/null | grep -qi started && echo active)
    fi
    listen=$(audit_config_get '.listen')
    port=$(audit_config_get '.port')
    health_host=$listen
    [[ $listen == 0.0.0.0 ]] && health_host=127.0.0.1
    if [[ $service_status == active ]]; then
        service_status=$(_green running)
    else
        service_status=$(_red_bg stopped)
    fi
    health=$(_wget -qO- -T 2 "http://$health_host:$port/api/health" 2>/dev/null)
    token=$(audit_config_get '.web_token')
    summary=$(_wget -qO- -T 2 --header="Authorization: Bearer $token" "http://$health_host:$port/api/summary?range=24h" 2>/dev/null)
    msg "\n流量审计: $service_status"
    msg "监听地址: $listen:$port"
    msg "数据保留: $(audit_config_get '.retention_days') 天"
    if [[ $(jq -r '.ok // false' <<<"$health" 2>/dev/null) == true ]]; then
        msg "前端服务: $(_green 可访问)"
    else
        msg "前端服务: $(_red 不可访问)"
    fi
    if [[ $(jq -r '.collector.connected // false' <<<"$summary" 2>/dev/null) == true ]]; then
        msg "数据采集: $(_green 正常)"
    else
        msg "数据采集: $(_red 异常)"
        [[ $summary ]] && msg "采集错误: $(jq -r '.collector.last_error // "未知错误"' <<<"$summary")"
    fi
    audit_url
}

audit_set() {
    audit_require_root
    [[ -f $is_audit_config ]] || err "流量审计尚未启用."
    local option=$1 value=$2 config_tmp config_backup current_port
    [[ $option && $value ]] || err "正确使用: $is_core audit set <listen|port|retention|interval|token> <value>"
    config_tmp=$(mktemp)
    config_backup=$(mktemp)
    cp -f "$is_audit_config" "$config_backup"
    case $option in
    listen)
        audit_validate_listen "$value"
        jq --arg value "$value" '.listen = $value' "$is_audit_config" >"$config_tmp"
        ;;
    port)
        audit_validate_port "$value"
        current_port=$(audit_config_get '.port')
        if [[ $value != "$current_port" && $(is_test port_used "$value") ]]; then
            rm -f "$config_tmp" "$config_backup"
            err "端口 ($value) 已被占用."
        fi
        jq --argjson value "$value" '.port = $value' "$is_audit_config" >"$config_tmp"
        ;;
    retention)
        [[ $value =~ ^[0-9]+$ && $value -ge 1 && $value -le 3650 ]] || err "retention 必须为 1 到 3650 天."
        jq --argjson value "$value" '.retention_days = $value' "$is_audit_config" >"$config_tmp"
        ;;
    interval)
        [[ $value =~ ^[0-9]+$ && $value -ge 1 && $value -le 60 ]] || err "interval 必须为 1 到 60 秒."
        jq --argjson value "$value" '.poll_interval = $value' "$is_audit_config" >"$config_tmp"
        ;;
    token)
        [[ $value == reset ]] && value=$(audit_random_token)
        [[ ${#value} -ge 16 ]] || err "访问令牌至少需要 16 个字符, 或使用 reset 自动生成."
        jq --arg value "$value" '.web_token = $value' "$is_audit_config" >"$config_tmp"
        ;;
    *)
        rm -f "$config_tmp"
        err "无法识别配置项 ($option)."
        ;;
    esac
    [[ -s $config_tmp ]] || err "写入审计配置失败."
    mv -f "$config_tmp" "$is_audit_config"
    chmod 600 "$is_audit_config"
    if ! python3 "$is_audit_server" --config "$is_audit_config" --check &>/dev/null; then
        mv -f "$config_backup" "$is_audit_config"
        err "新配置验证失败."
    fi
    if ! audit_service_action restart quiet; then
        mv -f "$config_backup" "$is_audit_config"
        audit_service_action restart quiet
        err "审计服务无法使用新配置启动, 已恢复原配置."
    fi
    rm -f "$config_backup"
    _green "\n审计配置已更新: $option\n"
}

audit_export() {
    [[ -f $is_audit_config ]] || err "流量审计尚未启用."
    local format=${1:-csv}
    local range=${2:-24h}
    local output=$3
    local view=$4
    local listen port token url output_tmp endpoint=export name_part=connections
    case $view in
    usage)
        endpoint=usage-export
        name_part=usage
        ;;
    config)
        endpoint=config-usage-export
        name_part=config-usage
        ;;
    esac
    [[ $format == csv || $format == json ]] || err "导出格式仅支持 csv 或 json."
    [[ $range =~ ^(1h|6h|24h|7d|30d|all)$ ]] || err "时间范围仅支持 1h/6h/24h/7d/30d/all."
    [[ ! $output ]] && output="$PWD/sing-box-audit-$name_part-$(date +%Y%m%d-%H%M%S).$format"
    port=$(audit_config_get '.port')
    listen=$(audit_config_get '.listen')
    [[ $listen == 0.0.0.0 ]] && listen=127.0.0.1
    token=$(audit_config_get '.web_token')
    url="http://$listen:$port/api/$endpoint?format=$format&range=$range"
    [[ ! -d $output ]] || { err "导出路径不能是目录: $output"; return 1; }
    output_tmp=$(mktemp "${output}.tmp.XXXXXX") || { err "无法创建导出临时文件."; return 1; }
    if ! _wget -q --header="Authorization: Bearer $token" -O "$output_tmp" "$url"; then
        rm -f -- "$output_tmp"
        err "导出失败, 请确认审计服务正在运行."
        return 1
    fi
    if ! mv -f -- "$output_tmp" "$output"; then
        rm -f -- "$output_tmp"
        err "保存导出文件失败, 已保留原文件."
        return 1
    fi
    _green "\n审计数据已导出: $output\n"
}

audit_purge() {
    audit_require_root
    [[ -f $is_audit_config ]] || err "流量审计尚未启用."
    local days=$1
    [[ $days =~ ^[0-9]+$ && $days -ge 1 && $days -le 3650 ]] || err "请指定 1 到 3650 天: $is_core audit purge <days>"
    python3 "$is_audit_server" --config "$is_audit_config" --purge "$days" || err "清理审计数据失败."
    _green "\n已删除 $days 天以前的审计数据.\n"
}

audit_disable() {
    audit_require_root
    [[ -f $is_audit_config ]] || err "流量审计尚未启用."
    audit_service_action stop quiet
    audit_service_action disable quiet
    _green "\n流量审计服务已禁用, 配置和历史数据已保留."
    msg "重新启用: $is_core audit enable\n"
}

audit_remove_service() {
    audit_service_action stop quiet
    audit_service_action disable quiet
    if [[ $is_systemd ]]; then
        rm -f "/lib/systemd/system/$is_audit_name.service"
        systemctl daemon-reload 2>/dev/null
    elif [[ $is_openrc ]]; then
        rm -f "/etc/init.d/$is_audit_name"
    fi
}

audit_uninstall() {
    audit_require_root
    local assume_yes=$1
    local parent_uninstall=$2
    local managed controller managed_secret config_tmp
    [[ -f $is_audit_config ]] || {
        [[ ! $parent_uninstall ]] && msg "\n流量审计尚未启用.\n"
        return
    }
    if [[ $assume_yes != -y && ! $parent_uninstall ]]; then
        echo -ne "是否卸载流量审计并删除全部历史数据? [y]:"
        read -r REPLY
        [[ ${REPLY,,} == y ]] || err "已取消卸载."
    fi
    managed=$(audit_config_get '.managed_clash_api')
    controller=$(audit_config_get '.managed_controller')
    managed_secret=$(audit_config_get '.collector_secret')
    audit_remove_service
    if [[ $managed == true && -f $is_config_json ]]; then
        config_tmp=$(mktemp)
        jq --arg controller "$controller" --arg secret "$managed_secret" '
            if .experimental.clash_api.external_controller == $controller and
               .experimental.clash_api.secret == $secret then
                del(.experimental.clash_api.external_controller, .experimental.clash_api.secret) |
                if .experimental.clash_api == {} then del(.experimental.clash_api) else . end |
                if .experimental == {} then del(.experimental) else . end
            else . end
        ' "$is_config_json" >"$config_tmp" && mv -f "$config_tmp" "$is_config_json"
        [[ ! $parent_uninstall ]] && manage restart &>/dev/null
    fi
    rm -rf "$is_audit_dir" "$is_audit_data_dir"
    [[ ! $parent_uninstall ]] && _green "\n流量审计已卸载, 历史数据已删除.\n"
}

audit_main() {
    case $1 in
    enable | install)
        audit_enable "$2" "$3"
        ;;
    disable)
        audit_disable
        ;;
    uninstall | remove)
        audit_uninstall "$2"
        ;;
    start | stop | restart)
        [[ -f $is_audit_config ]] || err "流量审计尚未启用."
        audit_service_action "$1"
        ;;
    status | s)
        audit_status
        ;;
    url)
        audit_url
        ;;
    token)
        audit_token
        ;;
    set)
        audit_set "$2" "$3"
        ;;
    export)
        audit_export "$2" "$3" "$4"
        ;;
    report)
        audit_export "$2" "$3" "$4" usage
        ;;
    config-report)
        audit_export "$2" "$3" "$4" config
        ;;
    purge)
        audit_purge "$2"
        ;;
    h | help | --help | '')
        audit_usage
        ;;
    *)
        err "无法识别 audit 参数 ($1), 请使用: $is_core audit help"
        ;;
    esac
}
