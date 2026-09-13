get_latest_version() {
    case $1 in
    core)
        name=$is_core_name
        url="https://api.github.com/repos/${is_core_repo}/releases/latest?v=$RANDOM"
        ;;
    sh)
        name="$is_core_name 脚本"
        url="https://api.github.com/repos/$is_sh_repo/releases/latest?v=$RANDOM"
        ;;
    caddy)
        name="Caddy"
        url="https://api.github.com/repos/$is_caddy_repo/releases/latest?v=$RANDOM"
        ;;
    esac
    latest_ver=$(_wget -qO- $url | grep tag_name | grep -E -o 'v([0-9.]+)')
    [[ ! $latest_ver ]] && {
        err "获取 ${name} 最新版本失败."
    }
    unset name url
}
validate_archive() {
    local archive=$1 member listing
    listing=$(tar tzf "$archive") || return 1
    while IFS= read -r member; do
        case $member in
        /* | .. | ../* | */../* | */..)
            return 1
            ;;
        esac
    done <<<"$listing"
    listing=$(tar tvzf "$archive") || return 1
    # Release packages contain ordinary files/directories, never links outside the stage.
    [[ ! $(grep -E '^[lh]' <<<"$listing") ]]
}

validate_scripts() {
    local directory=$1 file
    [[ -s $directory/sing-box.sh && -s $directory/src/init.sh && -s $directory/src/core.sh ]] || return 1
    for file in "$directory"/*.sh "$directory"/src/*.sh; do
        [[ -f $file ]] || continue
        bash -n "$file" || return 1
    done
    if [[ -f $directory/src/audit/server.py ]] && type -P python3 &>/dev/null; then
        python3 -c 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' "$directory/src/audit/server.py" || return 1
    fi
    chmod +x "$directory/sing-box.sh"
}

update_service_running() {
    [[ $1 ]] || return 1
    if [[ $is_systemd ]]; then
        systemctl is-active --quiet "$1"
    elif [[ $is_openrc ]]; then
        rc-service "$1" status &>/dev/null
    else
        return 1
    fi
}

update_service_restart() {
    local service=$1 attempt listen port
    if [[ $is_systemd ]]; then
        systemctl restart "$service" || return 1
    elif [[ $is_openrc ]]; then
        rc-service "$service" restart || return 1
    else
        return 1
    fi
    for attempt in 1 2 3 4 5; do
        sleep 1
        update_service_running "$service" || continue
        if [[ $service == "$is_audit_name" ]]; then
            listen=$(jq -r '.listen' "$is_audit_config")
            port=$(jq -r '.port' "$is_audit_config")
            [[ $listen == 0.0.0.0 ]] && listen=127.0.0.1
            _wget --no-proxy -qO- -t 1 -T 2 "http://$listen:$port/api/health" | jq -e '.ok == true' &>/dev/null || continue
        fi
        return 0
    done
    return 1
}

# Stage on the destination filesystem, preserve a running service, and roll back on failure.
install_update() {
    local source=$1 target=$2 service=$3
    (
        local work old_exists=0 changed=0 running=0 result rollback_failed=0
        work=$(mktemp -d "${target%/*}/.update.XXXXXX") || exit 1
        trap '
            result=$?
            if [[ $result != 0 && $changed == 1 ]]; then
                if [[ -d $target ]]; then
                    mv -- "$target" "$work/failed" || rollback_failed=1
                fi
                if [[ $old_exists == 1 ]]; then
                    mv -f -- "$work/previous" "$target" || rollback_failed=1
                elif [[ -f $target ]]; then
                    rm -f -- "$target" || rollback_failed=1
                fi
                if [[ $running == 1 && $rollback_failed == 0 ]]; then
                    update_service_restart "$service" || printf "恢复后的服务未启动, 请检查: %s\n" "$service" >&2
                fi
            fi
            if [[ $rollback_failed == 0 ]]; then
                rm -rf -- "$work"
            else
                printf "自动恢复失败, 备份保留在: %s\n" "$work" >&2
            fi
            exit "$result"
        ' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        cp -a -- "$source" "$work/new" || exit 1
        update_service_running "$service" && running=1
        if [[ -e $target ]]; then
            old_exists=1
            if [[ -d $target ]]; then
                mv -- "$target" "$work/previous" || exit 1
                changed=1
            else
                cp -p -- "$target" "$work/previous" || exit 1
            fi
        fi
        mv -f -- "$work/new" "$target" || exit 1
        changed=1
        if [[ $running == 1 ]]; then
            update_service_restart "$service" || exit 1
        fi
        exit 0
    )
}

download() {
    local component=$1
    latest_ver=$2
    [[ $latest_ver ]] || get_latest_version "$component" || return 1
    (
        local tmpdir tmpfile link target staged service name checksum expected actual
        tmpdir=$(mktemp -d) || exit 1
        trap 'rm -rf -- "$tmpdir"' EXIT
        tmpfile=$tmpdir/package.tar.gz
        case $component in
        core)
            name=$is_core_name
            link="https://github.com/${is_core_repo}/releases/download/${latest_ver}/${is_core}-${latest_ver:1}-linux-${is_arch}.tar.gz"
            target=$is_core_bin
            service=$is_core
            ;;
        sh)
            name="$is_core_name 脚本"
            link="https://github.com/${is_sh_repo}/releases/download/${latest_ver}/code.tar.gz"
            target=$is_sh_dir
            service=$is_audit_name
            ;;
        caddy)
            name=Caddy
            link="https://github.com/${is_caddy_repo}/releases/download/${latest_ver}/caddy_${latest_ver:1}_linux_${is_arch}.tar.gz"
            target=$is_caddy_bin
            service=caddy
            ;;
        *)
            exit 1
            ;;
        esac
        _wget -t 5 -T 30 "$link" -O "$tmpfile" || { err "下载 ${name} 失败."; exit 1; }
        if [[ $component == sh ]]; then
            checksum=$tmpdir/checksum
            if _wget -q -t 2 -T 15 "$link.sha256" -O "$checksum"; then
                read -r expected _ <"$checksum"
                actual=$(sha256sum "$tmpfile") || exit 1
                [[ $expected =~ ^[[:xdigit:]]{64}$ && ${actual%% *} == "$expected" ]] || { err "脚本包 SHA-256 校验失败."; exit 1; }
            else
                warn "此版本未提供校验摘要, 将使用 TLS 和包结构校验."
            fi
        fi
        validate_archive "$tmpfile" || { err "下载包校验失败, 已保留原版本."; exit 1; }
        mkdir "$tmpdir/package" || exit 1
        if [[ $component == core ]]; then
            tar zxf "$tmpfile" --strip-components 1 -C "$tmpdir/package" || exit 1
            staged=$tmpdir/package/$is_core
            [[ -f $staged && ! -L $staged ]] && chmod +x "$staged" && "$staged" version &>/dev/null || exit 1
            "$staged" check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null || { err "新核心不接受当前配置, 已保留原版本."; exit 1; }
        else
            tar zxf "$tmpfile" -C "$tmpdir/package" || exit 1
            if [[ $component == sh ]]; then
                staged=$tmpdir/package
                validate_scripts "$staged" || { err "脚本包校验失败, 已保留原版本."; exit 1; }
            else
                staged=$tmpdir/package/caddy
                [[ -f $staged && ! -L $staged ]] && chmod +x "$staged" && "$staged" version &>/dev/null || exit 1
                if [[ -f $is_caddyfile ]]; then
                    "$staged" validate --config "$is_caddyfile" --adapter caddyfile &>/dev/null || exit 1
                fi
            fi
        fi
        install_update "$staged" "$target" "$service" || { err "更新失败, 已尝试恢复原版本, 请检查服务状态."; exit 1; }
    )
}
