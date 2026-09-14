#!/bin/bash

author=233boy
# github=https://github.com/233boy/sing-box

# bash fonts colors
red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$@${none}; }
_blue() { echo -e ${blue}$@${none}; }
_cyan() { echo -e ${cyan}$@${none}; }
_green() { echo -e ${green}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }
_magenta() { echo -e ${magenta}$@${none}; }
_red_bg() { echo -e "\e[41m$@${none}"; }

is_err=$(_red_bg 错误!)
is_warn=$(_red_bg 警告!)

err() {
    echo -e "\n$is_err $@\n" && exit 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}

# root
[[ $EUID != 0 ]] && err "当前非 ${yellow}ROOT用户.${none}"

# apt-get, yum, zypper or apk
cmd=$(type -P apt-get || type -P yum || type -P zypper || type -P apk)
[[ ! $cmd ]] && err "此脚本仅支持 ${yellow}(Ubuntu or Debian or CentOS or SUSE or Alpine)${none}."

# systemd or openrc
is_systemd=$(type -P systemctl)
is_openrc=$(type -P rc-service)
[[ ! $is_systemd && ! $is_openrc ]] && {
    err "此系统缺少 ${yellow}(systemctl 或 rc-service)${none}, 请安装 systemd 或确认 OpenRC 已启用."
}

# wget installed or none
is_wget=$(type -P wget)

# x64
case $(uname -m) in
amd64 | x86_64)
    is_arch=amd64
    ;;
*aarch64* | *armv8*)
    is_arch=arm64
    ;;
*)
    err "此脚本仅支持 64 位系统..."
    ;;
esac

is_core=sing-box
is_core_name=sing-box
is_core_dir=/etc/$is_core
is_core_bin=$is_core_dir/bin/$is_core
is_core_repo=SagerNet/$is_core
is_conf_dir=$is_core_dir/conf
is_log_dir=/var/log/$is_core
is_sh_bin=/usr/local/bin/$is_core
is_sh_dir=$is_core_dir/sh
is_sh_repo=zonwe/$is_core
is_audit_name=${is_core}-audit
is_audit_dir=$is_core_dir/audit
is_audit_config=$is_audit_dir/config.json
is_audit_data_dir=/var/lib/$is_audit_name
is_audit_database=$is_audit_data_dir/audit.db
is_audit_server=$is_sh_dir/src/audit/server.py
is_audit_listen=127.0.0.1
is_audit_port=9091
is_pkg="ca-certificates wget tar bash"
# Alpine: gcompat provides glibc compatibility for prebuilt binaries
[[ $cmd =~ apk ]] && is_pkg="$is_pkg gcompat jq"
is_config_json=$is_core_dir/config.json
tmp_var_lists=(
    tmpcore
    tmpsh
    tmpjq
    is_core_ok
    is_sh_ok
    is_jq_ok
    is_pkg_ok
)

# tmp dir
tmpdir=$(mktemp -d) || err "无法创建安装临时目录."
trap 'rm -rf -- "$tmpdir"' EXIT

# set up var
for i in ${tmp_var_lists[*]}; do
    export $i=$tmpdir/$i
done

# load bash script.
load() {
    . $is_sh_dir/src/$1
}

# Install CA certificates before using verified HTTPS downloads.
_wget() {
    [[ $proxy ]] && export https_proxy=$proxy
    wget "$@"
}

# print a mesage
msg() {
    case $1 in
    warn)
        local color=$yellow
        ;;
    err)
        local color=$red
        ;;
    ok)
        local color=$green
        ;;
    esac

    echo -e "${color}$(date +'%T')${none}) ${2}"
}

# show help msg
show_help() {
    echo -e "Usage: $0 [-f xxx | -l | --script-update | -p xxx | -v xxx | --no-audit | --audit-listen xxx | --audit-port xxx | -h]"
    echo -e "  -f, --core-file <path>          自定义 $is_core_name 文件路径, e.g., -f /root/$is_core-linux-amd64.tar.gz"
    echo -e "  -l, --local-install             本地获取安装脚本, 使用当前目录"
    echo -e "      --script-update             仅更新已安装的管理脚本, 保留配置和审计数据"
    echo -e "  -p, --proxy <addr>              使用代理下载, e.g., -p http://127.0.0.1:2333"
    echo -e "  -v, --core-version <ver>        自定义 $is_core_name 版本, e.g., -v v1.8.13"
    echo -e "      --no-audit                  全新安装时不启用流量审计"
    echo -e "      --audit-listen <addr>       审计页面监听地址, 默认 127.0.0.1"
    echo -e "      --audit-port <port>         审计页面端口, 默认 9091"
    echo -e "  -h, --help                      显示此帮助界面\n"

    exit 0
}

validate_audit_listen_arg() {
    local listen=$1
    local octet
    local old_ifs=$IFS
    [[ $listen == localhost ]] && return 0
    [[ $listen =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=.
    for octet in $listen; do
        if ((10#$octet > 255)); then
            IFS=$old_ifs
            return 1
        fi
    done
    IFS=$old_ifs
}

# install dependent pkg
install_pkg() {
    cmd_not_found=
    for i in $*; do
        if [[ $i == ca-certificates ]]; then
            [[ -s /etc/ssl/certs/ca-certificates.crt || -s /etc/pki/tls/certs/ca-bundle.crt || -s /etc/ssl/ca-bundle.pem ]] || cmd_not_found="$cmd_not_found,$i"
        else
            [[ ! $(type -P "$i") ]] && cmd_not_found="$cmd_not_found,$i"
        fi
    done
    if [[ $cmd_not_found ]]; then
        pkg=$(echo $cmd_not_found | sed 's/,/ /g')
        msg warn "安装依赖包 >${pkg}"
        if [[ $cmd =~ apk ]]; then
            apk update &>/dev/null
            apk add $pkg &>/dev/null
        else
            $cmd install -y $pkg &>/dev/null
            if [[ $? != 0 ]]; then
                [[ $cmd =~ yum ]] && yum install epel-release -y &>/dev/null
                if [[ $cmd =~ zypper ]]; then
                    $cmd --non-interactive refresh &>/dev/null
                else
                    $cmd update -y &>/dev/null
                fi
                $cmd install -y $pkg &>/dev/null
            fi
        fi
        [[ $? == 0 ]] && >$is_pkg_ok
    else
        >$is_pkg_ok
    fi
}

# download file
download() {
    local link name tmpfile is_ok expected actual checksum
    case $1 in
    core)
        [[ ! $is_core_ver ]] && is_core_ver=$(_wget -qO- "https://api.github.com/repos/${is_core_repo}/releases/latest?v=$RANDOM" | grep tag_name | grep -E -o 'v([0-9.]+)')
        [[ $is_core_ver ]] && link="https://github.com/${is_core_repo}/releases/download/${is_core_ver}/${is_core}-${is_core_ver:1}-linux-${is_arch}.tar.gz"
        name=$is_core_name
        tmpfile=$tmpcore
        is_ok=$is_core_ok
        ;;
    sh)
        link=https://github.com/${is_sh_repo}/releases/latest/download/code.tar.gz
        name="$is_core_name 脚本"
        tmpfile=$tmpsh
        is_ok=$is_sh_ok
        ;;
    jq)
        link=https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-$is_arch
        name="jq"
        tmpfile=$tmpjq
        is_ok=$is_jq_ok
        ;;
    esac

    [[ $link ]] && {
        msg warn "下载 ${name} > ${link}"
        if _wget -t 3 -T 30 -q "$link" -O "$tmpfile"; then
            if [[ $1 == jq ]]; then
                # jq 1.7.1 official sha256sum.txt, pinned with the download version.
                case $is_arch in
                amd64) expected=5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5 ;;
                arm64) expected=4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5 ;;
                esac
                actual=$(sha256sum "$tmpfile") || return 1
                [[ ${actual%% *} == "$expected" ]] || { msg err "jq SHA-256 校验失败."; return 1; }
            else
                validate_archive "$tmpfile" || { msg err "${name} 下载包校验失败."; return 1; }
                if [[ $1 == sh ]]; then
                    checksum=$tmpfile.sha256
                    if _wget -q -t 2 -T 15 "$link.sha256" -O "$checksum"; then
                        read -r expected _ <"$checksum"
                        actual=$(sha256sum "$tmpfile") || return 1
                        [[ $expected =~ ^[[:xdigit:]]{64}$ && ${actual%% *} == "$expected" ]] || { msg err "脚本包 SHA-256 校验失败."; return 1; }
                    else
                        msg warn "此版本未提供校验摘要, 将使用 TLS 和包结构校验."
                    fi
                fi
            fi
            mv -f -- "$tmpfile" "$is_ok"
        fi
    }
}

# get server ip
get_ip() {
    export "$(_wget -4 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
    [[ -z $ip ]] && export "$(_wget -6 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
}

# check background tasks status
check_status() {
    # dependent pkg install fail
    [[ ! -f $is_pkg_ok ]] && {
        msg err "安装依赖包失败"
        if [[ $cmd =~ apk ]]; then
            msg err "请尝试手动安装依赖包: apk update; apk add $is_pkg"
        else
            msg err "请尝试手动安装依赖包: $cmd update -y; $cmd install -y $is_pkg"
        fi
        is_fail=1
    }

    # download file status
    if [[ $is_wget ]]; then
        [[ ! -f $is_core_ok ]] && {
            msg err "下载 ${is_core_name} 失败"
            is_fail=1
        }
        [[ ! -f $is_sh_ok ]] && {
            msg err "下载 ${is_core_name} 脚本失败"
            is_fail=1
        }
        [[ ! -f $is_jq_ok ]] && {
            msg err "下载 jq 失败"
            is_fail=1
        }
    else
        [[ ! $is_fail ]] && {
            is_wget=1
            [[ ! $is_core_file ]] && download core &
            [[ ! $local_install ]] && download sh &
            [[ $jq_not_found ]] && download jq &
            get_ip
            wait
            check_status
        }
    fi

    # found fail status, remove tmp dir and exit.
    [[ $is_fail ]] && {
        exit_and_del_tmpdir
    }
}

# parameters check
pass_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
        -f | --core-file)
            [[ -z $2 ]] && {
                err "($1) 缺少必需参数, 正确使用示例: [$1 /root/$is_core-linux-amd64.tar.gz]"
            } || [[ ! -f $2 ]] && {
                err "($2) 不是一个常规的文件."
            }
            is_core_file=$2
            shift 2
            ;;
        -l | --local-install)
            [[ ! -f ${PWD}/src/core.sh || ! -f ${PWD}/$is_core.sh ]] && {
                err "当前目录 (${PWD}) 非完整的脚本目录."
            }
            local_install=1
            shift 1
            ;;
        --script-update)
            script_update=1
            shift 1
            ;;
        --no-audit)
            is_no_audit=1
            shift 1
            ;;
        --audit-listen)
            [[ -z $2 || $2 == -* ]] && {
                err "($1) 缺少必需参数, 正确使用示例: [$1 127.0.0.1]"
            }
            validate_audit_listen_arg "$2" || {
                err "($2) 不是有效的审计监听地址, 请输入 IPv4 地址或 localhost."
            }
            is_audit_listen=$2
            shift 2
            ;;
        --audit-port)
            [[ -z $2 || $2 == -* ]] && {
                err "($1) 缺少必需参数, 正确使用示例: [$1 9091]"
            }
            [[ $2 =~ ^[0-9]+$ && $2 -ge 1 && $2 -le 65535 ]] || {
                err "($2) 不是有效的审计页面端口, 请输入 1 到 65535."
            }
            is_audit_port=$2
            shift 2
            ;;
        -p | --proxy)
            [[ -z $2 ]] && {
                err "($1) 缺少必需参数, 正确使用示例: [$1 http://127.0.0.1:2333 or -p socks5://127.0.0.1:2333]"
            }
            proxy=$2
            shift 2
            ;;
        -v | --core-version)
            [[ -z $2 ]] && {
                err "($1) 缺少必需参数, 正确使用示例: [$1 v1.8.13]"
            }
            is_core_ver=v${2//v/}
            shift 2
            ;;
        -h | --help)
            show_help
            ;;
        *)
            echo -e "\n${is_err} ($@) 为未知参数...\n"
            show_help
            ;;
        esac
    done
    [[ $is_core_ver && $is_core_file ]] && {
        err "无法同时自定义 ${is_core_name} 版本和 ${is_core_name} 文件."
    }
}

# Bootstrap copies of src/download.sh helpers: keep both entry points compatible with older releases.
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

# update installed management scripts without reinstalling sing-box
update_script_only() {
    [[ ! -f $is_sh_bin || ! -d $is_sh_dir ]] && {
        err "未检测到已安装的 $is_core_name 管理脚本."
    }

    mkdir -p "$tmpdir"
    install_pkg "ca-certificates wget tar bash"
    [[ ! -f $is_pkg_ok ]] && {
        err "安装更新依赖失败."
    }

    is_wget=$(type -P wget)
    download sh
    [[ ! -f $is_sh_ok ]] && {
        err "下载 ${is_core_name} 脚本失败."
    }
    mkdir "$tmpdir/scripts" || err "无法创建脚本暂存目录."
    tar zxf "$is_sh_ok" -C "$tmpdir/scripts" || err "下载的脚本包无法解压."
    validate_scripts "$tmpdir/scripts" || err "下载的脚本包无法通过校验."
    install_update "$tmpdir/scripts" "$is_sh_dir" "$is_audit_name" || err "更新失败, 已尝试恢复原脚本, 请检查服务状态."
    msg ok "管理脚本更新完成; 配置和审计数据均已保留."
    exit 0
}

# exit and remove tmpdir
exit_and_del_tmpdir() {
    rm -rf "$tmpdir"
    [[ ! $1 ]] && {
        msg err "哦豁.."
        msg err "安装过程出现错误..."
        echo -e "反馈问题) https://github.com/${is_sh_repo}/issues"
        echo
        exit 1
    }
    exit 0
}

# main
main() {

    # check parameters before detecting an existing installation so that
    # --script-update can migrate installations from the upstream script.
    [[ $# -gt 0 ]] && pass_args "$@"
    [[ $script_update ]] && update_script_only

    # check old version
    [[ -f $is_sh_bin && -d $is_core_dir/bin && -d $is_sh_dir && -d $is_conf_dir ]] && {
        err "检测到脚本已安装, 如需重装请使用${green} ${is_core} reinstall ${none}命令."
    }

    # show welcome msg
    clear
    echo
    echo "........... $is_core_name script by $author .........."
    echo

    # start installing...
    msg warn "开始安装..."
    [[ $is_core_ver ]] && msg warn "${is_core_name} 版本: ${yellow}$is_core_ver${none}"
    [[ $proxy ]] && msg warn "使用代理: ${yellow}$proxy${none}"
    [[ ! $is_no_audit ]] && msg warn "流量审计: ${yellow}默认启用 ($is_audit_listen:$is_audit_port)${none}"
    # create tmpdir
    mkdir -p $tmpdir
    # if is_core_file, copy file
    [[ $is_core_file ]] && {
        cp -f $is_core_file $is_core_ok
        msg warn "${yellow}${is_core_name} 文件使用 > $is_core_file${none}"
    }
    # local dir install sh script
    [[ $local_install ]] && {
        >$is_sh_ok
        msg warn "${yellow}本地获取安装脚本 > $PWD ${none}"
    }

    if [[ $is_systemd ]]; then
        timedatectl set-ntp true &>/dev/null
        [[ $? != 0 ]] && {
            is_ntp_on=1
        }
    fi

    # install dependent pkg
    if [[ $cmd =~ apk ]]; then
        # Alpine: force install full versions to replace BusyBox applets
        apk update &>/dev/null
        apk add $is_pkg &>/dev/null
        [[ $? == 0 ]] && >$is_pkg_ok
    else
        install_pkg $is_pkg
    fi
    [[ -f $is_pkg_ok ]] || exit_and_del_tmpdir

    # jq
    if [[ $(type -P jq) ]]; then
        >$is_jq_ok
    else
        jq_not_found=1
    fi
    # if wget installed. download core, sh, jq, get ip
    [[ $is_wget ]] && {
        [[ ! $is_core_file ]] && download core &
        [[ ! $local_install ]] && download sh &
        [[ $jq_not_found ]] && download jq &
        get_ip
    }

    # waiting for background tasks is done
    wait

    # check background tasks status
    check_status

    # test $is_core_file
    if [[ $is_core_file ]]; then
        mkdir -p $tmpdir/testzip
        validate_archive "$is_core_ok" || exit_and_del_tmpdir
        tar zxf "$is_core_ok" --strip-components 1 -C "$tmpdir/testzip" &>/dev/null
        [[ $? != 0 ]] && {
            msg err "${is_core_name} 文件无法通过测试."
            exit_and_del_tmpdir
        }
        [[ ! -f $tmpdir/testzip/$is_core ]] && {
            msg err "${is_core_name} 文件无法通过测试."
            exit_and_del_tmpdir
        }
    fi

    # get server ip.
    [[ ! $ip ]] && {
        msg err "获取服务器 IP 失败."
        exit_and_del_tmpdir
    }

    # create sh dir...
    mkdir -p $is_sh_dir

    # copy sh file or unzip sh zip file.
    if [[ $local_install ]]; then
        cp -rf "$PWD/"* "$is_sh_dir" || exit_and_del_tmpdir
    else
        tar zxf "$is_sh_ok" -C "$is_sh_dir" || exit_and_del_tmpdir
    fi
    validate_scripts "$is_sh_dir" || exit_and_del_tmpdir

    # create core bin dir
    mkdir -p $is_core_dir/bin
    # copy core file or unzip core zip file
    if [[ $is_core_file ]]; then
        cp -rf "$tmpdir/testzip/"* "$is_core_dir/bin" || exit_and_del_tmpdir
    else
        tar zxf "$is_core_ok" --strip-components 1 -C "$is_core_dir/bin" || exit_and_del_tmpdir
    fi

    # add alias
    echo "alias sb=$is_sh_bin" >>/root/.bashrc
    echo "alias $is_core=$is_sh_bin" >>/root/.bashrc

    # core command
    ln -sf $is_sh_dir/$is_core.sh $is_sh_bin
    ln -sf $is_sh_dir/$is_core.sh ${is_sh_bin/$is_core/sb}

    # jq
    [[ $jq_not_found ]] && mv -f $is_jq_ok /usr/bin/jq

    # chmod
    chmod +x $is_core_bin $is_sh_bin /usr/bin/jq ${is_sh_bin/$is_core/sb}

    # create log dir
    mkdir -p $is_log_dir

    # show a tips msg
    msg ok "生成配置文件..."

    # create service
    load systemd.sh
    is_new_install=1
    install_service $is_core &>/dev/null

    # create condf dir
    mkdir -p $is_conf_dir

    load core.sh
    # create a reality config
    add reality || exit_and_del_tmpdir
    # wait for background tasks (e.g., OpenRC service start)
    wait
    # enable traffic audit by default for a new installation
    if [[ ! $is_no_audit ]]; then
        load audit.sh
        audit_enable "$is_audit_listen" "$is_audit_port"
    fi
    # remove tmp dir and exit.
    exit_and_del_tmpdir ok
}

# start.
main "$@"
