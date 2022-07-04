#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>

int ptrace_read(int pid, unsigned long addr, void *data, unsigned int len);
int ptrace_getregs( pid_t pid, struct user_regs_struct* regs );
int ptrace_setregs( pid_t pid, struct user_regs_struct* regs );
int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size );
int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size );
int ptrace_writestring( pid_t pid, uint8_t *dest, char *str  );
int ptrace_call( pid_t pid, uint64_t addr, long *params, uint32_t num_params, struct user_regs_struct* regs,int is_trap);

int ptrace_continue( pid_t pid );
int ptrace_attach( pid_t pid );
int ptrace_detach( pid_t pid );
void get_libc_path( pid_t pid, char* path );
void* get_module_base( pid_t pid, const char* module_name );
void* get_remote_addr( pid_t target_pid, const char* module_name, void* local_addr );



