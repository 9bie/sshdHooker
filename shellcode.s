.intel_syntax noprefix
.global _dlopen_mode_addr_s
.global _dlopen_mode_param1_s
.global _inject_start_s
.global _inject_end_s
.global _printf_addr_s
.data
_inject_start_s:
        nop
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
        mov    %rsi, 0x2
_dlopen_mode_param1_s:
        mov    %rdi,0x1122334455667788
_dlopen_mode_addr_s:
        movabs %rax,0x1122334455667788
        call %rax
        int 0x80
        int 0xcc
_inject_end_s:
.space 0x400, 0
.end
