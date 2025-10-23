---
title: Practical Ethical Hacking
author: siresire
date: 2023-05-28 18:10:00 +0800
categories: [Basics]
tags: []
render_with_liquid: false
---


## Enumerations 

### Nmap scan

```yaml
nmap -Pn -sV --script=vuln -vv -oN nmap_scans dancing.htb
```

![Alt text](/assets/img/posts/dancing_001.png)
3 ports are open here 

#### Checking the SMB (Server Message Block)

##### port 445 TCP

```yaml
# to list smb shares 
smbclient -L dancing.htb
```
![Alt text](/assets/img/posts/dancing_002.png)


after downloading the files from smb shares got a flag and this info message 

>  
- start apache server on the linux machine
- secure the ftp server
- setup winrm on dancing
{: .prompt-info }
