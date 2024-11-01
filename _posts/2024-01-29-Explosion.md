---
title: Explosion
author: siresire
date: 2024-01-29 9:10:00 +0800
categories: [Hackthebox, Starting point, windows]
tags: [RDP]
render_with_liquid: false
---


## Enumerations 

### Nmap scan

```yaml
nmap -Pn -sV -A -vv -oN nmap_scans explosion.htb
```

![Alt text](/assets/img/posts/explosion_001.png)


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
