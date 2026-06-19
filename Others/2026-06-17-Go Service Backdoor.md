---
title: Analyzing a Go Service Backdoor 
author: siresire
date: 2026-06-17 18:10:00 +0800
categories: []
tags: []
render_with_liquid: false
---

# Getting the file signatures 

```bash
C:\Users\sire\Desktop
λ file Backdoor.srvupdat.exe.malz
Backdoor.srvupdat.exe.malz: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 14 sections

C:\Users\sire\Desktop
λ sha256sum.exe Backdoor.srvupdat.exe.malz
914cad877a41f12bb0998bc1c28d04ee2fb33c4538707547cad726b41f7d01c3 *Backdoor.srvupdat.exe.malz

C:\Users\sire\Desktop
λ

```

from virustotal we can this is a malicous 
![alt text](/assets/img/TCM/010/image.png)

## pulling out strings 
from floss, we ca see alot of strings have go meaing that this binary is probably written i go language 
![alt text](/assets/img/TCM/010/image-1.png)

from PE-bear we can see ‘.symtab’ section which means the malware was compiled in go
![alt text](/assets/img/TCM/010/image-2.png)

running the malware and trying to follow the tcp stream, we ca see the user-aget is also Go-http-client/1.1 meaning the malware is in go laguage 
![alt text](/assets/img/TCM/010/image-3.png)

# the Goal

The goal here is to indetify the key characterristics of a certain portable executable and to be able to key in on te sigatures strings imports and we ca pivit those into rules that will write to identify this out in the file 