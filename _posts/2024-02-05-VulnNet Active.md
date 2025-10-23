---
title: VulnNet Active
author: siresire
date: 2024-02-15 10:14:00 +0800
categories: [TryHackMe]
tags: [CVE]
render_with_liquid: false
---

# Introduction 
## Information Gathering

How about we begin by nmap a scans to check which ports are currently being used?

```yaml
nmap -sV -vv -sC -oN nmap.scans 10.10.161.98
```

![Alt text](/assets/img/tryhackme/va1.png)


The nmap scan provided us with some key details about our target. but, we've found open SMB ports (139 and 445), an RCP port (135), and an exposed Redis server (6379).


<!-- # Directory Enumeration 


![Alt text](/assets/img/posts/ofbizz_04.png)


# Vulnerability Analysis



# Exploitation

 -->

