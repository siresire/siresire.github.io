---
title: Simple-CTF 
author: siresire
date: 2024-04-8 08:45:00 +0800
categories: [TryHackMe,Linux]
tags: [CVE,VIM]
render_with_liquid: false
---


# Introduction 
The Simple CTF on TryHackMe is a perfect star8ng point for cybersecurity beginners. It's a beginner-level Capture the Flag (CTF) that offers a thrilling challenge. You get to prac8ce scanning, research, exploita8on, and privilege escala8on, key cybersecurity skills. Each task mimics real-world scenarios, allowing you to uncover vulnerabili8es. With determina8on and curiosity, I'm ready to tackle Simple CTF, sharpen my skills, and succeed in cybersecurity.

# Information Gathering
## nping 

First thing, I checked if the machine responded to pings (ICMP) using its IP address. The nping command showed 5 packets received, which works similarly to ping but sends an unlimited number of packets unless -n is used to specify the number of packets to send, the result was the same.

Based on the time-to-live (TTL) response, it appears the machine was likely running a Linux opera8ng system. However, it had lost 3 TTLs. Typically, Linux systems have a TTL of 64 in total. This suggests that the machine was routed 3 8mes before reaching us.
![Alt text](/assets/img/tryhackme/ln/ln19.png)

I attempted to determine the routing hops using the `tracepath` command or `traceroute`, but unfortunately, I couldn't find the information I was seeking.

## nmap scan 

Using the command `nmap -vv -sV -oN nmap.scans 10.10.156.57 -vv`, I discovered that there were a total of 3 ports open out of the first 10,000 ports.

![Alt text](/assets/img/tryhackme/ln/ln20.png)


### Port 21 FTP
Port 21, which is typically associated with FTP (File Transfer Protocol), allowed for anonymous login. Upon accessing FTP, I discovered a single directory containing a file.
![Alt text](/assets/img/tryhackme/ln/ln22.png)

After transferring the file, I found only a message discussing password reuse, which I made a note of Although I considered placing a payload there, I realized there was no available execution point for it.

```bash
┌──(root㉿kali)-[/home/…/Documents/CTFs/TryHackMe/easyctf]
└─# cat ForMitch.txt          
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
                                                                                                                    
```

### Port 80 HTTP

Port 80 showed an Apache2 Ubuntu Default Page, but there wasn't anything else in the page source code.

![Alt text](/assets/img/tryhackme/ln/ln21.png)


## Directory Enumeration
Since there was nothing on port 80, I decided to scan for hidden directories using a tool called `feroxbuster`.

![Alt text](/assets/img/tryhackme/ln/ln23.png)

When checking the URL directory, I found a page running `CMS Made Simple version 2.2.8`.

![Alt text](/assets/img/tryhackme/ln/ln24.png)

# Vulnerability Analysis
## CVE-2019-9053
When I checked on `searchsploit` for the CMS version, I found an exploit written in Python2 for `CVE-2019-9053` and moved it to my current folder
![Alt text](/assets/img/tryhackme/ln/ln25.png)


```python
┌──(root㉿kali)-[/home/…/Documents/CTFs/TryHackMe/easyctf]
└─# ls
46635.py  direcotories.logs  exploit.py  ForMitch.txt  login.req  nmap.scans  nmap.scans.all
                                                                                                                                                       
┌──(root㉿kali)-[/home/…/Documents/CTFs/TryHackMe/easyctf]
└─# python2 46635.py                                                                            
[+] Specify an url target
[+] Example usage (no cracking password): exploit.py -u http://target-uri
[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist
[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based.
```

To run the script, you had to supply url,wordlist and --crack parameters

Downloaded top 100 seclist instead of using rockyou.txt in which rockyou.txt had 14344392 creds 

![Alt text](/assets/img/tryhackme/ln/ln26.png)


To run the script, you needed to provide the URL, a wordlist, and the "--crack" parameter. Instead of using the rockyou.txt wordlist, I downloaded the top 100 seclist, as the rockyou.txt file contained 14,344,392 credentials.
After running the script approximately 20 times, it eventually successfully cracked the password

```bash
[+] Salt for password found:1dac0d92e9a6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com 
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96 
[+] Password cracked: secret
┌──(root㉿kali)-[/home/…/Documents/CTFs/TryHackMe/easyctf]
└─# 

```
# Exploitation

After successfully cracking the password, I managed to log in successfully to the CMS.
![Alt text](/assets/img/tryhackme/ln/ln27.png)
Before uploading a payload to the CMS, I tried reusing the password on port 2222 (SSH) because I remembered there was a message about password reuse on port 21 (FTP).
And I was in the machine 

## Exploitation
#### user enumeration. 

There are two users in the home directory: Mitch and Sunbath. If no user is found in the home directory, you can use 'grep' to search for those with a shell defined in /etc/passwd.
![Alt text](/assets/img/tryhackme/ln/ln30.png)

# Checking the process running
When I checked open ports using `netstat -ona`, I found that port 3306 was open, indicating MySQL. It was running locally, explaining why it wasn't detected in the Nmap scans. 
![Alt text](/assets/img/tryhackme/ln/ln29.png)

Upon checking the MySQL status, it was indeed running. However, attempting to reuse the password led to a dead end.
![Alt text](/assets/img/tryhackme/ln/ln31.png)

Using the find command, located where the app was running to hunt for passwords and in the configuration file there was a jackpot, database password
![Alt text](/assets/img/tryhackme/ln/ln32.png)

I accessed a database named 'bigtree' and found a 'cms_users' table with a password hash. 
![Alt text](/assets/img/tryhackme/ln/ln33.png)

Then, I added myself as a user in MySQL, allowing me to log in to the CMS with the new credentials.
```mysql
INSERT INTO cms_users (user_id, username, password, admin_access, first_name, last_name, email, active, create_date, modified_date) 
VALUES (1, 'sire', '0c01f4468bd75d7a84c7eb73846e8d96', 1, 'Godfrey', 'Bosire', 'john@example.com', 1, '2024-04-06', '2024-04-06');
```
![Alt text](/assets/img/tryhackme/ln/ln34.png)

 Although I encountered some failed attempts in the log files, I eventually succeeded in logging in.
![Alt text](/assets/img/tryhackme/ln/ln35.png)

# Privilege Escalation

Checking files that I (mitch) can run without root permission there was vim. 
![Alt text](/assets/img/tryhackme/ln/ln36.png)

Looking at the vim manual, I found out that the "-c" parameter lets us run commands. 
![Alt text](/assets/img/tryhackme/ln/ln37.png)

Used the command `sudo vim -c '!/bin/bash'` to execute a shell command upon opening Vim
![Alt text](/assets/img/tryhackme/ln/ln38.png)

# Post exploitation 
Creating users 
In this scenario, I made a new user and put them in the sudo group for more powers. 

![Alt text](/assets/img/tryhackme/ln/ln39.png)

Once created, I logged in with the new user's details, getting access to more functions. Then, I tried to gain even more control by accessing the root account and getting full power over the system.

![Alt text](/assets/img/tryhackme/ln/ln40.png)
Cleaning the logs 
We need to remove the log of exploiting vim to gain root access, as well as the log of creating a new user in `/var/log`.

![Alt text](/assets/img/tryhackme/ln/ln41.png)
- In the apache2 logs, we have our IP address in so echo null to the apache2 logs
- In error logs we have ur IP address there I cleaned it as well 

# Conclusion(Remediation/patching)

- Update the CMS Made Simple version 2.2.8 to the latest version, although the application appears to be discontinued.
- Disable the privileges allowing the user "Mitch" to execute vim with root privileges without a password by commenting out this relevant line with the command `sudo visudo`

```bash
# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
#mitch  ALL=(root) NOPASSWD: /usr/bin/vim
```

![Alt text](/assets/img/tryhackme/ln/ln42.png)

<!-- # P0wn3d <img src="https://media.giphy.com/media/WUlplcMpOCEmTGBtBW/giphy.gif" width="150" align="center"> -->

## 🐞 CVE-2019-9053