---
title: Volatility
author: siresire
date: 2024-02-28 22:10:00 +0800
categories: [Forensics,Volatility]
tags: [Volatility 3]
render_with_liquid: false
---

# Introduction

Volatility is a free memory forensics tool commonly used by malware and SOC analysts within a blue team or as part of their detection and monitoring solutions. Volatility is written in Python and is made up of python plugins and modules designed as a plug-and-play way of analyzing memory dumps.

Volatility uses different plugins together to gather info from a memory dump. First, you'll ID the image type; we'll discuss how in later tasks. Then, with the image type and other plugins sorted, you can start analyzing the dump using various Volatility plugins covered later. Volatility being separate from the system investigated allows for complete segmentation but full insight into the system's runtime state.

## Memory Extraction

Extracting a memory dump can be performed in numerous ways, varying based on the requirements of your investigation. Listed below are a few of the techniques and tools that can be used to extract a memory from a bare-metal machine.

- FTK Imager
- Redline
- DumpIt.exe
- win32dd.exe / win64dd.exe
- Memoryze
- FastDump

When using an extraction tool on a bare-metal host, it can usually take a considerable amount of time; take this into consideration during your investigation if time is a constraint.


For virtual machines, gathering a memory file can easily be done by collecting the virtual memory file from the host machine’s drive. This file can change depending on the hypervisor used; listed below are a few of the hypervisor virtual memory files you may encounter.

- VMWare - .vmem
- Hyper-V - .bin
- Parallels - .mem
- VirtualBox - .sav file *this is only a partial memory file


# Plugins Overview

Identifying image profiles can be tough without knowing the machine's version and build. Volatility's imageinfo plugin solves this by assigning the best OS profiles to the memory dump, simplifying analysis, especially in Volatility2.

```bash
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.raw windows.info
Volatility 3 Framework 1.0.1
Progress:  100.00		PDB scanning finished                     
Variable	Value

Kernel Base	0x804d7000
DTB	0x39000
Symbols	file:///opt/volatility3/volatility3/symbols/windows/ntoskrnl.pdb/423320282DB842E7BA2B0BFC86A84D75-2.json.xz
Is64Bit	False
IsPAE	False
primary	0 WindowsIntel
memory_layer	1 FileLayer
KdDebuggerDataBlock	0x8054cf60
NTBuildLab	2600.xpsp_sp3_qfe.130704-0421
CSDVersion	3
KdVersionBlock	0x8054cf38
Major/Minor	15.2600
MachineType	332
KeNumberProcessors	1
SystemTime	2017-05-12 21:26:32
NtSystemRoot	C:\WINDOWS
NtProductType	NtProductWinNt
NtMajorVersion	5
NtMinorVersion	1
PE MajorOperatingSystemVersion	5
PE MinorOperatingSystemVersion	1
PE Machine	332
PE TimeDateStamp	Thu Jul  4 02:58:58 2013
thmanalyst@ubuntu:/opt/volatility3$ 
```

# Listing Processes and Connections
Five different plugins within Volatility allow you to dump processes and network connections, each with varying techniques used. In this task, we will be discussing each and its pros and cons when it comes to evasion techniques used by adversaries

Use pslist to list all processes, including terminated ones, akin to Task Manager.
Syntax: `python3 vol.py -f <file> windows.pslist`

```bash
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.raw windows.pslist
Volatility 3 Framework 1.0.1
Progress:  100.00		PDB scanning finished                     
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output
4	0	System	0x823c8830	51	244	N/A	False	N/A	N/A	Disabled
348	4	smss.exe	0x82169020	3	19	N/A	False	2017-05-12 21:21:55.000000 	N/A	Disabled
596	348	csrss.exe	0x82161da0	12	352	0	False	2017-05-12 21:22:00.000000 	N/A	Disabled
---snippet ------------------------
544	664	alg.exe	0x82010020	6	101	0	False	2017-05-12 21:22:55.000000 	N/A	Disabled
1168	1024	wscntfy.exe	0x81fea8a0	1	37	0	False	2017-05-12 21:22:56.000000 	N/A	Disabled
thmanalyst@ubuntu:/opt/volatility3$ 

```

Combat process-hiding techniques like rootkits with psscan, though it may yield false positives. Syntax: `python3 vol.py -f <file> windows.psscan`

```bash
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.raw windows.psscan
Volatility 3 Framework 1.0.1
Progress:  100.00		PDB scanning finished                     
PID	PPID	ImageFileName	Offset	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

860	1940	taskdl.exe	0x1f4daf0	0	-	0	False	2017-05-12 21:26:23.000000 	2017-05-12 21:26:23.000000Disabled
536	1940	taskse.exe	0x1f53d18	0	-	0	False	2017-05-12 21:26:22.000000 	2017-05-12 21:26:23.000000Disabled
1768	1024	wuauclt.exe	0x1f747c0	7	132	0	False	2017-05-12 21:22:52.000000 	N/A	Disabled
260	664	svchost.exe	0x1fb95d8	5	105	0	False	2017-05-12 21:22:18.000000 	N/A	Disabled
740	1940	@WanaDecryptor@	0x1fde308	2	70	0	False	2017-05-12 21:22:22.000000 	N/A	Disabled
836	664	svchost.exe	0x221a2c0	19	211	0	False	2017-05-12 21:22:02.000000 	N/A	Disabled
---snippet ------------------------

```

The pstree plugin lists processes based on parent process IDs, offering a comprehensive view of process hierarchy, useful for understanding extraction events. Syntax: `python3 vol.py -f <file> windows.pstree`

Identify network connections with netstat, which can be unstable in older Windows builds; consider using bulk_extractor for stability. Syntax: ` python3 vol.py -f <file> windows.netstat`


This command in the current state of volatility3 can be very unstable, particularly around old Windows builds. To combat this, you can utilize other tools like bulk_extractor to extract a PCAP file from the memory file. In some cases, this is preferred in network connections that you cannot identify from Volatility alone.[link](https://tools.kali.org/forensics/bulk-extractor)

Utilize dlllist to list DLLs associated with processes, aiding in malware detection and analysis. Syntax: `python3 vol.py -f <file> windows.dlllist`

# Volatility Hunting and Detection Capabilities
Volatility offers a plethora of plugins that can be used to aid in your hunting and detection capabilities when hunting for malware or other anomalies within a system's memory.

`malfind` will attempt to identify injected processes and their PIDs along with the offset address and a Hex, Ascii, and Disassembly view of the infected area. The plugin works by scanning the heap and identifying processes that have the executable bit set RWE or RX and/or no memory-mapped file on disk (file-less malware). Based on what `malfind` identifies, the injected area will change. An MZ header is an indicator of a Windows executable file. The injected area could also be directed towards shellcode which requires further analysis.

```bash
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.raw windows.malfind
Volatility 3 Framework 1.0.1
Progress:  100.00		PDB scanning finished                     
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Hexdump	Disasm

596	csrss.exe	0x7f6f0000	0x7f7effff	Vad 	PAGE_EXECUTE_READWRITE	0	0	Disabled	
c8 00 00 00 8b 01 00 00	........
ff ee ff ee 08 70 00 00	.....p..
08 00 00 00 00 fe 00 00	........
00 00 10 00 00 20 00 00	........
00 02 00 00 00 20 00 00	........
8d 01 00 00 ff ef fd 7f	........
03 00 08 06 00 00 00 00	........
00 00 00 00 00 00 00 00	........	c8 00 00 00 8b 01 00 00 ff ee ff ee 08 70 00 00 08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00 00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f 03 00 08 06 00 00 00 00 00 00 00 00 00 00 00 00
620	winlogon.exe	0x21400000	0x21403fff	VadS	PAGE_EXECUTE_READWRITE	4	1	Disabled	
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........

---snippet ------------------------
```

# Advanced Memory Forensics

Advanced Memory Forensics can be daunting, especially without experience in system object interactions or malware techniques like hooking and driver manipulation. Dealing with advanced adversaries often means confronting rootkits with sophisticated evasion tactics, necessitating analysis of drivers, mutexes, and hooked functions to uncover hidden malware.

The first evasion technique we will be hunting is hooking; there are five methods of hooking employed by adversaries, outlined below:

- SSDT Hooks
- IRP Hooks
- IAT Hooks
- EAT Hooks
- Inline Hooks


The `ssdt` plugin will search for hooking and output its results. Hooking can be used by legitimate applications, so it is up to you as the analyst to identify what is evil. As a brief overview of what SSDT hooking is: SSDT stands for System Service Descriptor Table; the Windows kernel uses this table to look up system functions. An adversary can hook into this table and modify pointers to point to a location the rootkit controls.

The `modules` plugin will dump a list of loaded kernel modules; this can be useful in identifying active malware. However, if a malicious file is idly waiting or hidden, this plugin may miss it.

The `driverscan` plugin will scan for drivers present on the system at the time of extraction. This plugin can help to identify driver files in the kernel that the modules plugin might have missed or were hidden.

There are also other plugins listed below that can be helpful when attempting to hunt for advanced malware in memory.
: modscan, 
driverirp, 
callbacks, 
idt, 
apihooks, 
moddump and
handles
