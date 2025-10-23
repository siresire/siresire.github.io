---
title: The Redux
author: siresire
date: 2024-05-04 18:10:00 +0800
categories: [Forensics]
tags: [PDF,peepdf,vmonkey]
render_with_liquid: false
---

# Analysing Malicious PDF's
Here we are again, delving into the realm of analyzing malicious PDF files.It's crucial to recognize that PDFs can harbor various other types of code, all capable of executing without the user's awareness. These encompass not only JavaScript but also Python scripts, executables, and Powershell shellcode.

![Alt text](/assets/img/tryhackme/rem/rm1.png)

Checking the output confirms that there's Javascript present, but also how it is executed? OpenAction will execute the code when the PDF is launched.To extract this Javascript, we can use `peepdf's` "extract" module. 

`echo 'extract js > javascript-from-demo_notsuspicious.pdf' > extracted_javascript.txt`

The script will extract all javascript via extract js and pipe > the contents into "javascript-from-demo_notsuspicious.pdf". We now need to tell peepdf the name of the script (extracted_javascript.txt) and the PDF file that we want to extract from (demo_notsuspicious.pdf): 

`peepdf -s extracted_javascript.txt demo_notsuspicious.pdf`

![Alt text](/assets/img/tryhackme/rem/rm2.png)

## Challenge 

Checking the metadata of the pdf

```bash
remnux@thm-remnux:~/Tasks/3$ peepdf advert.pdf 
Warning: PyV8 is not installed!!

File: advert.pdf
MD5: 1b79db939b1a77a2f14030f9fd165645
SHA1: e760b618943fe8399ac1af032621b6e7b327a772
SHA256: 09bb03e57d14961e522446e1e81184ca0b4e4278f080979d80ef20dacbbe50b7
Size: 74870 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 2
Objects: 29
Streams: 6
URIs: 0
Comments: 0
Errors: 1

Version 0:
	Catalog: 1
	Info: 9
	Objects (22): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
	Compressed objects (7): [10, 11, 12, 13, 14, 15, 16]
	Streams (5): [4, 17, 19, 20, 22]
		Xref streams (1): [22]
		Object streams (1): [17]
		Encoded (4): [4, 17, 19, 22]
	Suspicious elements:
		/Names (1): [13]


Version 1:
	Catalog: 1
	Info: 9
	Objects (0): []
	Streams (0): []

Version 2:
	Catalog: 1
	Info: 9
	Objects (7): [1, 3, 24, 25, 26, 27, 28]
	Streams (1): [26]
		Encoded (1): [26]
	Objects with JS code (1): [27]
	Suspicious elements:
		/OpenAction (1): [1]
		/Names (2): [24, 1]
		/AA (1): [3]
		/JS (1): [27]
		/Launch (1): [28]
		/JavaScript (1): [27]


remnux@thm-remnux:~/Tasks/3$ 

```

![Alt text](/assets/img/tryhackme/rem/rm3.png)


# Analysing Malicious Microsoft Office Macros

To analyze the Malicious Microsoft Office, we use a tool called `vmonkey` which is a parser engine that is capable of analysing visual basic macros without executing (opening the document).
`vmonkey DefinitelyALegitInvoice.doc`

![Alt text](/assets/img/tryhackme/rem/rm4.png)

# How's Your Memory?

Extracting the image information `volatility -f Win7-Jigsaw.raw imageinfo`

![Alt text](/assets/img/tryhackme/rem/rm5.png)

rofile `Win7SP1x64` is the first suggested and just happens to be the correct OS version.SO let's check for malicious processes to get an understanding of how the malware works and to also build a picture of Indicators of Compromise (IoC). We can list the processes that were running via pslist:

```bash
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ 
0xfffffa8003cf0960 System                    4      0     88      629 ------      0 2020-10-20 08:16:59 UTC+0000
0xfffffa800472e040 smss.exe                220      4      2       30 ------      0 2020-10-20 08:16:59 UTC+0000
0xfffffa80044f8b00 csrss.exe               320    308      9      466      0      0 2020-10-20 08:17:07 UTC+0000
----snipet------------------------
0xfffffa80059c6210 sppsvc.exe             2972    484      4      169      0      0 2020-10-20 08:22:56 UTC+0000
0xfffffa8006446060 OfficeClickToR         1432    484     19      573      0      0 2020-10-20 08:33:19 UTC+0000 
0xfffffa800647d060 chrome.exe             2472   1596      0 --------      1      0 2020-10-20 16:01:08 UTC+0000   2020-10-20 17:02:17 UTC+0000
0xfffffa800684ca00 drpbx.exe              3704   3604      4      131      1      0 2020-10-20 17:03:58 UTC+0000
0xfffffa80066f1b00 svchost.exe            2852    484      5       46      0      0 2020-10-20 17:20:08 UTC+0000
```

Note how you can see Google Chrome within the process because the application was running at the time of the memory dump.

Luckily we've got quite a shortlist of processes here, so we can start to narrow down between the system processes and any applications.

It can be daunting at first in trying to decide on what's worthy of investigating. As your seat time in malware analysis increases, you'll be able to pick out abnormalities. In this case, it's process "drpbx.exe" with a PID of 3704.

### What Can We Do With This?

Now that we've identified the abnormal process, we can begin to dump this specifically and begin analysing. As the application will be unpacked and/or in it's most revealing state, it is perfect for analysis.

`volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 dlllist -p 3704`

![Alt text](/assets/img/tryhackme/rem/rm6.png)

This DLL is a Windows library that allows applications to use cryptography. Whilst many use it legitimately, i.e. HTTPS, let's assume that we didn't know that the host was infected with ransomware specifically, we'd need to start investigating the process further.