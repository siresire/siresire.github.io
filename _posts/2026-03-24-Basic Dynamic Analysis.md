---
title: Basic Dynamic Analysis
author: siresire
date: 2026-03-24 18:10:00 +0800
categories: [Malware, SOC]
tags: [Wireshark,Procmon ]
render_with_liquid: false
---


# Basic Dynamic Analysis Report

This report documents the dynamic analysis of a malware sample, following a prior static analysis conducted [here](https://siresire.github.io/posts/Basic-Static-Analysis/)


The goal of this phase is to validate and observe the actual runtime behavior of the sample, specifically focusing on network activity, file system changes, and execution flow.

---

## 1. Objectives

The main objectives of this analysis were:

- Validate indicators identified during static analysis  
- Observe network communication with external resources  
- Identify file system activity (file creation, deletion)  
- Understand process execution and control flow  
- Detect any anti-analysis or evasion techniques  

---

## 2. Static Analysis Summary

### Extracted Strings
```text
cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
http://ssl-6582datamanager.helpdeskbros.local/favicon.ico
C:\Users\Public\Documents\CR433101.dat.exe
Mozilla/5.0
````

### Relevant API Calls

* `URLDownloadToFileW`
* `InternetOpenUrlW`
* `InternetOpenW`
* `CreateProcessW`
* `ShellExecuteW`

---

## 3. Dynamic Analysis Environment

The sample was executed in a controlled lab environment using:

* **Wireshark** → network traffic analysis
* **Process Monitor (Procmon)** → host activity monitoring

---

## 4. Network Analysis

Wireshark filter used:

```text
http.request.full_uri contains favicon.ico
```

![alt text](/assets/img/TCM/002/image.png)

Observed request:

```text
http://ssl-6582datamanager.helpdeskbros.local/favicon.ico
```

![alt text](/assets/img/TCM/002/image-1.png)

### Findings

* Outbound HTTP request confirmed
* User-Agent observed: `Mozilla/4.0`
* Matches static analysis indicator

---

## 5. Host-Based Analysis

### 5.1 File System Activity

Procmon filter:

```
Process Name is Malware.Unknown.exe
```

![alt text](/assets/img/TCM/002/image-2.png)

Filtered file operations:

![alt text](/assets/img/TCM/002/image-3.png)

### Findings

File created:

```text
C:\Users\Public\Documents\CR433101.dat.exe
```

---

### 5.2 Command Execution & Self-Deletion

Command observed:

```text
cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
```

![alt text](/assets/img/TCM/002/image-4.png)

### Findings

* Execution of `cmd.exe`
* Network connectivity check via `ping`
* Conditional self-deletion

---

## 6. Execution Flow

### If URL is reachable

* Connect to remote server
* Download payload (`favicon.ico`)
* Save as `CR433101.dat.exe`
* Execute payload

### If URL is not reachable

* Perform connectivity check
* Delete original binary
* Terminate execution

---

## 7. Indicators of Compromise (IOCs)

### Network

* `http://ssl-6582datamanager.helpdeskbros.local/favicon.ico`

### Host

* `C:\Users\Public\Documents\CR433101.dat.exe`
* `cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"`

---

## 8. MITRE ATT&CK Mapping

The observed behaviors were mapped to the MITRE ATT&CK framework as follows:

| Tactic                  | Technique                                                 | ID        | Evidence                                             |
| ----------------------- | --------------------------------------------------------- | --------- | ---------------------------------------------------- |
| Execution               | Command and Scripting Interpreter (Windows Command Shell) | T1059.003 | Use of `cmd.exe` to execute ping and delete commands |
| Defense Evasion         | Indicator Removal on Host                                 | T1070.004 | Self-deletion using `Del /f /q`                      |
| Defense Evasion         | System Checks                                             | T1497     | Ping to `1.1.1.1` used to verify network environment |
| Command and Control     | Application Layer Protocol: Web Protocols                 | T1071.001 | HTTP request to remote domain                        |
| Command and Control     | Ingress Tool Transfer                                     | T1105     | Download of payload (`favicon.ico`)                  |
| Execution               | User Execution (Indirect)                                 | T1204     | Execution of downloaded payload                      |
| Persistence / Execution | Create Process                                            | T1106     | Use of Windows API (`CreateProcessW`)                |

---

## 9. Conclusion

The dynamic analysis confirms that the malware:

* Communicates with a remote server over HTTP
* Downloads and writes a secondary payload to disk
* Executes the downloaded file
* Uses a simple anti-analysis technique (self-deletion based on connectivity check)

These behaviors are consistent with findings from static analysis and align with multiple MITRE ATT&CK techniques.

---

## 10. Next Steps

* Perform debugging using **x64dbg** to trace execution flow
* Analyze the dropped payload (`CR433101.dat.exe`)
* Expand lab setup (INetSim, FakeDNS) for deeper behavior analysis


