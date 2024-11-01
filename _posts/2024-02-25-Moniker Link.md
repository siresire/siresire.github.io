---
title: Moniker Link
author: siresire
date: 2024-02-25 14:10:00 +0800
categories: [CVE]
tags: [CVE-2024-21413,NTLM]
render_with_liquid: false
---


# Introduction
On February 13th, 2024, Microsoft announced a Microsoft Outlook RCE & credential leak vulnerability with the assigned CVE of [CVE-2024-21413](https://www.cve.org/CVERecord?id=CVE-2024-21413)(Moniker Link). Haifei Li of Check Point Research is credited with [discovering the vulnerability](https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/).

The vulnerability bypasses Outlook's security mechanisms when handing a specific type of hyperlink known as a Moniker Link. An attacker can abuse this by sending an email that contains a malicious Moniker Link to a victim, resulting in Outlook sending the user's NTLM credentials to the attacker once the hyperlink is clicked.

# Moniker Link (CVE-2024-21413)

Outlook can render emails as HTML. You may notice this being used by your favourite newsletters. Additionally, Outlook can parse hyperlinks such as HTTP and HTTPS. However, it can also open URLs specifying applications known as [Moniker Links](https://learn.microsoft.com/en-us/windows/win32/com/url-monikers ). Normally, Outlook will prompt a security warning when external applications are triggered.


> TO be continued ..