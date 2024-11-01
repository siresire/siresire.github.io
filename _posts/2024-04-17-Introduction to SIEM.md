---
title: Introduction to SIEM
author: siresire
date: 2024-04-17 8:10:00 +0800
categories: []
tags: []
render_with_liquid: false
---
# Introduction
SIEM(Security Information and Event Management system) is a tool that collects data from various endpoints/network devices across the network, stores them at a centralized place, and performs correlation on them.

# Network Visibility through SIEM

Network log sources can be divided into two logical parts:

## Host-Centric Log Sources

These are log sources that capture events that occurred within or related to the host. Some log sources that generate host-centric logs are Windows Event logs, Sysmon, Osquery, etc. Some examples of host-centric logs are:

- A user accessing a file
- A user attempting to authenticate.
- A process Execution Activity
- A process adding/editing/deleting a registry key or value.
- Powershell execution

## Network-Centric Log Sources

Network-related logs are generated when the hosts communicate with each other or access the internet to visit a website. Some network-based protocols are SSH, VPN, HTTP/s, FTP, etc. Examples of such events are:

- SSH connection
- A file being accessed via FTP
- Web traffic
- A user accessing company's resources through VPN.
- Network file sharing Activity


![Alt text](/assets/img/tryhackme/siem/s1.png)

# Log Sources and Log Ingestion
Every device on the network creates logs for activities like website visits, SSH connections, and user logins. Common network devices include:

## Windows Machine
In Windows, `Event Viewer` shows all system activities with unique IDs for easy tracking. Just search `Event Viewer` to access logs. These logs are sent to SIEM for monitoring.

![Alt text](/assets/img/tryhackme/siem//s2.gif)

## Linux Workstation

Linux OS stores logs such as events, errors, warnings, etc. Which are then ingested into SIEM for continuous monitoring. Some of the common locations where Linux store logs are:

- /var/log/httpd : Contains HTTP Request  / Response and error logs.
- /var/log/cron   : Events related to cron jobs are stored in this location.
- /var/log/auth.log and /var/log/secure : Stores authentication related logs.
- /var/log/kern : This file stores kernel related events.

example
```logs
May 28 13:04:20 ebr crond[2843]: /usr/sbin/crond 4.4 dillon's cron daemon, started with loglevel notice
May 28 13:04:20 ebr crond[2843]: no timestamp found (user root job sys-hourly)
May 28 13:04:20 ebr crond[2843]: no timestamp found (user root job sys-daily)
May 28 13:04:20 ebr crond[2843]: no timestamp found (user root job sys-weekly)
May 28 13:04:20 ebr crond[2843]: no timestamp found (user root job sys-monthly)
Jun 13 07:46:22 ebr crond[3592]: unable to exec /usr/sbin/sendmail: cron output for user root job sys-daily to /dev/null
```

## Web Server

In Linux, it's crucial to monitor incoming and outgoing requests on the webserver for possible attacks. Apache-related logs are typically stored in /var/log/apache or /var/log/httpd.

example of Apache Logs:
```logs
192.168.21.200 - - [21/March/2022:10:17:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395
127.0.0.1 - - [21/March/2022:10:22:04 -0300] "GET / HTTP/1.0" 200 2216
```

## Log Ingestion

All these logs hold valuable data for spotting security problems. SIEM solutions have various ways to gather these logs. Here are some common methods:

1. Agent / Forwarder: These SIEM solutions provide a lightweight tool called an agent (forwarder by Splunk) that gets installed in the Endpoint. It is configured to capture all the important logs and send them to the SIEM server.
2. Syslog: Syslog is a widely used protocol to collect data from various systems like web servers, databases, etc., are sent real-time data to the centralized destination.
3. Manual Upload: Some SIEM solutions, like Splunk, ELK, etc., allow users to ingest offline data for quick analysis. Once the data is ingested, it is normalized and made available for analysis.
4. Port-Forwarding: SIEM solutions can also be configured to listen on a certain port, and then the endpoints forward the data to the SIEM instance on the listening port.

# Why SIEM

SIEM is used to provide correlation on the collected data to detect threats. Once a threat is detected, or a certain threshold is crossed, an alert is raised. This alert enables the analysts to take suitable actions based on the investigation. SIEM plays an important role in the Cyber Security domain and helps detect and protect against the latest threats in a timely manner. It provides good visibility of what's happening within the network infrastructure.

## SIEM Capabilities
1. Correlation between events from different log sources.
2. Provide visibility on both Host-centric and Network-centric activities.
3. Allow analysts to investigate the latest threats and timely responses.
4. Hunt for threats that are not detected by the rules in place.

![Alt text](/assets/img/tryhackme/siem/s3.png)

## SOC Analyst Responsibilities

SOC Analysts utilize SIEM solutions in order to have better visibility of what is happening within the network. Some of their responsibilities include:
1. Monitoring and Investigating.
2. Identifying False positives.
3. Tuning Rules which are causing the noise or False positives.
4. Reporting and Compliance.
5. Identifying blind spots in the network visibility and covering them.


# Analysing Logs and Alerts

SIEM tool gets all the security-related logs ingested through agents, port forwarding, etc. Once the logs are ingested, SIEM looks for unwanted behavior or suspicious pattern within the logs with the help of the conditions set in the rules by the analysts. If the condition is met, a rule gets triggered, and the incident is investigated.

## Dashboard

Dashboards are the most important components of any SIEM. SIEM presents the data for analysis after being normalized and ingested. The summary of these analyses is presented in the form of actionable insights with the help of multiple dashboards. Each SIEM solution comes with some default dashboards and provides an option for custom Dashboard creation. Some of the information that can be found in a dashboard are:
- Alert Highlights
- System Notification
- Health Alert
- List of Failed Login Attempts
- Events Ingested Count
- Rules triggered
- Top Domains Visited


## Correlation Rules

Correlation rules play an important role in the timely detection of threats allowing analysts to take action on time. Correlation rules are pretty much logical expressions set to be triggered. A few examples of correlation rules are:
- If a User gets 5 failed Login Attempts in 10 seconds - Raise an alert for Multiple Failed Login Attempts
- If login is successful after multiple failed login attempts - Raise an alert for Successful Login After multiple Login Attempts
- A rule is set to alert every time a user plugs in a USB (Useful if USB is restricted as per the company policy)
- If outbound traffic is > 25 MB - Raise an alert to potential Data exfiltration Attempt (Usually, it depends on the company policy)

## How a correlation rule is created

Use-Case 1: Adversaries tend to remove the logs during the post-exploitation phase to remove their tracks. A unique Event ID 104 is logged every time a user tries to remove or clear event logs. To create a rule based on this activity, we can set the condition as follows:

Rule: If the Log source is WinEventLog AND EventID is 104 - Trigger an alert `Event Log Cleared`

Use-Case 2: Adversaries use commands like whoami after the exploitation/privilege escalation phase. The following Fields will be helpful to include in the rule.

1. Log source: Identify the log source capturing the event logs
2. Event ID: which Event ID is associated with Process Execution activity? In this case, event id 4688 will be helpful.
3. NewProcessName: which process name will be helpful to include in the rule?

Rule: If Log Source is WinEventLog AND EventCode is 4688, and NewProcessName contains whoami, then Trigger an ALERT `WHOAMI command Execution DETECTED`

## Alert Investigation

 Once an alert is triggered in the dashboard, the events/flows associated with the alert are examined, and the rule is checked to see which conditions are met. Based on the investigation, the analyst determines if it's a True or False positive. Some of the actions that are performed after the analysis are:
1. Alert is False Alarm. It may require tuning the rule to avoid similar False positives from occurring again.
2. Alert is True Positive. Perform further investigation.
3. Contact the asset owner to inquire about the activity.
4. Suspicious activity is confirmed. Isolate the infected host
5. Block the suspicious IP.