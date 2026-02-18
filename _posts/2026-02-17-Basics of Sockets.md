---
title: Sockets UDP & TCP
author: siresire
date: 2026-02-17 06:10:00 +0800
categories: [Networking, Security Labs]
tags: [Basics,Wireshark,nc]
render_with_liquid: false
---

# UDP Sockets with Python – Simple Send & Receive Examples

This guide shows basic **UDP client** and **UDP server** implementations in Python, plus how to quickly test both directions using **netcat** (`nc`).

> **Important UDP facts**  
> • Connectionless — no handshake  
> • No guaranteed delivery  
> • No guaranteed order  
> • No flow control  
> • Best-effort datagram service

---

## 1. UDP Client – Send one message

```python
#!/usr/bin/env python3
import socket

# ────────────────────────────────────────────────
# SETTINGS
# ────────────────────────────────────────────────
TARGET_IP   = "127.0.0.1"
TARGET_PORT = 9191
MESSAGE     = b"Hello from UDP client!\n"

# ────────────────────────────────────────────────
# SOCKET + SEND
# ────────────────────────────────────────────────
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(MESSAGE, (TARGET_IP, TARGET_PORT))

sock.close()

print(f"Sent → {MESSAGE.decode().rstrip()!r}")
```

### Quick reference – socket flags

- `AF_INET`     → IPv4 addresses  
- `SOCK_DGRAM`  → UDP (datagram) mode  
- `sendto()`    → requires destination address on every call

---

## 2. Test the client using netcat (as receiver)

In one terminal, start a UDP listener:

```bash
nc -luv 9191
```

Then run the Python client script in another terminal.

→ The message should appear immediately in the `nc` window.

Flags explained:

- `-l`   listen  
- `-u`   UDP mode (very important!)  
- `-v`   verbose output

---

## 3. UDP Server – Receive messages in a loop

```python
#!/usr/bin/env python3
import socket

# ────────────────────────────────────────────────
# SETTINGS
# ────────────────────────────────────────────────
BIND_IP   = "127.0.0.1"     # or "0.0.0.0" to accept from anywhere
BIND_PORT = 9191

# ────────────────────────────────────────────────
# SERVER
# ────────────────────────────────────────────────
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Reserve the address/port
sock.bind((BIND_IP, BIND_PORT))

print(f"UDP server listening  {BIND_IP}:{BIND_PORT} …")

try:
    while True:
        data, addr = sock.recvfrom(1024)          # buffer size = 1024 bytes
        ip, port = addr

        try:
            text = data.decode(errors="replace").rstrip()
        except:
            text = f"[binary data – {len(data)} bytes]"

        print(f"[{ip}:{port}]  {text!r}")
except KeyboardInterrupt:
    print("\nServer stopped by user.")
finally:
    sock.close()
```

### Core concepts

- `bind()` is **required** on servers/receivers  
- `recvfrom()` returns **(data, sender_address)** tuple  
- Without `bind()` → usually no reliable way to receive on a known port

---

## 4. Test the server using netcat (as sender)

1. Start the Python server first  
2. In a second terminal run:

```bash
nc -u 127.0.0.1 9191
```

3. Type messages and press Enter — they should appear in the Python window.

> **Client-side note**  
> Normal UDP clients almost never call `bind()`  
> → OS automatically assigns a random high-numbered source port

---




# TCP Sockets with Python

> **TCP reminder**  
> TCP is connection-oriented: it does a handshake (`connect` / `accept`), guarantees delivery, and keeps order.

---

## TCP Server – Listen, accept one connection, receive once, print

```python
#!/usr/bin/env python3
import socket

ip = "127.0.0.1"
port = 9191

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ip, port))
s.listen(1)                     # allow 1 waiting connection

conn, addr = s.accept()         # blocks until a client connects
data = conn.recv(1024)          # receive up to 1024 bytes

print("Received:", data.decode().strip())

conn.close()
s.close()
```

**What happens here:**  
Server binds → listens → waits for exactly one client → receives one message → prints it → closes.

---

## TCP Client – Connect once, send one message

```python
#!/usr/bin/env python3
import socket

ip = "127.0.0.1"
port = 9191
data = b"Hello, TCP Server!\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))           # performs TCP handshake
s.sendall(data)                 # send all bytes (may send in multiple packets)
s.close()
```

**What happens here:**  
Client creates socket → connects (handshake) → sends message → closes.

---

## Quick test with netcat

### Option 1: Use `nc` as server, Python as client

First run (in one terminal):

```bash
nc -lv 9191
```

### Option 2: Use Python as server, `nc` as client

First run the Python server script (shown above).

Then in another terminal:

```bash
nc 127.0.0.1 9191
```


- `-l` = listen (server mode)  
- `-v` = verbose

---
