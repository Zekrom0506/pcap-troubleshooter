# Packet Capture Troubleshooting Report

| | |
|---|---|
| **File** | `missing_route.pcapng` |
| **Packets** | 24 |
| **Captured** | 2026-10-28 10:00:00 → 2026-10-28 10:00:12 (12.1 s) |
| **Protocols** | TCP 3, UDP 2, DNS 2, DHCP 0, ARP 2, ICMP 17 |

## Summary

**5** errors, **0** warnings, **0** info

| Check | Result |
|---|---|
| TCP Handshake | 1 issue(s) |
| TCP Retransmissions | ✅ OK |
| DNS | 1 issue(s) |
| DHCP | ✅ OK |
| ARP Conflict | ✅ OK |
| ICMP | 3 issue(s) |

## Issues

### 1. 🔴 ERROR — ICMP

**Network unreachable: 10.0.12.2 reports 192.168.30.10**

- 10.0.12.2 sent 4 ICMP 'Network unreachable' message(s) about traffic from 192.168.10.10 to 192.168.30.10.
- Likely cause: a router has no route to the destination network (missing or wrong route).

Frames: 6, 8, 10, 12

```
frame.number in {6 8 10 12}
```

### 2. 🔴 ERROR — DNS

**Unanswered DNS query: A srv.lab.local. (server 192.168.30.53)**

- 192.168.10.10 asked DNS server 192.168.30.53 2 time(s) and never got an answer.
- Likely cause: the DNS server is down or unreachable, UDP port 53 is blocked, or the client is pointed at the wrong DNS server.

Frames: 13, 15

```
frame.number in {13 15}
```

### 3. 🔴 ERROR — ICMP

**Network unreachable: 10.0.12.2 reports 192.168.30.53:53/udp**

- 10.0.12.2 sent 2 ICMP 'Network unreachable' message(s) about traffic from 192.168.10.10 to 192.168.30.53:53/udp.
- Likely cause: a router has no route to the destination network (missing or wrong route).

Frames: 14, 16

```
frame.number in {14 16}
```

### 4. 🔴 ERROR — TCP Handshake

**SYN rejected by router 10.0.12.2: 192.168.10.10:41500 -> 192.168.30.10:80**

- The client sent 3 SYN packet(s); router 10.0.12.2 answered with 3 ICMP 'destination unreachable' message(s) instead of the server replying.
- See the matching ICMP issue for the exact reason (no route, ACL, host down).

Frames: 17, 18, 19, 20, 21, 22

```
frame.number in {17 18 19 20 21 22}
```

### 5. 🔴 ERROR — ICMP

**Network unreachable: 10.0.12.2 reports 192.168.30.10:80/tcp**

- 10.0.12.2 sent 3 ICMP 'Network unreachable' message(s) about traffic from 192.168.10.10 to 192.168.30.10:80/tcp.
- Likely cause: a router has no route to the destination network (missing or wrong route).

Frames: 18, 20, 22

```
frame.number in {18 20 22}
```
