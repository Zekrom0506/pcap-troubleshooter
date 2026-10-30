# Routing Lab

The `captures/routing_lab/` files simulate faults on this three-router topology.
All captures are taken on PC1's switch port in LAN A (so traffic to LAN B is seen
going to / coming from R1's MAC address).

```
        LAN A 192.168.10.0/24                                                   LAN B 192.168.30.0/24
  +-----------------------------+                                         +------------------------------+
  | PC1  192.168.10.10 (static) |                                         | SRV   192.168.30.10 (web/ftp)|
  | PC2  DHCP                   |                                         | DNS   192.168.30.53          |
  | PC3  DHCP                   |                                         | DHCP  192.168.30.67          |
  +--------------+--------------+                                         +---------------+--------------+
                 |                                                                        |
           Gi0/0 .1                                                                 Gi0/0 .1
              [ R1 ]--- .1  10.0.12.0/30  .2 ---[ R2 ]--- .5  10.0.23.4/30  .6 ---[ R3 ]
                       (serial link)                     (serial link)
```

## Scenarios

### 1. Missing route — `missing_route.pcapng`
R2 has no route to 192.168.30.0/24 (static route typo / LAN B not advertised in OSPF).

Expected: R2 (10.0.12.2) sends **ICMP network unreachable** for pings, DNS and HTTP;
the DNS query to 192.168.30.53 is **unanswered**; the TCP SYN to the web server is
**rejected by router 10.0.12.2**.

Fix: `ip route 192.168.30.0 255.255.255.0 10.0.23.6` on R2 (or advertise LAN B in OSPF on R3).

### 2. DHCP relay missing — `dhcp_relay_missing.pcapng`
The DHCP server is on LAN B but R1's LAN A interface has no helper address, so DHCP
broadcasts never leave LAN A.

Expected: PC2 and PC3 each send four **DISCOVERs with no OFFER**; they fall back to 169.254.x.x.

Fix: `interface Gi0/0` → `ip helper-address 192.168.30.67` on R1.
`dhcp_relay_working.pcapng` is the same lab after the fix and produces a clean report.

### 3. ACL blocking SSH — `acl_blocking_ssh.pcapng`
An extended ACL on R3 permits HTTP to the server but denies TCP/22.

Expected: HTTP works; SSH SYNs get **ICMP communication administratively prohibited**
from R3 (10.0.23.6), and the handshake check reports **SYN rejected by router 10.0.23.6**.

### 4. Routing loop — `routing_loop.pcapng`
R2 routes 172.16.0.0/16 to R3, R3's default route points back to R2.

Expected: pings to 172.16.5.5 produce **TTL exceeded** from R2 (WARNING: possible loop).
A normal traceroute to the server in the same capture also produces TTL exceeded
messages, which the tool recognises as traceroute probes and only marks INFO.

### 5. Lossy WAN link — `lossy_wan_link.pcapng`
Errors on the R1–R2 serial link (clock rate mismatch) drop about one in eight segments
of an FTP download.

Expected: **TCP retransmissions** WARNING, 5 of 45 segments (11%).

### 6. Duplicate gateway IP — `duplicate_gateway_ip.pcapng`
A PC was configured with 192.168.10.1, the same address as R1's LAN interface.

Expected: **ARP conflict** for 192.168.10.1 (R1's MAC and the PC's MAC), and a
**connection refused** because PC1's web traffic briefly went to the wrong machine.

### 7. All working — `all_working.pcapng`
Everything fixed: DNS, HTTP and pings across the lab. The report is empty.
