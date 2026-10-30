# How the checks work

The tool reads the capture once with Scapy (`loader.py`), numbering packets from 1
exactly like Wireshark. Each check then walks through the list of packets, keeps a
small dictionary of "conversations" it has seen, and at the end reports the
conversations that never finished properly.

## TCP Handshake (`checks/tcp_handshake.py`)

Key: `(client IP, client port, server IP, server port)`.

| Seen | Reported as | Severity |
|---|---|---|
| SYN ... SYN-ACK ... ACK | fine | – |
| SYN, then RST from the server | Connection refused | ERROR |
| SYN, then ICMP unreachable quoting that SYN | SYN rejected by router | ERROR |
| SYN (maybe repeated), nothing back | No response to SYN | ERROR |
| SYN, SYN-ACK, but no ACK from the client | Handshake not completed | WARNING |

If the only SYN/SYN-ACK was in the last 3 seconds of the capture, the severity drops
to INFO because the reply may not have been captured yet.

## TCP Retransmissions (`checks/tcp_retransmissions.py`)

For each direction of each connection the check remembers the highest
`sequence number + data length` seen so far. A data segment that starts below
that number is "old" data. Like Wireshark, it then decides why:

1. **Already acknowledged** – the receiver had ACKed this data → retransmission (spurious).
2. **Asked for again** – the receiver sent 2+ duplicate ACKs for exactly this data → retransmission (fast).
3. **Arrived within one round trip of newer data** → only *out of order* (the packets took
   different paths), not counted. The round trip time is measured from the connection's
   SYN to its first ACK (3 ms if the handshake was not captured).
4. Otherwise → retransmission.

A duplicate ACK only counts if the window size is unchanged (a changed window is
a "window update", not a request for data). Pure ACKs, SYNs, keep-alives and
Ethernet padding are ignored.

* ERROR – one segment sent 4+ times (receiver not getting anything)
* WARNING – at least 3 retransmissions and 5% or more of the flow's data segments
* INFO – anything less

## DNS (`checks/dns_queries.py`)

Queries are matched with answers using `(client IP, client port, server IP, transaction ID)`.
Repeated queries for the same name to the same server are grouped into one lookup.
Only port 53 is checked (multicast DNS and LLMNR are often unanswered on purpose).

* Unanswered – ERROR (INFO if another DNS server answered the same question: computers
  often ask the IPv4 and IPv6 DNS server at the same time and use the first answer)
* SERVFAIL / REFUSED / other error codes – WARNING
* NXDOMAIN – INFO (name does not exist, usually a typo)

## DHCP (`checks/dhcp_exchanges.py`)

All messages with the same transaction ID (`xid`) belong to one exchange.
A healthy exchange is DISCOVER → OFFER → REQUEST → ACK (or REQUEST → ACK for a lease renewal).

| Exchange | Reported as |
|---|---|
| DISCOVER, no OFFER | No DHCP server answered (ERROR) |
| OFFER, no REQUEST | Offer never requested (WARNING) |
| REQUEST, no ACK | Request never acknowledged (ERROR) |
| NAK | Server refused request (ERROR) |
| DECLINE | Client declined the offered address (ERROR) |
| DISCOVER then REQUEST, no OFFER seen | Offer not captured (INFO) – the client clearly got one |

Missing server replies are only an ERROR if the capture *should* have seen them:
either the client set the BOOTP broadcast flag, or the capture sees other frames
sent directly to that client. Otherwise (typical on Wi-Fi, where the router answers
other devices directly) the issue is INFO with a note.

## ARP Conflict (`checks/arp_conflicts.py`)

Every ARP request and reply says "IP X is at MAC Y". The check builds a table of
IP → set of MACs. Two or more MACs for one IP is a conflict. ARP probes (sender IP
0.0.0.0) that get answered by a different device are also reported.

## ICMP (`checks/icmp_unreachable.py`)

ICMP errors contain a copy of the start of the packet that failed. The check reads
that copy to report *who* could not reach *what*, and groups repeated errors.
Both IPv4 and IPv6 are supported.

| Message | Severity |
|---|---|
| Network / host unreachable, admin prohibited | ERROR |
| Port unreachable, fragmentation needed | WARNING |
| Port unreachable caused by a *late reply* (from a service port < 1024 back to a temporary port) | INFO, grouped per server |
| Time exceeded (not traceroute) – possible routing loop | WARNING |
| Time exceeded caused by traceroute probes (UDP 33434-33534) | INFO |

## Tested on my own network

A 108-second capture of my home Wi-Fi (44,000 packets: browsing, then Wi-Fi turned
off and on) was compared with Wireshark's TCP analysis:

| | Before tuning | After tuning |
|---|---|---|
| Data retransmissions Wireshark flags | 1,549 | 1,549 |
| Also flagged by this tool | 1,544 | 1,507 (97%) |
| Flagged by this tool only | 2,428 (all out-of-order packets) | 5 |
| Total issues in the report | 236 | 133 (22 errors, 28 warnings) |

The real capture exposed four false-alarm sources that synthetic captures did not:
out-of-order packets, duplicate ACKs that were really window updates, late DNS replies
rejected with "port unreachable", and DHCP replies sent directly to other Wi-Fi devices.
The remaining errors were real: DNS stopped answering while Wi-Fi was off, and the home
router does not answer DNS over TCP.

## Verifying against Wireshark

The sample captures were cross-checked with `tshark`, for example:

```bash
tshark -r captures/basic/tcp_retransmissions.pcap -Y "tcp.analysis.retransmission or tcp.analysis.fast_retransmission"
tshark -2 -r captures/basic/dns_failures.pcap -Y "dns.flags.response==0 && !dns.response_in"
```

and the frame numbers match the tool's report.
