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
`sequence number + data length` seen so far. A data segment that starts below that
number is data that was already sent, i.e. a retransmission. Pure ACKs, SYNs and
TCP keep-alives are skipped, and the data length is worked out from the IP/TCP
header lengths so Ethernet padding is not mistaken for data.

* ERROR – one segment sent 4+ times (receiver not getting anything)
* WARNING – 5% or more of the flow's data segments retransmitted
* INFO – a few retransmissions, below 5%

## DNS (`checks/dns_queries.py`)

Queries are matched with answers using `(client IP, client port, server IP, transaction ID)`.
Repeated queries for the same name to the same server are grouped into one lookup.
Only port 53 is checked (multicast DNS and LLMNR are often unanswered on purpose).

* Unanswered – ERROR
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
| Time exceeded (not traceroute) – possible routing loop | WARNING |
| Time exceeded caused by traceroute probes (UDP 33434-33534) | INFO |

## Verifying against Wireshark

The sample captures were cross-checked with `tshark`, for example:

```bash
tshark -r captures/basic/tcp_retransmissions.pcap -Y "tcp.analysis.retransmission"
tshark -2 -r captures/basic/dns_failures.pcap -Y "dns.flags.response==0 && !dns.response_in"
```

and the frame numbers match the tool's report.
