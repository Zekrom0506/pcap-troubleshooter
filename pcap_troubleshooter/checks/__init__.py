"""
All the problem checks the tool knows about.

Each check is a module with:
    CHECK_NAME              - a short name shown in the report
    find_issues(frames, capture_end) - returns a list of Issue objects

To add a new check, write a module like the others and add it to ALL_CHECKS.
"""

from pcap_troubleshooter.checks import (
    tcp_handshake,
    tcp_retransmissions,
    dns_queries,
    dhcp_exchanges,
    arp_conflicts,
    icmp_unreachable,
)

ALL_CHECKS = [
    tcp_handshake,
    tcp_retransmissions,
    dns_queries,
    dhcp_exchanges,
    arp_conflicts,
    icmp_unreachable,
]
