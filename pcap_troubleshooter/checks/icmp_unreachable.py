"""
Check: ICMP "destination unreachable" (and "time exceeded") messages.

When a router or host cannot deliver a packet, it often sends an ICMP message
back to the sender explaining why. Inside that ICMP message is a copy of the
start of the original packet, so we can tell exactly which traffic failed.

ICMP type 3 (IPv4) / ICMPv6 type 1 - Destination Unreachable
ICMP type 11 (IPv4) / ICMPv6 type 3 - Time Exceeded (TTL reached zero:
    normal during traceroute, otherwise a hint of a routing loop)
"""

from scapy.layers.inet import ICMP, IPerror, TCPerror, UDPerror
from scapy.layers.inet6 import (ICMPv6DestUnreach, ICMPv6TimeExceeded,
                                IPerror6, TCPerror as TCPerror6, UDPerror as UDPerror6)

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR, WARNING, INFO

CHECK_NAME = "ICMP"

ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11

# code -> (name, likely cause, severity)
IPV4_UNREACHABLE_CODES = {
    0: ("Network unreachable", "a router has no route to the destination network (missing or wrong route)", ERROR),
    1: ("Host unreachable", "the last router could not reach the host (host down, or no ARP reply on the last hop)", ERROR),
    2: ("Protocol unreachable", "the destination does not support that IP protocol", WARNING),
    3: ("Port unreachable", "nothing is listening on that UDP port at the destination", WARNING),
    4: ("Fragmentation needed", "the packet is too big for a link on the path and has DF set (MTU problem)", WARNING),
    5: ("Source route failed", "a source-routed path could not be followed", WARNING),
    6: ("Destination network unknown", "the destination network is unknown to the router", ERROR),
    7: ("Destination host unknown", "the destination host is unknown", ERROR),
    9: ("Network administratively prohibited", "a firewall or ACL is blocking traffic to that network", ERROR),
    10: ("Host administratively prohibited", "a firewall or ACL is blocking traffic to that host", ERROR),
    13: ("Communication administratively prohibited", "a firewall or ACL on a router is blocking this traffic", ERROR),
}

IPV6_UNREACHABLE_CODES = {
    0: ("No route to destination", "a router has no route to the destination", ERROR),
    1: ("Administratively prohibited", "a firewall or ACL is blocking this traffic", ERROR),
    3: ("Address unreachable", "the last router could not reach the host (no neighbor discovery reply)", ERROR),
    4: ("Port unreachable", "nothing is listening on that UDP port at the destination", WARNING),
    5: ("Source address failed policy", "ingress/egress policy rejected the source address", ERROR),
    6: ("Reject route", "the router has a reject route for this destination", ERROR),
}

# Traceroute (Linux/macOS) sends UDP probes to ports starting here.
TRACEROUTE_FIRST_PORT = 33434
TRACEROUTE_LAST_PORT = 33534


class IcmpGroup:
    """All ICMP messages with the same sender, kind and original destination."""

    def __init__(self, reporter, kind_name, cause, severity, original_source, original_target, is_time_exceeded):
        self.reporter = reporter                  # router/host that sent the ICMP
        self.kind_name = kind_name
        self.cause = cause
        self.severity = severity
        self.original_source = original_source    # who sent the packet that failed
        self.original_target = original_target    # where that packet was going
        self.is_time_exceeded = is_time_exceeded
        self.frames = []
        self.looks_like_traceroute = True


def describe_original_packet(packet, is_ipv6):
    """
    Look inside the ICMP message at the copy of the original packet.
    Return (original source ip, original destination ip, "target text", destination port or None).
    """
    if is_ipv6:
        inner_ip_class, inner_tcp_class, inner_udp_class = IPerror6, TCPerror6, UDPerror6
    else:
        inner_ip_class, inner_tcp_class, inner_udp_class = IPerror, TCPerror, UDPerror

    if not packet.haslayer(inner_ip_class):
        return "?", "?", "unknown destination", None

    inner_ip = packet[inner_ip_class]
    target = inner_ip.dst
    port = None

    if packet.haslayer(inner_tcp_class):
        port = int(packet[inner_tcp_class].dport)
        target = helpers.format_endpoint(inner_ip.dst, port) + "/tcp"
    elif packet.haslayer(inner_udp_class):
        port = int(packet[inner_udp_class].dport)
        target = helpers.format_endpoint(inner_ip.dst, port) + "/udp"

    return inner_ip.src, inner_ip.dst, target, port


def classify(packet):
    """
    Work out what kind of ICMP error this packet is.
    Returns (kind_name, cause, severity, is_time_exceeded, is_ipv6) or None.
    """
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        if icmp.type == ICMP_DEST_UNREACHABLE:
            code = int(icmp.code)
            default = ("Destination unreachable (code " + str(code) + ")", "the destination could not be reached", ERROR)
            name, cause, severity = IPV4_UNREACHABLE_CODES.get(code, default)
            return name, cause, severity, False, False
        if icmp.type == ICMP_TIME_EXCEEDED:
            return "TTL exceeded in transit", "", WARNING, True, False
        return None

    if packet.haslayer(ICMPv6DestUnreach):
        code = int(packet[ICMPv6DestUnreach].code)
        default = ("Destination unreachable (code " + str(code) + ")", "the destination could not be reached", ERROR)
        name, cause, severity = IPV6_UNREACHABLE_CODES.get(code, default)
        return name, cause, severity, False, True

    if packet.haslayer(ICMPv6TimeExceeded):
        return "Hop limit exceeded in transit", "", WARNING, True, True

    return None


def find_issues(frames, capture_end):
    """Return one Issue per group of related ICMP error messages."""
    groups = {}

    for frame in frames:
        packet = frame.packet
        result = classify(packet)
        if result is None:
            continue
        kind_name, cause, severity, is_time_exceeded, is_ipv6 = result

        addresses = helpers.get_ip_addresses(packet)
        if addresses is None:
            continue
        reporter = addresses[0]

        original_source, original_host, original_target, port = describe_original_packet(packet, is_ipv6)

        if is_time_exceeded:
            # For TTL problems group by destination host only, not by port,
            # because traceroute uses a different port for every probe.
            original_target = original_host

        key = (reporter, kind_name, original_source, original_target)

        group = groups.get(key)
        if group is None:
            group = IcmpGroup(reporter, kind_name, cause, severity,
                              original_source, original_target, is_time_exceeded)
            groups[key] = group
        group.frames.append(frame)

        if port is None or port < TRACEROUTE_FIRST_PORT or port > TRACEROUTE_LAST_PORT:
            group.looks_like_traceroute = False

    issues = []
    for group in groups.values():
        count = len(group.frames)
        severity = group.severity

        if group.is_time_exceeded:
            if group.looks_like_traceroute:
                severity = INFO
                cause = ("these look like traceroute probes, which expire on purpose."
                         " No action needed.")
            else:
                cause = ("packets ran out of hops before arriving. This usually means a routing"
                         " loop (two routers pointing at each other) or a very low TTL.")
            summary = group.kind_name + ": " + group.reporter + " dropped traffic to " + group.original_target
        else:
            cause = group.cause + "."
            summary = group.kind_name + ": " + group.reporter + " reports " + group.original_target

        details = [
            group.reporter + " sent " + str(count) + " ICMP '" + group.kind_name + "' message(s)"
            + " about traffic from " + group.original_source + " to " + group.original_target + ".",
            "Likely cause: " + cause,
        ]

        issues.append(Issue(
            check=CHECK_NAME,
            severity=severity,
            summary=summary,
            details=details,
            frame_numbers=helpers.frame_numbers_of(group.frames),
        ))

    return issues
