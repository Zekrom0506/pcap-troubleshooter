"""
Small helper functions shared by several checks.
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


# How close to the end of the capture something must be before we say
# "maybe the answer just was not captured yet".
END_OF_CAPTURE_GRACE_SECONDS = 3.0

# TCP flag bits.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def get_ip_addresses(packet):
    """
    Return (source_ip, destination_ip) for an IPv4 or IPv6 packet.
    Return None if the packet has no IP layer.
    """
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return None


def tcp_flags_value(packet):
    """Return the TCP flags of a packet as a plain integer."""
    return int(packet[TCP].flags)


def has_flag(flags_value, flag):
    """True if the given flag bit is set in flags_value."""
    return (flags_value & flag) != 0


def tcp_payload_length(packet):
    """
    Return how many bytes of data a TCP segment carries.

    We work this out from the IP and TCP header length fields instead of
    measuring the payload, because Ethernet adds padding bytes to very
    small frames and those padding bytes are not real TCP data.
    """
    tcp_header_length = packet[TCP].dataofs * 4

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_header_length = ip_layer.ihl * 4
        payload_length = ip_layer.len - ip_header_length - tcp_header_length
    elif packet.haslayer(IPv6):
        # IPv6 "plen" counts everything after the fixed 40 byte header.
        # (This ignores IPv6 extension headers, which are rare for TCP.)
        payload_length = packet[IPv6].plen - tcp_header_length
    else:
        payload_length = 0

    if payload_length < 0:
        payload_length = 0
    return payload_length


def format_endpoint(ip_address, port):
    """Turn an address and port into text like 10.0.0.5:443 or [fe80::1]:443."""
    if ":" in ip_address:
        return "[" + ip_address + "]:" + str(port)
    return ip_address + ":" + str(port)


def near_capture_end(event_time, capture_end):
    """True if event_time is within a few seconds of the end of the capture."""
    seconds_left = capture_end - event_time
    return seconds_left < END_OF_CAPTURE_GRACE_SECONDS


def frame_numbers_of(frames):
    """Turn a list of Frame objects into a list of their frame numbers."""
    numbers = []
    for frame in frames:
        numbers.append(frame.number)
    return numbers
