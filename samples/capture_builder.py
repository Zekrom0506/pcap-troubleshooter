"""
Helpers for building realistic capture files with Scapy.

The sample generator uses these functions to write .pcap / .pcapng files that
contain both normal traffic and the failures we want the troubleshooter to find.
Each helper adds the packets of one small "conversation" to a CaptureBuilder.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, mac2str, wrpcap

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

# A fixed start time keeps the generated files identical on every run.
DEFAULT_START_TIME = 1793181600.0  # 28 Oct 2026, 10:00 UTC


class CaptureBuilder:
    """Collects packets with timestamps, then saves them to a file."""

    def __init__(self, start_time=DEFAULT_START_TIME):
        self.clock = start_time
        self.packets = []

    def add(self, packet, gap=0.001):
        """Add a packet `gap` seconds after the previous one."""
        self.clock = self.clock + gap
        packet.time = self.clock
        self.packets.append(packet)

    def wait(self, seconds):
        """Move the clock forward without adding a packet."""
        self.clock = self.clock + seconds

    def save(self, path):
        """Save as .pcapng if the name ends with .pcapng, otherwise as classic .pcap."""
        if path.endswith(".pcapng"):
            writer = PcapNgWriter(path)
            for packet in self.packets:
                writer.write(packet)
            writer.close()
        else:
            wrpcap(path, self.packets)


# ---------------------------------------------------------------- ARP

def arp_resolve(builder, asker_mac, asker_ip, target_mac, target_ip, answered=True):
    """Host asks 'who has target_ip?' and (optionally) gets an answer."""
    request = Ether(src=asker_mac, dst=BROADCAST_MAC) / ARP(
        op=1, hwsrc=asker_mac, psrc=asker_ip, hwdst=ZERO_MAC, pdst=target_ip)
    builder.add(request, gap=0.05)
    if answered:
        reply = Ether(src=target_mac, dst=asker_mac) / ARP(
            op=2, hwsrc=target_mac, psrc=target_ip, hwdst=asker_mac, pdst=asker_ip)
        builder.add(reply, gap=0.0005)


def gratuitous_arp(builder, mac, ip_address):
    """A host announcing 'ip_address is at mac' to everyone."""
    packet = Ether(src=mac, dst=BROADCAST_MAC) / ARP(
        op=2, hwsrc=mac, psrc=ip_address, hwdst=BROADCAST_MAC, pdst=ip_address)
    builder.add(packet, gap=0.2)


def arp_probe(builder, mac, ip_address):
    """A host checking whether ip_address is free (sender IP 0.0.0.0)."""
    packet = Ether(src=mac, dst=BROADCAST_MAC) / ARP(
        op=1, hwsrc=mac, psrc="0.0.0.0", hwdst=ZERO_MAC, pdst=ip_address)
    builder.add(packet, gap=0.1)


# ---------------------------------------------------------------- DHCP

def dhcp_message(kind, client_mac, xid, from_server=False, server_mac=None, server_ip=None,
                 offered_ip="0.0.0.0", requested_ip=None, extra_options=None, relay_ip="0.0.0.0"):
    """Build one DHCP packet."""
    options = [("message-type", kind)]
    if requested_ip is not None:
        options.append(("requested_addr", requested_ip))
    if from_server:
        options.append(("server_id", server_ip))
        options.append(("lease_time", 86400))
        options.append(("subnet_mask", "255.255.255.0"))
    if extra_options:
        options.extend(extra_options)
    options.append("end")

    if from_server:
        ethernet = Ether(src=server_mac, dst=BROADCAST_MAC)
        ip_layer = IP(src=server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, xid=xid, yiaddr=offered_ip, siaddr=server_ip,
                      giaddr=relay_ip, chaddr=mac2str(client_mac), flags=0x8000)
    else:
        ethernet = Ether(src=client_mac, dst=BROADCAST_MAC)
        ip_layer = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(op=1, xid=xid, chaddr=mac2str(client_mac), flags=0x8000)

    return ethernet / ip_layer / udp / bootp / DHCP(options=options)


def dhcp_full_exchange(builder, client_mac, xid, server_mac, server_ip, offered_ip, gateway_ip):
    """A normal, successful DISCOVER -> OFFER -> REQUEST -> ACK."""
    router_option = [("router", gateway_ip), ("name_server", gateway_ip)]
    builder.add(dhcp_message("discover", client_mac, xid), gap=0.3)
    builder.add(dhcp_message("offer", client_mac, xid, True, server_mac, server_ip, offered_ip,
                             extra_options=router_option), gap=0.004)
    builder.add(dhcp_message("request", client_mac, xid, requested_ip=offered_ip), gap=0.002)
    builder.add(dhcp_message("ack", client_mac, xid, True, server_mac, server_ip, offered_ip,
                             extra_options=router_option), gap=0.003)


# ---------------------------------------------------------------- DNS

def dns_lookup(builder, client_mac, client_ip, server_mac, server_ip, name, answer_ip,
               transaction_id, client_port, answered=True, rcode=0, retries=0, retry_gap=1.0):
    """A DNS A-record query and, optionally, its answer."""
    for attempt in range(retries + 1):
        query = (Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip)
                 / UDP(sport=client_port, dport=53)
                 / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=name, qtype="A")))
        gap = 0.05 if attempt == 0 else retry_gap
        builder.add(query, gap=gap)

    if not answered:
        return

    if rcode == 0:
        dns_answer = DNS(id=transaction_id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype="A"),
                         an=DNSRR(rrname=name, type="A", ttl=300, rdata=answer_ip))
    else:
        dns_answer = DNS(id=transaction_id, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype="A"))

    response = (Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip)
                / UDP(sport=53, dport=client_port) / dns_answer)
    builder.add(response, gap=0.012)


# ---------------------------------------------------------------- TCP

class TcpConversation:
    """
    Keeps track of sequence numbers for one TCP connection so the helper
    methods can produce correct-looking packets.
    """

    def __init__(self, builder, client_mac, client_ip, client_port,
                 server_mac, server_ip, server_port, client_isn=1000, server_isn=5000, ttl=64):
        self.builder = builder
        self.client_mac = client_mac
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_mac = server_mac
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_seq = client_isn
        self.server_seq = server_isn
        self.ttl = ttl

    def from_client(self, flags, payload=b"", seq=None, ack=None):
        ethernet = Ether(src=self.client_mac, dst=self.server_mac)
        ip_layer = IP(src=self.client_ip, dst=self.server_ip, ttl=self.ttl)
        tcp = TCP(sport=self.client_port, dport=self.server_port, flags=flags,
                  seq=self.client_seq if seq is None else seq,
                  ack=self.server_seq if ack is None else ack, window=64240)
        packet = ethernet / ip_layer / tcp
        if payload:
            packet = packet / Raw(load=payload)
        return packet

    def from_server(self, flags, payload=b"", seq=None, ack=None):
        ethernet = Ether(src=self.server_mac, dst=self.client_mac)
        ip_layer = IP(src=self.server_ip, dst=self.client_ip, ttl=self.ttl)
        tcp = TCP(sport=self.server_port, dport=self.client_port, flags=flags,
                  seq=self.server_seq if seq is None else seq,
                  ack=self.client_seq if ack is None else ack, window=65160)
        packet = ethernet / ip_layer / tcp
        if payload:
            packet = packet / Raw(load=payload)
        return packet

    def syn(self, gap=0.05):
        packet = self.from_client("S", ack=0)
        self.builder.add(packet, gap=gap)
        return packet

    def handshake(self, rtt=0.02):
        """SYN, SYN-ACK, ACK."""
        self.syn()
        self.client_seq = self.client_seq + 1
        self.builder.add(self.from_server("SA", seq=self.server_seq), gap=rtt / 2)
        self.server_seq = self.server_seq + 1
        self.builder.add(self.from_client("A"), gap=rtt / 2)

    def client_sends(self, data, gap=0.002):
        self.builder.add(self.from_client("PA", data), gap=gap)
        self.client_seq = self.client_seq + len(data)

    def server_sends(self, data, gap=0.002):
        self.builder.add(self.from_server("PA", data), gap=gap)
        self.server_seq = self.server_seq + len(data)

    def client_acks(self, gap=0.001):
        self.builder.add(self.from_client("A"), gap=gap)

    def server_acks(self, gap=0.001):
        self.builder.add(self.from_server("A"), gap=gap)

    def close(self, gap=0.01):
        """FIN from client, FIN from server, final ACK."""
        self.builder.add(self.from_client("FA"), gap=gap)
        self.client_seq = self.client_seq + 1
        self.builder.add(self.from_server("FA"), gap=0.01)
        self.server_seq = self.server_seq + 1
        self.builder.add(self.from_client("A"), gap=0.001)


def http_session(builder, client_mac, client_ip, client_port, server_mac, server_ip, server_port=80,
                 response_size=3000, ttl=64):
    """A complete, healthy HTTP request/response."""
    conversation = TcpConversation(builder, client_mac, client_ip, client_port,
                                   server_mac, server_ip, server_port, ttl=ttl,
                                   client_isn=client_port * 7, server_isn=client_port * 13)
    conversation.handshake()
    conversation.client_sends(b"GET / HTTP/1.1\r\nHost: " + server_ip.encode() + b"\r\n\r\n")
    conversation.server_acks()
    remaining = response_size
    first = True
    while remaining > 0:
        chunk = min(1400, remaining)
        if first:
            body = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * (chunk - 19)
            first = False
        else:
            body = b"x" * chunk
        conversation.server_sends(body)
        remaining = remaining - chunk
    conversation.client_acks()
    conversation.close()
    return conversation


# ---------------------------------------------------------------- ICMP

def ping(builder, src_mac, src_ip, dst_mac, dst_ip, sequence, ident=0x4242, answered=True, ttl=64):
    """ICMP echo request and (optionally) echo reply."""
    request = (Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, ttl=ttl)
               / ICMP(type=8, id=ident, seq=sequence) / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"))
    builder.add(request, gap=1.0 if sequence > 1 else 0.05)
    if answered:
        reply = (Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip, ttl=62)
                 / ICMP(type=0, id=ident, seq=sequence) / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"))
        builder.add(reply, gap=0.003)
    return request


def icmp_error_about(builder, router_mac, router_ip, victim_mac, victim_ip, original_packet,
                     icmp_type, icmp_code, gap=0.002):
    """
    A router sends an ICMP error back to the sender of original_packet.
    Like a real router, it quotes the original IP header plus the first 8 bytes after it.
    """
    # Turn the packet into bytes and back so fields like the header length get filled in.
    original_ip = IP(bytes(original_packet[IP]))
    quoted = bytes(original_ip)[:original_ip.ihl * 4 + 8]
    error = (Ether(src=router_mac, dst=victim_mac) / IP(src=router_ip, dst=victim_ip)
             / ICMP(type=icmp_type, code=icmp_code) / Raw(load=quoted))
    # Re-parse so Scapy shows the quoted packet as IPerror/TCPerror/UDPerror layers.
    error = Ether(bytes(error))
    builder.add(error, gap=gap)
