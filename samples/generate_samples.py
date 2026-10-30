"""
Generates the sample capture files used to test the troubleshooter.

    python samples/generate_samples.py

Two sets of captures are written:

  captures/basic/        one file per problem type, on a home-style network
  captures/routing_lab/  failures simulated on the 3-router lab topology
                         (see docs/routing_lab.md for the diagram)

Every file also contains normal, healthy traffic around the failure so the
tool has to pick the problem out of the noise, like on a real network.
"""

import os
import sys

# Allow "python samples/generate_samples.py" from the project root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

import capture_builder as cb  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASIC_DIR = os.path.join(PROJECT_ROOT, "captures", "basic")
LAB_DIR = os.path.join(PROJECT_ROOT, "captures", "routing_lab")


# ======================================================================
#  Home network used by the "basic" captures
# ======================================================================

HOME_ROUTER_MAC = "f4:92:bf:10:00:01"
HOME_ROUTER_IP = "192.168.1.1"      # also the DHCP and DNS server
LAPTOP_MAC = "3c:22:fb:aa:00:23"
LAPTOP_IP = "192.168.1.23"
PHONE_MAC = "a4:83:e7:bb:00:31"
PHONE_IP = "192.168.1.31"
NAS_MAC = "00:11:32:cc:00:20"
NAS_IP = "192.168.1.20"
PRINTER_MAC = "00:1b:a9:dd:00:50"
TV_MAC = "70:2a:d5:ee:00:50"

WEB_SERVER_IP = "93.184.215.14"
CDN_SERVER_IP = "151.101.1.140"


def add_background_traffic(builder, port_base=50000):
    """Normal home traffic: ARP for the gateway, a DNS lookup, a web page, a ping."""
    cb.arp_resolve(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP)
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "example.com.", WEB_SERVER_IP, transaction_id=port_base % 65535, client_port=port_base)
    cb.http_session(builder, LAPTOP_MAC, LAPTOP_IP, port_base + 1, HOME_ROUTER_MAC, WEB_SERVER_IP)
    cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=1)


def make_healthy_home_network():
    builder = cb.CaptureBuilder()
    cb.dhcp_full_exchange(builder, LAPTOP_MAC, 0x1a2b3c4d, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                          LAPTOP_IP, HOME_ROUTER_IP)
    cb.gratuitous_arp(builder, LAPTOP_MAC, LAPTOP_IP)
    add_background_traffic(builder, 50000)
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "fastly.net.", CDN_SERVER_IP, transaction_id=0x2222, client_port=50100)
    cb.http_session(builder, LAPTOP_MAC, LAPTOP_IP, 50101, HOME_ROUTER_MAC, CDN_SERVER_IP, response_size=9000)
    cb.arp_resolve(builder, PHONE_MAC, PHONE_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP)
    for sequence in range(2, 5):
        cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=sequence)
    builder.wait(5)
    cb.ping(builder, PHONE_MAC, PHONE_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=1, ident=7)
    builder.save(os.path.join(BASIC_DIR, "healthy_home_network.pcap"))


def make_tcp_handshake_failures():
    builder = cb.CaptureBuilder()
    add_background_traffic(builder, 51000)

    # 1. No answer at all: client retries SYN with exponential back-off (1s, 2s, 4s).
    silent = cb.TcpConversation(builder, LAPTOP_MAC, LAPTOP_IP, 51200, HOME_ROUTER_MAC, "203.0.113.50", 443)
    silent.syn()
    for backoff in [1.0, 2.0, 4.0]:
        silent.syn(gap=backoff)

    # 2. Port closed: the NAS answers the SYN with RST.
    refused = cb.TcpConversation(builder, LAPTOP_MAC, LAPTOP_IP, 51201, NAS_MAC, NAS_IP, 8080)
    refused.syn()
    builder.add(refused.from_server("RA", seq=0, ack=refused.client_seq + 1), gap=0.0008)

    # 3. SYN-ACK comes back but the client never completes the handshake;
    #    the server re-sends its SYN-ACK twice.
    half_open = cb.TcpConversation(builder, LAPTOP_MAC, LAPTOP_IP, 51202, HOME_ROUTER_MAC, "198.51.100.7", 22)
    half_open.syn()
    for gap in [0.03, 1.0, 2.0]:
        builder.add(half_open.from_server("SA", ack=half_open.client_seq + 1), gap=gap)

    # More normal traffic afterwards, so nothing above is "at the end of the capture".
    builder.wait(3)
    cb.http_session(builder, LAPTOP_MAC, LAPTOP_IP, 51300, HOME_ROUTER_MAC, CDN_SERVER_IP)
    builder.save(os.path.join(BASIC_DIR, "tcp_handshake_failures.pcap"))


def make_tcp_retransmissions():
    builder = cb.CaptureBuilder()
    add_background_traffic(builder, 52000)

    # File download where segments 5 and 12 are lost and sent again.
    download = cb.TcpConversation(builder, LAPTOP_MAC, LAPTOP_IP, 52100, HOME_ROUTER_MAC, CDN_SERVER_IP, 443,
                                  client_isn=700000, server_isn=900000)
    download.handshake()
    download.client_sends(b"\x16\x03\x01" + b"C" * 300)  # looks like a TLS ClientHello
    download.server_acks()

    segment_size = 1400
    lost_segments = [5, 12]
    for number in range(1, 21):
        start_seq = download.server_seq
        data = bytes([65 + number % 26]) * segment_size
        download.server_sends(data, gap=0.004)
        if number in lost_segments:
            # The client never got this one: it keeps ACKing the old number (duplicate ACKs)
            # until the server re-sends it.
            lost_seq = start_seq
            for _ in range(3):
                builder.add(download.from_client("A", ack=lost_seq), gap=0.002)
            builder.add(download.from_server("PA", data, seq=lost_seq), gap=0.02)
        if number % 2 == 0:
            download.client_acks()
    download.close()

    # A second connection to the NAS where one segment has to be sent five times.
    stuck = cb.TcpConversation(builder, LAPTOP_MAC, LAPTOP_IP, 52200, NAS_MAC, NAS_IP, 445,
                               client_isn=3000, server_isn=8000)
    stuck.handshake(rtt=0.002)
    stuck_seq = stuck.client_seq
    stuck_data = b"SMB" + b"\x00" * 1000
    stuck.client_sends(stuck_data)
    for backoff in [0.2, 0.4, 0.8, 1.6]:
        builder.add(stuck.from_client("PA", stuck_data, seq=stuck_seq), gap=backoff)
    builder.add(stuck.from_client("RA"), gap=3.2)

    builder.wait(2)
    cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=2)
    builder.wait(4)
    cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=3)
    builder.save(os.path.join(BASIC_DIR, "tcp_retransmissions.pcap"))


def make_dns_failures():
    builder = cb.CaptureBuilder()
    add_background_traffic(builder, 53000)

    # Unanswered, retried twice, to the home router.
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "intranet.example.org.", None, transaction_id=0x5001, client_port=53101,
                  answered=False, retries=2)
    # Unanswered, to a public resolver (UDP 53 blocked upstream).
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, "8.8.8.8",
                  "github.com.", None, transaction_id=0x5002, client_port=53102,
                  answered=False, retries=1, retry_gap=2.0)
    # Answered with NXDOMAIN (typo).
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "gooogle.cmo.", None, transaction_id=0x5003, client_port=53103, rcode=3)
    # Answered with SERVFAIL.
    cb.dns_lookup(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "broken-dnssec.example.", None, transaction_id=0x5004, client_port=53104, rcode=2)
    # A normal answered lookup from the phone.
    cb.dns_lookup(builder, PHONE_MAC, PHONE_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP,
                  "wikipedia.org.", "185.15.59.224", transaction_id=0x5005, client_port=53105)

    builder.wait(5)
    cb.http_session(builder, LAPTOP_MAC, LAPTOP_IP, 53200, HOME_ROUTER_MAC, WEB_SERVER_IP)
    builder.save(os.path.join(BASIC_DIR, "dns_failures.pcap"))


def make_dhcp_failures():
    builder = cb.CaptureBuilder()
    server_mac, server_ip = HOME_ROUTER_MAC, HOME_ROUTER_IP

    # Normal full exchange for the laptop.
    cb.dhcp_full_exchange(builder, LAPTOP_MAC, 0x11110001, server_mac, server_ip, LAPTOP_IP, HOME_ROUTER_IP)

    # Smart plug: four DISCOVERs, no OFFER.
    plug_mac = "50:02:91:ab:cd:01"
    for gap in [0.5, 4.0, 8.0, 16.0]:
        builder.add(cb.dhcp_message("discover", plug_mac, 0x22220002), gap=gap)

    # Phone: gets an OFFER but never sends a REQUEST (offer lost on the way back over Wi-Fi).
    builder.add(cb.dhcp_message("discover", PHONE_MAC, 0x33330003), gap=0.4)
    builder.add(cb.dhcp_message("offer", PHONE_MAC, 0x33330003, True, server_mac, server_ip, PHONE_IP), gap=0.004)

    # Tablet renewing its lease: REQUEST twice, no ACK.
    tablet_mac = "d0:81:7a:12:34:56"
    for gap in [0.6, 2.0]:
        builder.add(cb.dhcp_message("request", tablet_mac, 0x44440004, requested_ip="192.168.1.44"), gap=gap)

    # Visitor laptop asking for an address from its office network: NAK.
    visitor_mac = "8c:85:90:77:66:55"
    builder.add(cb.dhcp_message("request", visitor_mac, 0x55550005, requested_ip="10.20.30.40"), gap=0.5)
    builder.add(cb.dhcp_message("nak", visitor_mac, 0x55550005, True, server_mac, server_ip), gap=0.003)
    # ...after which it starts over and succeeds.
    cb.dhcp_full_exchange(builder, visitor_mac, 0x55550006, server_mac, server_ip, "192.168.1.60", HOME_ROUTER_IP)

    builder.wait(4)
    add_background_traffic(builder, 54000)
    builder.save(os.path.join(BASIC_DIR, "dhcp_failures.pcap"))


def make_arp_conflict():
    builder = cb.CaptureBuilder()
    add_background_traffic(builder, 55000)

    # Printer has a static IP of .50 ...
    cb.gratuitous_arp(builder, PRINTER_MAC, "192.168.1.50")
    cb.arp_resolve(builder, LAPTOP_MAC, LAPTOP_IP, PRINTER_MAC, "192.168.1.50")
    # ... and the smart TV was given .50 too. Both answer the laptop's ARP request.
    builder.add(Ether(src=TV_MAC, dst=LAPTOP_MAC) / cb.ARP(
        op=2, hwsrc=TV_MAC, psrc="192.168.1.50", hwdst=LAPTOP_MAC, pdst=LAPTOP_IP), gap=0.0004)
    cb.gratuitous_arp(builder, TV_MAC, "192.168.1.50")

    # The phone probes .77 before using it, and the NAS says "that's mine".
    cb.arp_probe(builder, PHONE_MAC, "192.168.1.77")
    builder.add(Ether(src=NAS_MAC, dst=PHONE_MAC) / cb.ARP(
        op=2, hwsrc=NAS_MAC, psrc="192.168.1.77", hwdst=PHONE_MAC, pdst="0.0.0.0"), gap=0.001)

    builder.wait(2)
    cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, HOME_ROUTER_IP, sequence=5)
    builder.save(os.path.join(BASIC_DIR, "arp_conflict.pcap"))


def make_icmp_unreachable():
    builder = cb.CaptureBuilder()
    add_background_traffic(builder, 56000)

    # SNMP query to the NAS on a port nothing listens on -> port unreachable.
    snmp = (Ether(src=LAPTOP_MAC, dst=NAS_MAC) / IP(src=LAPTOP_IP, dst=NAS_IP)
            / UDP(sport=56100, dport=161) / Raw(load=b"0)\x02\x01\x01\x04\x06public"))
    for gap in [0.1, 1.0]:
        builder.add(snmp.copy(), gap=gap)
        cb.icmp_error_about(builder, NAS_MAC, NAS_IP, LAPTOP_MAC, LAPTOP_IP, snmp, 3, 3)

    # Ping to a device that is switched off -> router says host unreachable.
    for sequence in [1, 2, 3]:
        request = cb.ping(builder, LAPTOP_MAC, LAPTOP_IP, HOME_ROUTER_MAC, "192.168.1.99",
                          sequence=sequence, answered=False)
        cb.icmp_error_about(builder, HOME_ROUTER_MAC, HOME_ROUTER_IP, LAPTOP_MAC, LAPTOP_IP,
                            request, 3, 1, gap=3.0)

    # Large packet with Don't Fragment over a VPN link -> fragmentation needed.
    big = (Ether(src=LAPTOP_MAC, dst=HOME_ROUTER_MAC) / IP(src=LAPTOP_IP, dst="172.16.40.10", flags="DF")
           / TCP(sport=56200, dport=443, flags="PA", seq=1, ack=1) / Raw(load=b"z" * 1460))
    builder.add(big, gap=0.2)
    cb.icmp_error_about(builder, HOME_ROUTER_MAC, HOME_ROUTER_IP, LAPTOP_MAC, LAPTOP_IP, big, 3, 4)

    builder.wait(3)
    cb.http_session(builder, LAPTOP_MAC, LAPTOP_IP, 56300, HOME_ROUTER_MAC, WEB_SERVER_IP)
    builder.save(os.path.join(BASIC_DIR, "icmp_unreachable.pcap"))


# ======================================================================
#  Routing lab (3 routers). Captured on the LAN A switch port of PC1.
#
#   LAN A 192.168.10.0/24      10.0.12.0/30       10.0.23.0/30      LAN B 192.168.30.0/24
#   PC1 .10  PC2 (DHCP)  -- R1 .1 ==== .2 R2 .5 ==== .6 R3 .1 --  SRV .10  DNS .53  DHCP .67
# ======================================================================

R1_LAN_MAC = "0c:ab:01:00:00:01"
R1_LAN_IP = "192.168.10.1"
R2_IP = "10.0.12.2"
R3_IP = "10.0.23.6"
PC1_MAC = "0c:aa:10:00:00:10"
PC1_IP = "192.168.10.10"
PC2_MAC = "0c:aa:10:00:00:20"
PC3_MAC = "0c:aa:10:00:00:30"
LAB_SERVER_IP = "192.168.30.10"
LAB_DNS_IP = "192.168.30.53"
LAB_DHCP_IP = "192.168.30.67"


def lab_background(builder, port_base):
    """PC1 resolves its gateway and pings it - always works because it is local."""
    cb.arp_resolve(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP, sequence=1, ident=port_base % 65535)


def make_lab_missing_route():
    """
    R2 is missing its route to 192.168.30.0/24 (static route typo / OSPF not
    advertising LAN B). Everything from LAN A to LAN B dies at R2.
    """
    builder = cb.CaptureBuilder()
    lab_background(builder, 1)

    # Ping server: R2 answers "network unreachable".
    for sequence in [1, 2, 3, 4]:
        request = cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, LAB_SERVER_IP,
                          sequence=sequence, answered=False, ident=0x0101)
        cb.icmp_error_about(builder, R1_LAN_MAC, R2_IP, PC1_MAC, PC1_IP, request, 3, 0, gap=0.004)

    # DNS query to the lab DNS server on LAN B: unreachable and unanswered.
    query = (Ether(src=PC1_MAC, dst=R1_LAN_MAC) / IP(src=PC1_IP, dst=LAB_DNS_IP)
             / UDP(sport=41000, dport=53) / cb.DNS(id=0x0b0b, rd=1, qd=cb.DNSQR(qname="srv.lab.local.")))
    builder.add(query, gap=0.5)
    cb.icmp_error_about(builder, R1_LAN_MAC, R2_IP, PC1_MAC, PC1_IP, query, 3, 0, gap=0.004)
    builder.add(query.copy(), gap=1.0)
    cb.icmp_error_about(builder, R1_LAN_MAC, R2_IP, PC1_MAC, PC1_IP, query, 3, 0, gap=0.004)

    # Web connection to the server: SYN gets network unreachable, client keeps retrying.
    web = cb.TcpConversation(builder, PC1_MAC, PC1_IP, 41500, R1_LAN_MAC, LAB_SERVER_IP, 80)
    for gap in [0.5, 1.0, 2.0]:
        syn = web.syn(gap=gap)
        cb.icmp_error_about(builder, R1_LAN_MAC, R2_IP, PC1_MAC, PC1_IP, syn, 3, 0, gap=0.004)

    builder.wait(3)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP, sequence=2, ident=1)
    builder.save(os.path.join(LAB_DIR, "missing_route.pcapng"))


def make_lab_dhcp_relay_missing():
    """
    The DHCP server lives on LAN B, but R1's LAN A interface has no
    'ip helper-address 192.168.30.67', so broadcasts never leave LAN A.
    PC2 and PC3 never get addresses; PC1 has a static IP and works.
    """
    builder = cb.CaptureBuilder()
    lab_background(builder, 2)

    for gap in [0.2, 4.0, 8.0, 16.0]:
        builder.add(cb.dhcp_message("discover", PC2_MAC, 0x0c0c0002), gap=gap)
        builder.add(cb.dhcp_message("discover", PC3_MAC, 0x0c0c0003), gap=0.7)

    # The PCs fall back to link-local (169.254.x.x) and announce it.
    cb.arp_probe(builder, PC2_MAC, "169.254.17.42")
    cb.gratuitous_arp(builder, PC2_MAC, "169.254.17.42")

    builder.wait(3)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP, sequence=2, ident=2)
    builder.save(os.path.join(LAB_DIR, "dhcp_relay_missing.pcapng"))


def make_lab_dhcp_relay_working():
    """Same lab after adding the helper address: R1 relays, PC2 gets an address."""
    builder = cb.CaptureBuilder()
    lab_background(builder, 3)
    builder.add(cb.dhcp_message("discover", PC2_MAC, 0x0d0d0002), gap=0.2)
    builder.add(cb.dhcp_message("offer", PC2_MAC, 0x0d0d0002, True, R1_LAN_MAC, LAB_DHCP_IP,
                                "192.168.10.100", relay_ip=R1_LAN_IP), gap=0.006)
    builder.add(cb.dhcp_message("request", PC2_MAC, 0x0d0d0002, requested_ip="192.168.10.100"), gap=0.002)
    builder.add(cb.dhcp_message("ack", PC2_MAC, 0x0d0d0002, True, R1_LAN_MAC, LAB_DHCP_IP,
                                "192.168.10.100", relay_ip=R1_LAN_IP), gap=0.006)
    cb.arp_resolve(builder, PC2_MAC, "192.168.10.100", R1_LAN_MAC, R1_LAN_IP)
    cb.http_session(builder, PC2_MAC, "192.168.10.100", 42000, R1_LAN_MAC, LAB_SERVER_IP, ttl=62)
    builder.wait(3)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, LAB_SERVER_IP, sequence=1, ident=3)
    builder.save(os.path.join(LAB_DIR, "dhcp_relay_working.pcapng"))


def make_lab_acl_blocking():
    """
    An extended ACL on R3 permits HTTP to the server but denies SSH, and R3
    is configured to send 'administratively prohibited' messages.
    """
    builder = cb.CaptureBuilder()
    lab_background(builder, 4)

    cb.http_session(builder, PC1_MAC, PC1_IP, 43000, R1_LAN_MAC, LAB_SERVER_IP, ttl=62)

    ssh = cb.TcpConversation(builder, PC1_MAC, PC1_IP, 43100, R1_LAN_MAC, LAB_SERVER_IP, 22)
    for gap in [0.3, 1.0, 2.0]:
        syn = ssh.syn(gap=gap)
        cb.icmp_error_about(builder, R1_LAN_MAC, R3_IP, PC1_MAC, PC1_IP, syn, 3, 13, gap=0.006)

    builder.wait(3)
    cb.http_session(builder, PC1_MAC, PC1_IP, 43200, R1_LAN_MAC, LAB_SERVER_IP, ttl=62)
    builder.save(os.path.join(LAB_DIR, "acl_blocking_ssh.pcapng"))


def make_lab_routing_loop():
    """
    R2 sends 172.16.0.0/16 to R3, and R3's default route points back at R2.
    Packets bounce until the TTL hits zero; R2 reports 'time exceeded'.
    A traceroute run afterwards is included to show the difference.
    """
    builder = cb.CaptureBuilder()
    lab_background(builder, 5)

    for sequence in [1, 2, 3]:
        request = cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, "172.16.5.5",
                          sequence=sequence, answered=False, ident=0x0505)
        # The packet loops R2 <-> R3 until TTL runs out.
        looped = request.copy()
        looped[IP].ttl = 1
        cb.icmp_error_about(builder, R1_LAN_MAC, R2_IP, PC1_MAC, PC1_IP, looped, 11, 0, gap=0.06)

    # Traceroute to the server: TTL 1 and 2 expire at R1 and R2 (normal), TTL 3 reaches it.
    hops = [(1, R1_LAN_IP), (2, R2_IP)]
    port = 33434
    for ttl, router in hops:
        for _ in range(3):
            probe = (Ether(src=PC1_MAC, dst=R1_LAN_MAC) / IP(src=PC1_IP, dst=LAB_SERVER_IP, ttl=ttl)
                     / UDP(sport=44000, dport=port) / Raw(load=b"\x00" * 24))
            builder.add(probe, gap=0.05)
            cb.icmp_error_about(builder, R1_LAN_MAC, router, PC1_MAC, PC1_IP, probe, 11, 0, gap=0.004)
            port = port + 1

    builder.wait(3)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP, sequence=2, ident=5)
    builder.save(os.path.join(LAB_DIR, "routing_loop.pcapng"))


def make_lab_lossy_wan_link():
    """
    The serial link between R1 and R2 has errors (clock rate mismatch).
    A file transfer from the server loses about 1 in 8 segments.
    """
    builder = cb.CaptureBuilder()
    lab_background(builder, 6)

    transfer = cb.TcpConversation(builder, PC1_MAC, PC1_IP, 45000, R1_LAN_MAC, LAB_SERVER_IP, 21,
                                  client_isn=12000, server_isn=40000, ttl=62)
    transfer.handshake(rtt=0.03)
    transfer.client_sends(b"RETR config-backup.tar\r\n")
    transfer.server_acks()
    for number in range(1, 41):
        start_seq = transfer.server_seq
        data = b"d" * 1200
        transfer.server_sends(data, gap=0.01)
        if number % 8 == 0:
            for _ in range(3):
                builder.add(transfer.from_client("A", ack=start_seq), gap=0.003)
            builder.add(transfer.from_server("PA", data, seq=start_seq), gap=0.25)
        if number % 2 == 0:
            transfer.client_acks()
    transfer.close()

    builder.wait(3)
    cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP, sequence=2, ident=6)
    builder.save(os.path.join(LAB_DIR, "lossy_wan_link.pcapng"))


def make_lab_duplicate_ip():
    """
    Someone gave a lab PC the static address 192.168.10.1 - the same as R1's
    LAN interface. PCs on LAN A now sometimes send traffic to the wrong box.
    """
    builder = cb.CaptureBuilder()
    rogue_mac = "0c:aa:10:00:00:99"
    cb.arp_resolve(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP)
    builder.add(Ether(src=rogue_mac, dst=PC1_MAC) / cb.ARP(
        op=2, hwsrc=rogue_mac, psrc=R1_LAN_IP, hwdst=PC1_MAC, pdst=PC1_IP), gap=0.0007)
    cb.gratuitous_arp(builder, rogue_mac, R1_LAN_IP)

    # PC1 now sends its web traffic to the rogue PC, which has no web server -> RST.
    wrong = cb.TcpConversation(builder, PC1_MAC, PC1_IP, 46000, rogue_mac, LAB_SERVER_IP, 80)
    wrong.syn()
    builder.add(wrong.from_server("RA", seq=0, ack=wrong.client_seq + 1), gap=0.0005)

    builder.wait(3)
    cb.arp_resolve(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, R1_LAN_IP)
    cb.http_session(builder, PC1_MAC, PC1_IP, 46100, R1_LAN_MAC, LAB_SERVER_IP, ttl=62)
    builder.save(os.path.join(LAB_DIR, "duplicate_gateway_ip.pcapng"))


def make_lab_all_working():
    """The lab with every fault fixed: should produce an empty report."""
    builder = cb.CaptureBuilder()
    lab_background(builder, 7)
    cb.dns_lookup(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, LAB_DNS_IP, "srv.lab.local.", LAB_SERVER_IP,
                  transaction_id=0x0707, client_port=47000)
    cb.http_session(builder, PC1_MAC, PC1_IP, 47001, R1_LAN_MAC, LAB_SERVER_IP, ttl=62, response_size=6000)
    for sequence in [1, 2, 3]:
        cb.ping(builder, PC1_MAC, PC1_IP, R1_LAN_MAC, LAB_SERVER_IP, sequence=sequence, ident=0x0707)
    builder.save(os.path.join(LAB_DIR, "all_working.pcapng"))


ALL_SAMPLES = [
    make_healthy_home_network,
    make_tcp_handshake_failures,
    make_tcp_retransmissions,
    make_dns_failures,
    make_dhcp_failures,
    make_arp_conflict,
    make_icmp_unreachable,
    make_lab_missing_route,
    make_lab_dhcp_relay_missing,
    make_lab_dhcp_relay_working,
    make_lab_acl_blocking,
    make_lab_routing_loop,
    make_lab_lossy_wan_link,
    make_lab_duplicate_ip,
    make_lab_all_working,
]


def main():
    os.makedirs(BASIC_DIR, exist_ok=True)
    os.makedirs(LAB_DIR, exist_ok=True)
    for make_sample in ALL_SAMPLES:
        make_sample()
        print("generated: " + make_sample.__name__.replace("make_", ""))


if __name__ == "__main__":
    main()
