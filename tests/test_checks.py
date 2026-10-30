"""
Unit tests for each check, using small hand-made packet lists.

Run with:  python -m pytest
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Padding, Raw
from scapy.utils import mac2str

from pcap_troubleshooter.checks import (arp_conflicts, dhcp_exchanges, dns_queries,
                                        icmp_unreachable, tcp_handshake, tcp_retransmissions)
from pcap_troubleshooter.models import Frame, ERROR, WARNING, INFO

CLIENT = "10.0.0.5"
SERVER = "10.0.0.80"


def make_frames(packets, start=1000.0, gap=0.5):
    """Wrap a list of Scapy packets into Frame objects with increasing timestamps."""
    frames = []
    for index, packet in enumerate(packets):
        # Rebuild from bytes so every field (lengths, checksums) is filled in, like a real capture.
        rebuilt = Ether(bytes(packet))
        frames.append(Frame(number=index + 1, time=start + index * gap, packet=rebuilt))
    return frames


def run_check(check, packets, extra_time_at_end=10.0):
    frames = make_frames(packets)
    capture_end = frames[-1].time + extra_time_at_end
    return check.find_issues(frames, capture_end)


def tcp(src, dst, sport, dport, flags, seq=0, ack=0, data=b""):
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if data:
        packet = packet / Raw(load=data)
    return packet


# ------------------------------------------------------------ TCP handshake

def test_completed_handshake_is_not_reported():
    packets = [
        tcp(CLIENT, SERVER, 40000, 80, "S", seq=100),
        tcp(SERVER, CLIENT, 80, 40000, "SA", seq=500, ack=101),
        tcp(CLIENT, SERVER, 40000, 80, "A", seq=101, ack=501),
    ]
    assert run_check(tcp_handshake, packets) == []


def test_syn_without_answer_is_error():
    packets = [tcp(CLIENT, SERVER, 40000, 443, "S", seq=100)] * 3
    issues = run_check(tcp_handshake, packets)
    assert len(issues) == 1
    assert issues[0].severity == ERROR
    assert "No response to SYN" in issues[0].summary
    assert issues[0].frame_numbers == [1, 2, 3]


def test_syn_answered_with_rst_is_connection_refused():
    packets = [
        tcp(CLIENT, SERVER, 40000, 8080, "S", seq=100),
        tcp(SERVER, CLIENT, 8080, 40000, "RA", seq=0, ack=101),
    ]
    issues = run_check(tcp_handshake, packets)
    assert len(issues) == 1
    assert "Connection refused" in issues[0].summary


def test_syn_ack_without_final_ack_is_warning():
    packets = [
        tcp(CLIENT, SERVER, 40000, 22, "S", seq=100),
        tcp(SERVER, CLIENT, 22, 40000, "SA", seq=500, ack=101),
    ]
    issues = run_check(tcp_handshake, packets)
    assert len(issues) == 1
    assert issues[0].severity == WARNING


def test_single_syn_at_end_of_capture_is_only_info():
    packets = [tcp(CLIENT, SERVER, 40000, 443, "S", seq=100)]
    issues = run_check(tcp_handshake, packets, extra_time_at_end=0.5)
    assert issues[0].severity == INFO


def test_syn_rejected_by_icmp_is_linked_to_router():
    syn = IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=80, flags="S", seq=100)
    quoted = bytes(syn)[:28]
    packets = [
        Ether() / syn,
        Ether() / IP(src="10.0.0.1", dst=CLIENT) / ICMP(type=3, code=0) / Raw(load=quoted),
    ]
    issues = run_check(tcp_handshake, packets)
    assert len(issues) == 1
    assert "rejected by router 10.0.0.1" in issues[0].summary
    assert issues[0].frame_numbers == [1, 2]


# ------------------------------------------------------- TCP retransmissions

def test_retransmitted_segment_is_found():
    data = b"x" * 100
    packets = [
        tcp(SERVER, CLIENT, 80, 40000, "PA", seq=1000, ack=1, data=data),
        tcp(SERVER, CLIENT, 80, 40000, "PA", seq=1100, ack=1, data=data),
        tcp(SERVER, CLIENT, 80, 40000, "PA", seq=1000, ack=1, data=data),  # sent again
        tcp(SERVER, CLIENT, 80, 40000, "PA", seq=1200, ack=1, data=data),
    ]
    issues = run_check(tcp_retransmissions, packets)
    assert len(issues) == 1
    assert issues[0].frame_numbers == [3]
    assert issues[0].severity == WARNING  # 1 of 4 = 25 %


def test_segment_sent_many_times_is_error():
    data = b"y" * 50
    packets = [tcp(CLIENT, SERVER, 40000, 445, "PA", seq=5000, ack=1, data=data)] * 5
    issues = run_check(tcp_retransmissions, packets)
    assert issues[0].severity == ERROR
    assert len(issues[0].frame_numbers) == 4


def test_keepalive_is_not_a_retransmission():
    packets = [
        tcp(CLIENT, SERVER, 40000, 80, "PA", seq=1000, ack=1, data=b"z" * 10),
        tcp(CLIENT, SERVER, 40000, 80, "A", seq=1009, ack=1, data=b"\x00"),  # keep-alive
    ]
    assert run_check(tcp_retransmissions, packets) == []


def test_ethernet_padding_is_not_counted_as_data():
    # Ethernet pads tiny frames to 60 bytes. Those padding bytes come after the
    # IP packet (IP length = 40) and must not be mistaken for TCP data.
    ack = (Ether() / IP(src=CLIENT, dst=SERVER, len=40)
           / TCP(sport=1, dport=2, flags="A", seq=10) / Padding(load=b"\x00" * 6))
    assert run_check(tcp_retransmissions, [ack, ack]) == []


# ---------------------------------------------------------------------- DNS

def dns_query(transaction_id, name, src_port=33333, server="10.0.0.53"):
    return (Ether() / IP(src=CLIENT, dst=server) / UDP(sport=src_port, dport=53)
            / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=name)))


def dns_answer(transaction_id, name, rcode=0, src_port=33333, server="10.0.0.53"):
    answer = DNS(id=transaction_id, qr=1, rcode=rcode, qd=DNSQR(qname=name))
    if rcode == 0:
        answer = DNS(id=transaction_id, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="1.2.3.4"))
    return Ether() / IP(src=server, dst=CLIENT) / UDP(sport=53, dport=src_port) / answer


def test_answered_dns_query_is_fine():
    packets = [dns_query(7, "example.com"), dns_answer(7, "example.com")]
    assert run_check(dns_queries, packets) == []


def test_unanswered_dns_query_is_error():
    packets = [dns_query(7, "example.com"), dns_query(7, "example.com")]
    issues = run_check(dns_queries, packets)
    assert len(issues) == 1
    assert issues[0].severity == ERROR
    assert "example.com" in issues[0].summary
    assert issues[0].frame_numbers == [1, 2]


def test_dns_answer_with_wrong_id_does_not_count():
    packets = [dns_query(7, "example.com"), dns_answer(8, "example.com")]
    assert len(run_check(dns_queries, packets)) == 1


def test_dns_servfail_and_nxdomain():
    packets = [
        dns_query(1, "broken.test", src_port=1001), dns_answer(1, "broken.test", rcode=2, src_port=1001),
        dns_query(2, "typo.test", src_port=1002), dns_answer(2, "typo.test", rcode=3, src_port=1002),
    ]
    issues = run_check(dns_queries, packets)
    severities = {}
    for issue in issues:
        severities[issue.summary.split(":")[0]] = issue.severity
    assert severities["DNS error SERVFAIL"] == WARNING
    assert severities["DNS error NXDOMAIN"] == INFO


def test_mdns_is_ignored():
    packet = (Ether() / IP(src=CLIENT, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
              / DNS(id=0, qd=DNSQR(qname="printer.local")))
    assert run_check(dns_queries, [packet]) == []


# --------------------------------------------------------------------- DHCP

CLIENT_MAC = "aa:bb:cc:00:00:01"


def dhcp(kind, xid=0x1234, from_server=False):
    if from_server:
        return (Ether() / IP(src="10.0.0.1", dst="255.255.255.255") / UDP(sport=67, dport=68)
                / BOOTP(op=2, xid=xid, yiaddr="10.0.0.50", chaddr=mac2str(CLIENT_MAC))
                / DHCP(options=[("message-type", kind), "end"]))
    return (Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, chaddr=mac2str(CLIENT_MAC))
            / DHCP(options=[("message-type", kind), "end"]))


def test_full_dora_is_fine():
    packets = [dhcp("discover"), dhcp("offer", from_server=True), dhcp("request"), dhcp("ack", from_server=True)]
    assert run_check(dhcp_exchanges, packets) == []


def test_discover_without_offer_is_error():
    issues = run_check(dhcp_exchanges, [dhcp("discover"), dhcp("discover")])
    assert len(issues) == 1
    assert "No DHCP server answered" in issues[0].summary
    assert CLIENT_MAC in issues[0].summary


def test_offer_without_request_is_warning():
    issues = run_check(dhcp_exchanges, [dhcp("discover"), dhcp("offer", from_server=True)])
    assert issues[0].severity == WARNING


def test_request_without_ack_is_error():
    issues = run_check(dhcp_exchanges, [dhcp("request"), dhcp("request")])
    assert "never acknowledged" in issues[0].summary


def test_nak_is_error():
    issues = run_check(dhcp_exchanges, [dhcp("request"), dhcp("nak", from_server=True)])
    assert "NAK" in issues[0].summary


def test_lease_renewal_is_fine():
    assert run_check(dhcp_exchanges, [dhcp("request"), dhcp("ack", from_server=True)]) == []


# ---------------------------------------------------------------------- ARP

def arp_reply(mac, ip_address):
    return Ether(src=mac) / ARP(op=2, hwsrc=mac, psrc=ip_address, pdst="10.0.0.5")


def test_one_mac_per_ip_is_fine():
    packets = [arp_reply("aa:aa:aa:aa:aa:01", "10.0.0.9"), arp_reply("aa:aa:aa:aa:aa:01", "10.0.0.9")]
    assert run_check(arp_conflicts, packets) == []


def test_two_macs_claiming_one_ip_is_conflict():
    packets = [arp_reply("aa:aa:aa:aa:aa:01", "10.0.0.9"), arp_reply("aa:aa:aa:aa:aa:02", "10.0.0.9")]
    issues = run_check(arp_conflicts, packets)
    assert len(issues) == 1
    assert "10.0.0.9" in issues[0].summary
    assert issues[0].frame_numbers == [1, 2]


def test_probe_answered_by_other_device_is_conflict():
    probe = Ether(src="aa:aa:aa:aa:aa:03") / ARP(op=1, hwsrc="aa:aa:aa:aa:aa:03", psrc="0.0.0.0", pdst="10.0.0.9")
    packets = [probe, arp_reply("aa:aa:aa:aa:aa:01", "10.0.0.9")]
    issues = run_check(arp_conflicts, packets)
    assert len(issues) == 1
    assert "already in use" in issues[0].summary


# --------------------------------------------------------------------- ICMP

def icmp_error(router, original, icmp_type, code):
    quoted = bytes(original)[:28]
    return Ether() / IP(src=router, dst=CLIENT) / ICMP(type=icmp_type, code=code) / Raw(load=quoted)


def test_network_unreachable_is_error_and_names_target():
    original = IP(src=CLIENT, dst="192.168.30.10") / ICMP(type=8)
    issues = run_check(icmp_unreachable, [icmp_error("10.0.12.2", original, 3, 0)])
    assert len(issues) == 1
    assert issues[0].severity == ERROR
    assert "Network unreachable" in issues[0].summary
    assert "192.168.30.10" in issues[0].summary


def test_port_unreachable_shows_port():
    original = IP(src=CLIENT, dst=SERVER) / UDP(sport=5000, dport=161)
    issues = run_check(icmp_unreachable, [icmp_error(SERVER, original, 3, 3)])
    assert "161/udp" in issues[0].summary


def test_repeated_errors_are_grouped():
    original = IP(src=CLIENT, dst="192.168.30.10") / ICMP(type=8)
    packets = [icmp_error("10.0.12.2", original, 3, 0)] * 4
    issues = run_check(icmp_unreachable, packets)
    assert len(issues) == 1
    assert len(issues[0].frame_numbers) == 4


def test_traceroute_time_exceeded_is_info_but_loop_is_warning():
    probe = IP(src=CLIENT, dst=SERVER, ttl=1) / UDP(sport=4000, dport=33434)
    looped_ping = IP(src=CLIENT, dst="172.16.5.5", ttl=1) / ICMP(type=8)
    issues = run_check(icmp_unreachable, [
        icmp_error("10.0.0.1", probe, 11, 0),
        icmp_error("10.0.12.2", looped_ping, 11, 0),
    ])
    by_target = {}
    for issue in issues:
        by_target[issue.summary.split()[-1]] = issue.severity
    assert by_target[SERVER] == INFO
    assert by_target["172.16.5.5"] == WARNING


def test_echo_reply_is_not_reported():
    packet = Ether() / IP(src=SERVER, dst=CLIENT) / ICMP(type=0)
    assert run_check(icmp_unreachable, [packet]) == []
