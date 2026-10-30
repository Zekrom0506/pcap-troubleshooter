"""
Check: unanswered DNS queries (and DNS error answers).

A DNS query is a UDP packet to port 53. The server is supposed to answer with
a packet that carries the same transaction ID. If no answer ever arrives, the
client cannot turn the name into an IP address, so the user sees
"site can't be reached" even though the network itself may be fine.

We also report answers that came back with an error code:
  SERVFAIL (2) - the DNS server itself failed to resolve the name
  NXDOMAIN (3) - the name does not exist (often a typo, so only INFO)
  REFUSED  (5) - the server refuses to answer this client
"""

from scapy.layers.dns import DNS
from scapy.layers.inet import UDP

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR, WARNING, INFO

CHECK_NAME = "DNS"

DNS_PORT = 53

RECORD_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}

ERROR_CODE_NAMES = {
    1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


class DnsLookup:
    """
    One name lookup from one client to one server.
    A client may send the same question several times (retries), so we group
    them together instead of reporting every retry separately.
    """

    def __init__(self, client_ip, server_ip, query_name, query_type):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.query_name = query_name
        self.query_type = query_type

        self.query_frames = []
        self.response_frames = []
        self.error_codes = []  # rcode of every response we got

    def type_name(self):
        return RECORD_TYPE_NAMES.get(self.query_type, "TYPE" + str(self.query_type))


def read_question(dns_layer):
    """Return (name, type) of the first question in a DNS packet."""
    try:
        question = dns_layer.qd[0]
    except (IndexError, TypeError):
        try:
            question = dns_layer.qd
        except AttributeError:
            return "<no question>", 0
    if question is None:
        return "<no question>", 0

    name = question.qname
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    return str(name), int(question.qtype)


def collect_lookups(frames):
    """Match DNS queries with DNS responses."""
    lookups = {}            # (client, server, name, type) -> DnsLookup
    lookup_by_id = {}       # (client, client port, server, transaction id) -> DnsLookup

    for frame in frames:
        packet = frame.packet
        if not packet.haslayer(UDP) or not packet.haslayer(DNS):
            continue

        udp = packet[UDP]
        # Only look at normal DNS on port 53.
        # (mDNS on 5353 and LLMNR on 5355 are multicast and often go unanswered on purpose.)
        if udp.sport != DNS_PORT and udp.dport != DNS_PORT:
            continue

        addresses = helpers.get_ip_addresses(packet)
        if addresses is None:
            continue
        source_ip, destination_ip = addresses
        dns = packet[DNS]

        if dns.qr == 0 and udp.dport == DNS_PORT:
            # This is a query from a client to a server.
            name, query_type = read_question(dns)
            lookup_key = (source_ip, destination_ip, name, query_type)
            lookup = lookups.get(lookup_key)
            if lookup is None:
                lookup = DnsLookup(source_ip, destination_ip, name, query_type)
                lookups[lookup_key] = lookup
            lookup.query_frames.append(frame)

            id_key = (source_ip, udp.sport, destination_ip, dns.id)
            lookup_by_id[id_key] = lookup

        elif dns.qr == 1 and udp.sport == DNS_PORT:
            # This is a response from a server back to a client.
            id_key = (destination_ip, udp.dport, source_ip, dns.id)
            lookup = lookup_by_id.get(id_key)
            if lookup is not None:
                lookup.response_frames.append(frame)
                lookup.error_codes.append(int(dns.rcode))

    return list(lookups.values())


def find_issues(frames, capture_end):
    """Return Issues for unanswered DNS queries and DNS error answers."""
    issues = []
    lookups = collect_lookups(frames)

    for lookup in lookups:
        what = lookup.type_name() + " " + lookup.query_name

        if len(lookup.response_frames) == 0:
            # Nobody answered.
            query_count = len(lookup.query_frames)
            last_query_time = lookup.query_frames[-1].time

            severity = ERROR
            details = [
                lookup.client_ip + " asked DNS server " + lookup.server_ip
                + " " + str(query_count) + " time(s) and never got an answer.",
                "Likely cause: the DNS server is down or unreachable, UDP port 53 is blocked,"
                + " or the client is pointed at the wrong DNS server.",
            ]
            if query_count == 1 and helpers.near_capture_end(last_query_time, capture_end):
                severity = INFO
                details.append("Note: the capture ended just after this query, so the answer may not have been captured.")

            issue = Issue(
                check=CHECK_NAME,
                severity=severity,
                summary="Unanswered DNS query: " + what + " (server " + lookup.server_ip + ")",
                details=details,
                frame_numbers=helpers.frame_numbers_of(lookup.query_frames),
            )
            issues.append(issue)
            continue

        # It was answered. Did every answer come back with an error?
        successful_answers = 0
        for code in lookup.error_codes:
            if code == 0:
                successful_answers = successful_answers + 1
        if successful_answers > 0:
            continue

        error_code = lookup.error_codes[-1]
        error_name = ERROR_CODE_NAMES.get(error_code, "RCODE " + str(error_code))

        if error_name == "NXDOMAIN":
            severity = INFO
            explanation = "The name does not exist. Check for typos or a missing DNS record."
        else:
            severity = WARNING
            explanation = "The DNS server could not or would not resolve this name."

        frames_involved = []
        frames_involved.extend(lookup.query_frames)
        frames_involved.extend(lookup.response_frames)

        issue = Issue(
            check=CHECK_NAME,
            severity=severity,
            summary="DNS error " + error_name + ": " + what + " (server " + lookup.server_ip + ")",
            details=[
                "Server " + lookup.server_ip + " answered " + lookup.client_ip + " with " + error_name + ".",
                explanation,
            ],
            frame_numbers=helpers.frame_numbers_of(frames_involved),
        )
        issues.append(issue)

    return issues
