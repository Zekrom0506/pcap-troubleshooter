"""
Check: incomplete DHCP exchanges.

A device that joins a network gets its IP address with four DHCP messages,
often remembered as "DORA":

    client  --- DISCOVER --->  (broadcast)   "Is there a DHCP server?"
    client  <-- OFFER    ----  server        "You can have 192.168.1.50"
    client  --- REQUEST  --->  (broadcast)   "I'll take 192.168.1.50"
    client  <-- ACK      ----  server        "It's yours"

All four messages share the same transaction ID (xid), so we group by it and
report any exchange that stopped part way through.

One catch on real networks (especially Wi-Fi): unless the client sets the
"broadcast" flag, the server sends OFFER and ACK straight to the client, so a
capture taken on a different computer never sees them. We only call a missing
reply an ERROR when it should have been visible in this capture.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.l2 import Ether

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR, WARNING, INFO

CHECK_NAME = "DHCP"

# Bit in the BOOTP "flags" field asking the server to broadcast its reply.
BROADCAST_FLAG = 0x8000

DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7
INFORM = 8

MESSAGE_NAMES = {
    DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST", DECLINE: "DECLINE",
    ACK: "ACK", NAK: "NAK", RELEASE: "RELEASE", INFORM: "INFORM",
}


class DhcpExchange:
    """All DHCP messages that share one transaction ID."""

    def __init__(self, transaction_id, client_mac):
        self.transaction_id = transaction_id
        self.client_mac = client_mac
        self.frames_by_type = {}   # message type -> list of frames
        self.all_frames = []
        self.offered_addresses = []
        self.wants_broadcast_reply = False  # client set the BOOTP broadcast flag

    def add(self, message_type, frame):
        if message_type not in self.frames_by_type:
            self.frames_by_type[message_type] = []
        self.frames_by_type[message_type].append(frame)
        self.all_frames.append(frame)

    def count(self, message_type):
        return len(self.frames_by_type.get(message_type, []))

    def has(self, message_type):
        return self.count(message_type) > 0

    def id_text(self):
        return "0x%08x" % self.transaction_id


def get_message_type(dhcp_layer):
    """Find the 'message-type' option in a DHCP packet. Returns None if missing."""
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and len(option) >= 2 and option[0] == "message-type":
            return int(option[1])
    return None


def mac_to_text(raw_bytes):
    """Turn the first 6 bytes of BOOTP's chaddr field into aa:bb:cc:dd:ee:ff."""
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("latin-1")
    parts = []
    for byte in raw_bytes[:6]:
        parts.append("%02x" % byte)
    return ":".join(parts)


def collect_exchanges(frames):
    """Group DHCP messages by transaction ID."""
    exchanges = {}

    for frame in frames:
        packet = frame.packet
        if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
            continue

        message_type = get_message_type(packet[DHCP])
        if message_type is None:
            continue

        bootp = packet[BOOTP]
        transaction_id = int(bootp.xid)

        exchange = exchanges.get(transaction_id)
        if exchange is None:
            exchange = DhcpExchange(transaction_id, mac_to_text(bootp.chaddr))
            exchanges[transaction_id] = exchange

        exchange.add(message_type, frame)

        if message_type == OFFER:
            exchange.offered_addresses.append(bootp.yiaddr)

        is_from_client = (bootp.op == 1)
        if is_from_client and (int(bootp.flags) & BROADCAST_FLAG) != 0:
            exchange.wants_broadcast_reply = True

    return list(exchanges.values())


def unicast_destinations(frames):
    """Every MAC address that some frame in the capture was sent directly to."""
    destinations = set()
    for frame in frames:
        if frame.packet.haslayer(Ether):
            destinations.add(frame.packet[Ether].dst.lower())
    destinations.discard("ff:ff:ff:ff:ff:ff")
    return destinations


def reply_would_be_visible(exchange, mac_addresses_reached):
    """
    Could this capture have seen the server's reply?
    Yes if the client asked for a broadcast reply, or if this capture does see
    frames sent directly to the client (so it is on the client's path).
    """
    if exchange.wants_broadcast_reply:
        return True
    return exchange.client_mac in mac_addresses_reached


NOT_VISIBLE_NOTE = ("Note: this client did not ask for a broadcast reply and this capture never sees"
                    " traffic sent directly to it, so the server's reply may just not be visible from"
                    " here (common on Wi-Fi). Capture on the client itself to be sure.")


def find_issues(frames, capture_end):
    """Return Issues for DHCP exchanges that did not finish."""
    issues = []
    mac_addresses_reached = unicast_destinations(frames)

    for exchange in collect_exchanges(frames):
        client = "client " + exchange.client_mac + " (xid " + exchange.id_text() + ")"
        last_time = exchange.all_frames[-1].time
        cut_off = helpers.near_capture_end(last_time, capture_end)

        # Informational messages that are not part of getting an address.
        if exchange.has(INFORM) or exchange.has(RELEASE):
            continue

        severity = None
        summary = ""
        details = []

        if exchange.has(NAK):
            severity = ERROR
            summary = "DHCP server refused request (NAK) from " + client
            details = [
                "The server answered the REQUEST with NAK.",
                "Likely cause: the client asked for an address from a different subnet"
                + " (moved networks) or the address is no longer valid.",
            ]

        elif exchange.has(DECLINE):
            severity = ERROR
            summary = "DHCP client declined the offered address: " + client
            details = [
                "The client sent DECLINE, which means it found the offered address already in use.",
                "Likely cause: a device with a static IP inside the DHCP pool (look for ARP conflicts).",
            ]

        elif exchange.has(DISCOVER) and not exchange.has(OFFER) and exchange.has(REQUEST):
            # The client went on to send REQUEST, so it DID get an offer: we just did not capture it.
            if exchange.has(ACK):
                continue
            severity = INFO
            summary = "DHCP offer and acknowledgement not captured for " + client
            details = [
                "The client sent DISCOVER and then REQUEST, so it received an OFFER that is not in this capture.",
                "The server most likely replied directly to the client (unicast).",
            ]

        elif exchange.has(DISCOVER) and not exchange.has(OFFER):
            severity = ERROR
            summary = "No DHCP server answered " + client
            details = [
                "The client broadcast " + str(exchange.count(DISCOVER)) + " DISCOVER message(s) and got no OFFER.",
                "Likely cause: no DHCP server on this network/VLAN, a missing or broken DHCP relay"
                + " (ip helper-address) on the router, or the address pool is exhausted.",
            ]

        elif exchange.has(OFFER) and not exchange.has(REQUEST):
            severity = WARNING
            summary = "DHCP offer was never requested by " + client
            details = [
                "The server offered " + ", ".join(exchange.offered_addresses)
                + " but the client never sent a REQUEST.",
                "Likely cause: the OFFER did not reach the client (relay or VLAN problem on the way back),"
                + " or the client picked a different server's offer.",
            ]

        elif exchange.has(REQUEST) and not exchange.has(ACK):
            severity = ERROR
            summary = "DHCP request never acknowledged for " + client
            details = [
                "The client sent " + str(exchange.count(REQUEST)) + " REQUEST message(s) and got no ACK.",
                "Likely cause: the server is unreachable (renewals go straight to the server)"
                + " or the server stopped responding mid-exchange.",
            ]

        if severity is None:
            continue

        server_replied = exchange.has(OFFER) or exchange.has(ACK) or exchange.has(NAK)
        if severity == ERROR and not server_replied and not reply_would_be_visible(exchange, mac_addresses_reached):
            severity = INFO
            details.append(NOT_VISIBLE_NOTE)

        # A single message right at the end of the capture may just be cut off.
        if cut_off and len(exchange.all_frames) == 1:
            severity = INFO
            details.append("Note: the capture ended right after this, so the rest of the exchange may not have been captured.")

        message_list = []
        for frame in exchange.all_frames:
            message_type = get_message_type(frame.packet[DHCP])
            message_list.append(MESSAGE_NAMES.get(message_type, str(message_type)))
        details.append("Messages seen: " + " -> ".join(message_list))

        issue = Issue(
            check=CHECK_NAME,
            severity=severity,
            summary=summary,
            details=details,
            frame_numbers=helpers.frame_numbers_of(exchange.all_frames),
        )
        issues.append(issue)

    return issues
