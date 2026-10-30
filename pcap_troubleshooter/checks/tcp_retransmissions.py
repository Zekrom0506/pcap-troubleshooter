"""
Check: TCP retransmissions.

Every byte TCP sends has a sequence number. If a sender transmits data whose
sequence numbers it has already sent before, the first copy was most likely
lost (or its acknowledgement was lost) and the sender is trying again.

A few retransmissions are normal on busy networks. Lots of them, or the same
segment being sent again and again, point to packet loss, congestion, a bad
cable / Wi-Fi link, or an MTU problem.
"""

from scapy.layers.inet import TCP

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR, WARNING, INFO

CHECK_NAME = "TCP Retransmissions"

# If more than this share of a flow's data segments are retransmissions,
# we raise the severity to WARNING.
WARNING_RATE = 0.05

# If one single segment is sent this many extra times, something is
# seriously wrong (the other side is probably not receiving at all).
ERROR_REPEAT_COUNT = 3


class FlowState:
    """Tracks one direction of one TCP connection (sender -> receiver)."""

    def __init__(self, source_ip, source_port, destination_ip, destination_port):
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port

        self.highest_sequence_end = None  # highest "seq + length" seen so far
        self.data_segment_count = 0       # segments that carried data
        self.retransmitted_frames = []    # frames we think are retransmissions
        self.times_sent = {}              # sequence number -> how many times it was sent

    def description(self):
        return (helpers.format_endpoint(self.source_ip, self.source_port)
                + " -> "
                + helpers.format_endpoint(self.destination_ip, self.destination_port))


def collect_flows(frames):
    """Walk the capture and fill in a FlowState for each TCP direction."""
    flows = {}

    for frame in frames:
        packet = frame.packet
        if not packet.haslayer(TCP):
            continue

        addresses = helpers.get_ip_addresses(packet)
        if addresses is None:
            continue
        source_ip, destination_ip = addresses

        tcp = packet[TCP]
        flags = helpers.tcp_flags_value(packet)

        # SYN retries are handled by the handshake check, so skip SYNs here.
        if helpers.has_flag(flags, helpers.TCP_SYN):
            continue

        payload_length = helpers.tcp_payload_length(packet)
        if payload_length == 0:
            # Pure ACKs carry no data, so they cannot be retransmissions of data.
            continue

        key = (source_ip, tcp.sport, destination_ip, tcp.dport)
        flow = flows.get(key)
        if flow is None:
            flow = FlowState(source_ip, tcp.sport, destination_ip, tcp.dport)
            flows[key] = flow

        sequence_start = tcp.seq
        sequence_end = tcp.seq + payload_length
        flow.data_segment_count = flow.data_segment_count + 1

        previous_count = flow.times_sent.get(sequence_start, 0)
        flow.times_sent[sequence_start] = previous_count + 1

        if flow.highest_sequence_end is None:
            # First data segment of this flow: nothing to compare against yet.
            flow.highest_sequence_end = sequence_end
            continue

        # TCP keep-alive: 0 or 1 byte sent one below the next expected number.
        # It looks like old data but is deliberate, so ignore it.
        is_keepalive = (payload_length <= 1
                        and sequence_start == flow.highest_sequence_end - 1)

        if sequence_start < flow.highest_sequence_end and not is_keepalive:
            # This data starts before data we have already seen -> sent again.
            flow.retransmitted_frames.append(frame)

        if sequence_end > flow.highest_sequence_end:
            flow.highest_sequence_end = sequence_end

    return flows


def find_issues(frames, capture_end):
    """Return one Issue for every TCP flow that contains retransmissions."""
    issues = []
    flows = collect_flows(frames)

    for flow in flows.values():
        retransmission_count = len(flow.retransmitted_frames)
        if retransmission_count == 0:
            continue

        rate = retransmission_count / flow.data_segment_count
        percent_text = str(round(rate * 100, 1)) + "%"

        # Find the segment that was sent the most times.
        most_times_sent = 0
        for count in flow.times_sent.values():
            if count > most_times_sent:
                most_times_sent = count
        extra_copies = most_times_sent - 1

        if extra_copies >= ERROR_REPEAT_COUNT:
            severity = ERROR
        elif rate >= WARNING_RATE:
            severity = WARNING
        else:
            severity = INFO

        details = [
            str(retransmission_count) + " of " + str(flow.data_segment_count)
            + " data segments were retransmitted (" + percent_text + ").",
        ]
        if extra_copies >= 1:
            details.append("The worst segment was sent " + str(most_times_sent) + " times in total.")

        if severity == ERROR:
            details.append("Likely cause: the receiver is not getting the data or its ACKs are being lost"
                           + " (link down, firewall dropping packets mid-connection, or MTU black hole).")
        elif severity == WARNING:
            details.append("Likely cause: packet loss or congestion on the path (bad cable, weak Wi-Fi,"
                           + " overloaded link or duplex mismatch).")
        else:
            details.append("A small number of retransmissions is normal; keep an eye on it if it grows.")

        issue = Issue(
            check=CHECK_NAME,
            severity=severity,
            summary=str(retransmission_count) + " retransmission(s) on " + flow.description(),
            details=details,
            frame_numbers=helpers.frame_numbers_of(flow.retransmitted_frames),
        )
        issues.append(issue)

    return issues
