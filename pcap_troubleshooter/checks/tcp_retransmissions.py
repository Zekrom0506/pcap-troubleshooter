"""
Check: TCP retransmissions.

Every byte TCP sends has a sequence number. If a sender transmits data whose
sequence numbers it has already sent before, the first copy was most likely
lost (or its acknowledgement was lost) and the sender is trying again.

We use the same three rules as Wireshark to spot a resent segment:
  1. the receiver had already acknowledged that data (spurious retransmission),
  2. the receiver sent 2+ duplicate ACKs asking for exactly this data (fast retransmission),
  3. the data is old and did not arrive within one round trip of newer data.

Not every "old" segment is a retransmission. If it shows up within a few
milliseconds of newer data, the packets simply arrived out of order (they
took different paths). Wireshark makes the same distinction, and so do we.

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

# A flow needs at least this many retransmissions before we call it a WARNING.
# (1 lost packet out of 8 is bad luck, not a broken link.)
WARNING_MIN_COUNT = 3

# An "old" segment that arrives soon after newer data is treated as
# out-of-order, not as a retransmission. "Soon" means within one round trip
# time (measured from the connection's SYN to its first ACK), or 3 ms if we
# did not see the handshake. Wireshark uses the same rule.
DEFAULT_OUT_OF_ORDER_SECONDS = 0.003

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
        self.last_advance_time = 0.0      # when highest_sequence_end last grew
        self.out_of_order_count = 0       # segments that were only out of order
        self.data_segment_count = 0       # segments that carried data
        self.retransmitted_frames = []    # frames we think are retransmissions
        self.times_sent = {}              # sequence number -> how many times it was sent

    def description(self):
        return (helpers.format_endpoint(self.source_ip, self.source_port)
                + " -> "
                + helpers.format_endpoint(self.destination_ip, self.destination_port))


class AckState:
    """What one side of a connection has acknowledged so far."""

    def __init__(self):
        self.highest_ack = None   # highest ACK number this side has sent
        self.duplicate_acks = 0   # how many times in a row it repeated that ACK
        self.last_window = None   # receive window in the last ACK


def remember_ack(ack_states, key, tcp, payload_length):
    """Update the ACK information for the side that sent this packet."""
    state = ack_states.get(key)
    if state is None:
        state = AckState()
        ack_states[key] = state

    ack_number = tcp.ack
    window = tcp.window
    if state.highest_ack is None or ack_number > state.highest_ack:
        state.highest_ack = ack_number
        state.duplicate_acks = 0
    elif ack_number == state.highest_ack and payload_length == 0 and window == state.last_window:
        # Same ACK and same window again with no data: the receiver is asking
        # for missing data. (Same ACK with a new window is just a "window update".)
        state.duplicate_acks = state.duplicate_acks + 1
    state.last_window = window


def connection_key(ip_a, port_a, ip_b, port_b):
    """Same key for both directions of a connection."""
    endpoint_a = (ip_a, port_a)
    endpoint_b = (ip_b, port_b)
    if endpoint_a < endpoint_b:
        return (endpoint_a, endpoint_b)
    return (endpoint_b, endpoint_a)


def collect_flows(frames):
    """Walk the capture and fill in a FlowState for each TCP direction."""
    flows = {}
    syn_times = {}         # connection -> time of the first SYN
    round_trip_times = {}  # connection -> seconds from SYN to the handshake ACK
    ack_states = {}        # (sender ip, sender port, receiver ip, receiver port) -> AckState

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

        connection = connection_key(source_ip, tcp.sport, destination_ip, tcp.dport)

        # SYN retries are handled by the handshake check, so skip SYNs here,
        # but remember when the connection started to measure its round trip time.
        if helpers.has_flag(flags, helpers.TCP_SYN):
            if not helpers.has_flag(flags, helpers.TCP_ACK) and connection not in syn_times:
                syn_times[connection] = frame.time
            continue

        # The first ACK after the SYN finishes the handshake: SYN -> ACK = one round trip.
        if connection in syn_times and connection not in round_trip_times:
            round_trip_times[connection] = frame.time - syn_times[connection]

        payload_length = helpers.tcp_payload_length(packet)
        key = (source_ip, tcp.sport, destination_ip, tcp.dport)
        reverse_key = (destination_ip, tcp.dport, source_ip, tcp.sport)

        if helpers.has_flag(flags, helpers.TCP_ACK):
            remember_ack(ack_states, key, tcp, payload_length)

        if payload_length == 0:
            # Pure ACKs carry no data, so they cannot be retransmissions of data.
            continue

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
            flow.last_advance_time = frame.time
            continue

        # TCP keep-alive: 0 or 1 byte sent one below the next expected number.
        # It looks like old data but is deliberate, so ignore it.
        is_keepalive = (payload_length <= 1
                        and sequence_start == flow.highest_sequence_end - 1)

        if sequence_start < flow.highest_sequence_end and not is_keepalive:
            # This data starts before data we have already seen.
            receiver = ack_states.get(reverse_key)
            already_acknowledged = False
            asked_for_again = False
            if receiver is not None and receiver.highest_ack is not None:
                already_acknowledged = sequence_end <= receiver.highest_ack
                asked_for_again = (receiver.duplicate_acks >= 2
                                   and sequence_start == receiver.highest_ack)

            seconds_since_newer_data = frame.time - flow.last_advance_time
            out_of_order_limit = round_trip_times.get(connection, DEFAULT_OUT_OF_ORDER_SECONDS)
            arrived_quickly = seconds_since_newer_data < out_of_order_limit
            # A segment that ends exactly where the newest data ends is a resend, not a late arrival.
            fills_the_end = sequence_end == flow.highest_sequence_end

            if already_acknowledged or asked_for_again:
                # Rules 1 and 2: definitely sent again.
                flow.retransmitted_frames.append(frame)
            elif arrived_quickly and not fills_the_end:
                # Just overtaken by a later packet on the way: out of order.
                flow.out_of_order_count = flow.out_of_order_count + 1
            else:
                # Sent again by the sender: a retransmission.
                flow.retransmitted_frames.append(frame)

        if sequence_end > flow.highest_sequence_end:
            flow.highest_sequence_end = sequence_end
            flow.last_advance_time = frame.time

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
        elif rate >= WARNING_RATE and retransmission_count >= WARNING_MIN_COUNT:
            severity = WARNING
        else:
            severity = INFO

        details = [
            str(retransmission_count) + " of " + str(flow.data_segment_count)
            + " data segments were retransmitted (" + percent_text + ").",
        ]
        if flow.out_of_order_count > 0:
            details.append(str(flow.out_of_order_count) + " more segment(s) arrived out of order"
                           + " (not counted as retransmissions).")
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
