"""
Check: failed TCP three-way handshakes.

A healthy TCP connection starts like this:

    client  --- SYN     --->  server
    client  <-- SYN-ACK ----  server
    client  --- ACK     --->  server

This check looks for connections that never got past that point:

  * The client sent SYN and got nothing back      -> no response (filtered / host down)
  * The client sent SYN and the server sent RST   -> connection refused (port closed)
  * The server sent SYN-ACK but no final ACK came -> handshake never finished

If a router answered the SYN with an ICMP error (for example "network
unreachable"), we attach that ICMP packet to the issue as well, because it
explains why the server never replied.
"""

from scapy.layers.inet import ICMP, IPerror, TCP, TCPerror

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR, WARNING, INFO

CHECK_NAME = "TCP Handshake"


class HandshakeAttempt:
    """Everything we have seen for one connection attempt."""

    def __init__(self, client_ip, client_port, server_ip, server_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port

        self.syn_frames = []       # SYN packets sent by the client
        self.syn_ack_frames = []   # SYN-ACK packets sent by the server
        self.rst_frames = []       # RST packets sent by the server
        self.icmp_frames = []      # ICMP errors a router sent about our SYN
        self.final_ack_frame = None  # the client's ACK that completes the handshake

    def is_complete(self):
        return self.final_ack_frame is not None

    def client_text(self):
        return helpers.format_endpoint(self.client_ip, self.client_port)

    def server_text(self):
        return helpers.format_endpoint(self.server_ip, self.server_port)

    def all_frames(self):
        frames = []
        frames.extend(self.syn_frames)
        frames.extend(self.syn_ack_frames)
        frames.extend(self.rst_frames)
        frames.extend(self.icmp_frames)
        frames.sort(key=lambda frame: frame.number)
        return frames


def collect_attempts(frames):
    """Walk through the capture and build a list of HandshakeAttempt objects."""

    # Maps (client_ip, client_port, server_ip, server_port) to the latest attempt.
    current_attempts = {}

    # Every attempt we have seen, in order, so nothing gets lost when a
    # client reuses the same port for a later connection.
    all_attempts = []

    for frame in frames:
        packet = frame.packet

        # An ICMP "destination unreachable" (type 3) that quotes one of our SYNs.
        # (Only IPv4, to keep things simple.)
        is_icmp_unreachable = packet.haslayer(ICMP) and packet[ICMP].type == 3
        if is_icmp_unreachable and packet.haslayer(IPerror) and packet.haslayer(TCPerror):
            quoted_ip = packet[IPerror]
            quoted_tcp = packet[TCPerror]
            key = (quoted_ip.src, quoted_tcp.sport, quoted_ip.dst, quoted_tcp.dport)
            attempt = current_attempts.get(key)
            if attempt is not None and not attempt.is_complete():
                attempt.icmp_frames.append(frame)
            continue

        if not packet.haslayer(TCP):
            continue

        addresses = helpers.get_ip_addresses(packet)
        if addresses is None:
            continue
        source_ip, destination_ip = addresses

        tcp = packet[TCP]
        flags = helpers.tcp_flags_value(packet)
        is_syn = helpers.has_flag(flags, helpers.TCP_SYN)
        is_ack = helpers.has_flag(flags, helpers.TCP_ACK)
        is_rst = helpers.has_flag(flags, helpers.TCP_RST)

        # Key written from the point of view of this packet's sender.
        forward_key = (source_ip, tcp.sport, destination_ip, tcp.dport)
        # Key written from the point of view of this packet's receiver.
        reverse_key = (destination_ip, tcp.dport, source_ip, tcp.sport)

        if is_syn and not is_ack:
            # Client is opening a connection (or retrying a SYN).
            attempt = current_attempts.get(forward_key)
            if attempt is None or attempt.is_complete():
                attempt = HandshakeAttempt(source_ip, tcp.sport, destination_ip, tcp.dport)
                current_attempts[forward_key] = attempt
                all_attempts.append(attempt)
            attempt.syn_frames.append(frame)

        elif is_syn and is_ack:
            # Server answering a SYN.
            attempt = current_attempts.get(reverse_key)
            if attempt is not None and not attempt.is_complete():
                attempt.syn_ack_frames.append(frame)

        elif is_rst:
            # A reset from the server before the handshake finished
            # means "nobody is listening on that port".
            attempt = current_attempts.get(reverse_key)
            if attempt is not None and not attempt.is_complete():
                attempt.rst_frames.append(frame)

        elif is_ack:
            # Client's ACK after receiving the SYN-ACK finishes the handshake.
            attempt = current_attempts.get(forward_key)
            if attempt is not None and len(attempt.syn_ack_frames) > 0:
                if not attempt.is_complete():
                    attempt.final_ack_frame = frame

    return all_attempts


def find_issues(frames, capture_end):
    """Return a list of Issue objects for failed TCP handshakes."""
    issues = []
    attempts = collect_attempts(frames)

    for attempt in attempts:
        if attempt.is_complete():
            continue

        involved_frames = attempt.all_frames()
        frame_numbers = helpers.frame_numbers_of(involved_frames)
        syn_count = len(attempt.syn_frames)
        last_frame_time = involved_frames[-1].time

        if len(attempt.rst_frames) > 0 and len(attempt.syn_ack_frames) == 0:
            # Server actively refused the connection.
            issue = Issue(
                check=CHECK_NAME,
                severity=ERROR,
                summary="Connection refused: " + attempt.client_text()
                + " -> " + attempt.server_text(),
                details=[
                    "The client sent " + str(syn_count) + " SYN packet(s) and the server answered with RST.",
                    "Likely cause: no service is listening on port " + str(attempt.server_port)
                    + ", or a firewall is rejecting the connection.",
                ],
                frame_numbers=frame_numbers,
            )
            issues.append(issue)

        elif len(attempt.syn_ack_frames) == 0 and len(attempt.icmp_frames) > 0:
            # A router told the client the server cannot be reached.
            first_icmp_packet = attempt.icmp_frames[0].packet
            router = helpers.get_ip_addresses(first_icmp_packet)[0]
            issue = Issue(
                check=CHECK_NAME,
                severity=ERROR,
                summary="SYN rejected by router " + router + ": " + attempt.client_text()
                + " -> " + attempt.server_text(),
                details=[
                    "The client sent " + str(syn_count) + " SYN packet(s); router " + router + " answered with "
                    + str(len(attempt.icmp_frames)) + " ICMP 'destination unreachable' message(s) instead of the server replying.",
                    "See the matching ICMP issue for the exact reason (no route, ACL, host down).",
                ],
                frame_numbers=frame_numbers,
            )
            issues.append(issue)

        elif len(attempt.syn_ack_frames) == 0:
            # SYN went out, nothing came back.
            severity = ERROR
            details = [
                "The client sent " + str(syn_count) + " SYN packet(s) and never got a SYN-ACK or RST back.",
                "Likely cause: the server is down, unreachable, or a firewall is silently dropping the packets.",
            ]
            if syn_count > 1:
                retry_seconds = attempt.syn_frames[-1].time - attempt.syn_frames[0].time
                details.append("The client kept retrying for " + str(round(retry_seconds, 1)) + " seconds.")

            if syn_count == 1 and helpers.near_capture_end(last_frame_time, capture_end):
                severity = INFO
                details.append("Note: the capture ended just after this SYN, so the reply may simply not have been captured.")

            issue = Issue(
                check=CHECK_NAME,
                severity=severity,
                summary="No response to SYN: " + attempt.client_text()
                + " -> " + attempt.server_text(),
                details=details,
                frame_numbers=frame_numbers,
            )
            issues.append(issue)

        else:
            # SYN-ACK came back but the client never finished the handshake.
            severity = WARNING
            details = [
                "The server answered with " + str(len(attempt.syn_ack_frames))
                + " SYN-ACK packet(s) but the client never sent the final ACK.",
                "Likely cause: the SYN-ACK was dropped on the way back (asymmetric routing or a firewall),"
                + " or the client gave up / was flooded with half-open connections.",
            ]
            if helpers.near_capture_end(last_frame_time, capture_end):
                severity = INFO
                details.append("Note: the capture ended just after the SYN-ACK, so the ACK may not have been captured.")

            issue = Issue(
                check=CHECK_NAME,
                severity=severity,
                summary="Handshake not completed: " + attempt.client_text()
                + " -> " + attempt.server_text(),
                details=details,
                frame_numbers=frame_numbers,
            )
            issues.append(issue)

    return issues
