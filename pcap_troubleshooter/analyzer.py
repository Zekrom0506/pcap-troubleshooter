"""
Runs every check on a capture and gathers the results into one AnalysisResult.
"""

import os
from dataclasses import dataclass, field

from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.inet6 import ICMPv6DestUnreach, ICMPv6TimeExceeded
from scapy.layers.l2 import ARP

from pcap_troubleshooter.checks import ALL_CHECKS
from pcap_troubleshooter.loader import load_capture, capture_start_time, capture_end_time
from pcap_troubleshooter.models import SEVERITY_ORDER


@dataclass
class AnalysisResult:
    """Everything the report needs to know about one capture file."""

    file_path: str
    packet_count: int
    start_time: float
    end_time: float
    protocol_counts: dict = field(default_factory=dict)
    issues: list = field(default_factory=list)
    checks_run: list = field(default_factory=list)

    def file_name(self):
        return os.path.basename(self.file_path)

    def duration_seconds(self):
        return self.end_time - self.start_time

    def count_by_severity(self, severity):
        total = 0
        for issue in self.issues:
            if issue.severity == severity:
                total = total + 1
        return total

    def count_by_check(self, check_name):
        total = 0
        for issue in self.issues:
            if issue.check == check_name:
                total = total + 1
        return total


def count_protocols(frames):
    """Count how many packets of each interesting protocol are in the capture."""
    counts = {"TCP": 0, "UDP": 0, "DNS": 0, "DHCP": 0, "ARP": 0, "ICMP": 0}

    for frame in frames:
        packet = frame.packet
        if packet.haslayer(TCP):
            counts["TCP"] = counts["TCP"] + 1
        if packet.haslayer(UDP):
            counts["UDP"] = counts["UDP"] + 1
        if packet.haslayer(DNS):
            counts["DNS"] = counts["DNS"] + 1
        if packet.haslayer(DHCP):
            counts["DHCP"] = counts["DHCP"] + 1
        if packet.haslayer(ARP):
            counts["ARP"] = counts["ARP"] + 1
        if packet.haslayer(ICMP) or packet.haslayer(ICMPv6DestUnreach) or packet.haslayer(ICMPv6TimeExceeded):
            counts["ICMP"] = counts["ICMP"] + 1

    return counts


def sort_key(issue):
    """Sort issues: most serious first, then by the first frame involved."""
    first_frame = 0
    if len(issue.frame_numbers) > 0:
        first_frame = min(issue.frame_numbers)
    return (SEVERITY_ORDER.get(issue.severity, 99), first_frame)


def analyze_frames(frames, file_path="<memory>", checks=None):
    """Run the checks on frames that are already loaded."""
    if checks is None:
        checks = ALL_CHECKS

    end = capture_end_time(frames)
    all_issues = []
    check_names = []

    for check in checks:
        check_names.append(check.CHECK_NAME)
        found = check.find_issues(frames, end)
        all_issues.extend(found)

    all_issues.sort(key=sort_key)

    return AnalysisResult(
        file_path=file_path,
        packet_count=len(frames),
        start_time=capture_start_time(frames),
        end_time=end,
        protocol_counts=count_protocols(frames),
        issues=all_issues,
        checks_run=check_names,
    )


def analyze_file(file_path, checks=None):
    """Load a capture file from disk and run the checks on it."""
    frames = load_capture(file_path)
    return analyze_frames(frames, file_path, checks)
