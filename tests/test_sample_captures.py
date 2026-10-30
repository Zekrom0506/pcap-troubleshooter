"""
End-to-end tests: run the whole tool on every sample capture and check that
it reports exactly the problems that were put into that capture.

The captures are created by samples/generate_samples.py.
"""

import json
import os
import subprocess
import sys

import pytest

from pcap_troubleshooter.analyzer import analyze_file
from pcap_troubleshooter.cli import main
from pcap_troubleshooter.models import ERROR, WARNING, INFO
from pcap_troubleshooter.report import build_report

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES = os.path.join(PROJECT_ROOT, "captures")


@pytest.fixture(scope="session", autouse=True)
def sample_captures_exist():
    """Generate the sample captures if they are missing."""
    marker = os.path.join(CAPTURES, "basic", "healthy_home_network.pcap")
    if not os.path.exists(marker):
        script = os.path.join(PROJECT_ROOT, "samples", "generate_samples.py")
        subprocess.run([sys.executable, script], check=True)


def capture(*parts):
    return os.path.join(CAPTURES, *parts)


def issue_list(path):
    """Return [(check, severity, summary), ...] for a capture."""
    result = analyze_file(path)
    found = []
    for issue in result.issues:
        found.append((issue.check, issue.severity, issue.summary))
    return found


def checks_and_severities(path):
    found = []
    for check, severity, _ in issue_list(path):
        found.append((check, severity))
    return sorted(found)


# --------------------------------------------------------------- basic set

def test_healthy_capture_has_no_issues():
    assert issue_list(capture("basic", "healthy_home_network.pcap")) == []


def test_tcp_handshake_capture():
    issues = issue_list(capture("basic", "tcp_handshake_failures.pcap"))
    summaries = " | ".join(summary for _, _, summary in issues)
    assert len(issues) == 3
    assert "No response to SYN" in summaries and "203.0.113.50:443" in summaries
    assert "Connection refused" in summaries and "192.168.1.20:8080" in summaries
    assert "Handshake not completed" in summaries and "198.51.100.7:22" in summaries


def test_tcp_retransmission_capture_matches_wireshark():
    # Wireshark (tcp.analysis.retransmission) flags frames 34, 48 and 69-72 in this file.
    result = analyze_file(capture("basic", "tcp_retransmissions.pcap"))
    frames = []
    for issue in result.issues:
        frames.extend(issue.frame_numbers)
    assert sorted(frames) == [34, 48, 69, 70, 71, 72]
    assert checks_and_severities(capture("basic", "tcp_retransmissions.pcap")) == [
        ("TCP Retransmissions", ERROR), ("TCP Retransmissions", WARNING)]


def test_dns_capture():
    assert checks_and_severities(capture("basic", "dns_failures.pcap")) == [
        ("DNS", ERROR), ("DNS", ERROR), ("DNS", INFO), ("DNS", WARNING)]


def test_dhcp_capture():
    assert checks_and_severities(capture("basic", "dhcp_failures.pcap")) == [
        ("DHCP", ERROR), ("DHCP", ERROR), ("DHCP", ERROR), ("DHCP", WARNING)]


def test_arp_capture():
    issues = issue_list(capture("basic", "arp_conflict.pcap"))
    assert len(issues) == 2
    assert "192.168.1.50" in issues[0][2] or "192.168.1.50" in issues[1][2]


def test_icmp_capture():
    summaries = [summary for _, _, summary in issue_list(capture("basic", "icmp_unreachable.pcap"))]
    assert len(summaries) == 3
    assert any("Host unreachable" in s for s in summaries)
    assert any("Port unreachable" in s and "161/udp" in s for s in summaries)
    assert any("Fragmentation needed" in s for s in summaries)


# --------------------------------------------------------- routing lab set

def test_lab_all_working_is_clean():
    assert issue_list(capture("routing_lab", "all_working.pcapng")) == []


def test_lab_dhcp_relay_working_is_clean():
    assert issue_list(capture("routing_lab", "dhcp_relay_working.pcapng")) == []


def test_lab_missing_route():
    issues = issue_list(capture("routing_lab", "missing_route.pcapng"))
    checks = sorted(check for check, _, _ in issues)
    assert checks == ["DNS", "ICMP", "ICMP", "ICMP", "TCP Handshake"]
    for _, severity, summary in issues:
        assert severity == ERROR
        if "ICMP" in summary or "unreachable" in summary:
            assert "10.0.12.2" in summary


def test_lab_dhcp_relay_missing():
    assert checks_and_severities(capture("routing_lab", "dhcp_relay_missing.pcapng")) == [
        ("DHCP", ERROR), ("DHCP", ERROR)]


def test_lab_acl_blocking():
    issues = issue_list(capture("routing_lab", "acl_blocking_ssh.pcapng"))
    summaries = " | ".join(summary for _, _, summary in issues)
    assert "administratively prohibited" in summaries
    assert "SYN rejected by router 10.0.23.6" in summaries
    assert ":22" in summaries


def test_lab_routing_loop():
    assert checks_and_severities(capture("routing_lab", "routing_loop.pcapng")) == [
        ("ICMP", INFO), ("ICMP", INFO), ("ICMP", WARNING)]


def test_lab_lossy_wan():
    assert checks_and_severities(capture("routing_lab", "lossy_wan_link.pcapng")) == [
        ("TCP Retransmissions", WARNING)]


def test_lab_duplicate_gateway_ip():
    issues = issue_list(capture("routing_lab", "duplicate_gateway_ip.pcapng"))
    assert ("ARP Conflict", ERROR, "Duplicate IP address 192.168.10.1 (2 MACs)") in issues


# ------------------------------------------------------- reports and CLI

@pytest.mark.parametrize("report_format", ["text", "markdown", "html", "json"])
def test_every_report_format_builds(report_format):
    result = analyze_file(capture("routing_lab", "missing_route.pcapng"))
    text = build_report(result, report_format)
    assert "192.168.30.10" in text
    assert "frame.number in {" in text


def test_json_report_is_valid():
    result = analyze_file(capture("basic", "dns_failures.pcap"))
    data = json.loads(build_report(result, "json"))
    assert data["summary"]["errors"] == 2
    assert data["issues"][0]["frames"] == [19, 20, 21]


def test_cli_exit_codes(tmp_path):
    assert main([capture("basic", "healthy_home_network.pcap"), "-o", str(tmp_path / "ok.txt")]) == 0
    assert main([capture("basic", "dns_failures.pcap"), "-o", str(tmp_path / "bad.txt")]) == 1
    assert main([str(tmp_path / "missing.pcap")]) == 2


def test_cli_output_dir_and_filters(tmp_path):
    out_dir = tmp_path / "reports"
    main([capture("basic", "dns_failures.pcap"), capture("basic", "arp_conflict.pcap"),
          "-d", str(out_dir), "-f", "markdown", "--only", "dns"])
    dns_report = (out_dir / "dns_failures_report.md").read_text()
    arp_report = (out_dir / "arp_conflict_report.md").read_text()
    assert "Unanswered DNS query" in dns_report
    assert "No problems found" in arp_report  # ARP check was not run


def test_cli_min_severity(tmp_path):
    out_file = tmp_path / "r.json"
    main([capture("basic", "dns_failures.pcap"), "-f", "json", "-o", str(out_file), "--min-severity", "ERROR"])
    data = json.loads(out_file.read_text())
    assert len(data["issues"]) == 2
