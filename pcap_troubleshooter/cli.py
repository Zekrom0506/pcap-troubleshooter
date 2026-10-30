"""
Command line interface.

Examples:
    python troubleshoot.py capture.pcapng
    python troubleshoot.py capture.pcapng --format html --output report.html
    python troubleshoot.py captures/*.pcap --output-dir reports --format markdown
    python troubleshoot.py capture.pcap --only dns dhcp
    python troubleshoot.py capture.pcap --min-severity WARNING
"""

import argparse
import os
import sys

from pcap_troubleshooter.analyzer import analyze_file
from pcap_troubleshooter.checks import ALL_CHECKS
from pcap_troubleshooter.models import SEVERITY_ORDER, ERROR
from pcap_troubleshooter.report import build_report, BUILDERS, FILE_EXTENSIONS

# Short names you can pass to --only.
CHECK_SHORT_NAMES = {
    "handshake": "TCP Handshake",
    "retransmissions": "TCP Retransmissions",
    "dns": "DNS",
    "dhcp": "DHCP",
    "arp": "ARP Conflict",
    "icmp": "ICMP",
}


def build_argument_parser():
    parser = argparse.ArgumentParser(
        prog="troubleshoot",
        description="Find common network problems in Wireshark capture files (.pcap / .pcapng).",
    )
    parser.add_argument("captures", nargs="+", help="one or more capture files")
    parser.add_argument("-f", "--format", choices=list(BUILDERS.keys()), default="text",
                        help="report format (default: text)")
    parser.add_argument("-o", "--output", help="write the report to this file instead of the screen")
    parser.add_argument("-d", "--output-dir",
                        help="write one report per capture into this folder")
    parser.add_argument("--only", nargs="+", choices=list(CHECK_SHORT_NAMES.keys()),
                        help="run only these checks")
    parser.add_argument("--min-severity", choices=["ERROR", "WARNING", "INFO"], default="INFO",
                        help="hide issues less serious than this (default: show everything)")
    return parser


def choose_checks(short_names):
    """Turn the --only names into the list of check modules to run."""
    if not short_names:
        return ALL_CHECKS

    wanted = []
    for short_name in short_names:
        wanted.append(CHECK_SHORT_NAMES[short_name])

    chosen = []
    for check in ALL_CHECKS:
        if check.CHECK_NAME in wanted:
            chosen.append(check)
    return chosen


def remove_less_serious(result, min_severity):
    """Drop issues that are less serious than min_severity."""
    limit = SEVERITY_ORDER[min_severity]
    kept = []
    for issue in result.issues:
        if SEVERITY_ORDER[issue.severity] <= limit:
            kept.append(issue)
    result.issues = kept


def main(argument_list=None):
    parser = build_argument_parser()
    args = parser.parse_args(argument_list)

    if args.output and len(args.captures) > 1:
        parser.error("--output works with one capture; use --output-dir for several")

    checks = choose_checks(args.only)
    found_any_error = False

    for capture_path in args.captures:
        try:
            result = analyze_file(capture_path, checks)
        except FileNotFoundError as problem:
            print("error: " + str(problem), file=sys.stderr)
            return 2
        except Exception as problem:  # Scapy raises different errors for broken files
            print("error: could not read " + capture_path + ": " + str(problem), file=sys.stderr)
            return 2

        remove_less_serious(result, args.min_severity)
        if result.count_by_severity(ERROR) > 0:
            found_any_error = True

        report_text = build_report(result, args.format)

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            base_name = os.path.splitext(os.path.basename(capture_path))[0]
            report_path = os.path.join(args.output_dir, base_name + "_report" + FILE_EXTENSIONS[args.format])
            with open(report_path, "w", encoding="utf-8") as report_file:
                report_file.write(report_text)
            print("Wrote " + report_path + "  (" + str(len(result.issues)) + " issue(s))")
        elif args.output:
            with open(args.output, "w", encoding="utf-8") as report_file:
                report_file.write(report_text)
            print("Wrote " + args.output + "  (" + str(len(result.issues)) + " issue(s))")
        else:
            print(report_text)
            if len(args.captures) > 1:
                print("")

    # Exit code 1 when errors were found, so scripts can react to it.
    if found_any_error:
        return 1
    return 0
