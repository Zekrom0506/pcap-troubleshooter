"""
Turns an AnalysisResult into a readable report.

Supported formats:
    text      - plain text for the terminal
    markdown  - a .md file (renders nicely on GitHub)
    html      - a single self-contained web page
    json      - machine-readable, for scripts
"""

import html
import json
from datetime import datetime

from pcap_troubleshooter.models import ERROR, WARNING, INFO

SEVERITIES = [ERROR, WARNING, INFO]


def format_time(timestamp):
    """Turn a Unix timestamp into readable text."""
    if timestamp == 0:
        return "-"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def frames_text(issue, limit=30):
    """List the frame numbers of an issue, shortening very long lists."""
    numbers = sorted(set(issue.frame_numbers))
    shown = []
    for number in numbers[:limit]:
        shown.append(str(number))
    text = ", ".join(shown)
    if len(numbers) > limit:
        text = text + " ... (" + str(len(numbers)) + " frames in total)"
    return text


# ---------------------------------------------------------------- text

def build_text_report(result):
    lines = []
    lines.append("=" * 72)
    lines.append("PACKET CAPTURE TROUBLESHOOTING REPORT")
    lines.append("=" * 72)
    lines.append("File:      " + result.file_path)
    lines.append("Packets:   " + str(result.packet_count))
    lines.append("Captured:  " + format_time(result.start_time) + "  ->  " + format_time(result.end_time)
                 + "  (" + str(round(result.duration_seconds(), 1)) + " s)")

    protocol_parts = []
    for name, count in result.protocol_counts.items():
        protocol_parts.append(name + "=" + str(count))
    lines.append("Protocols: " + "  ".join(protocol_parts))
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 72)
    lines.append("  Errors: " + str(result.count_by_severity(ERROR))
                 + "   Warnings: " + str(result.count_by_severity(WARNING))
                 + "   Info: " + str(result.count_by_severity(INFO)))
    lines.append("")
    for check_name in result.checks_run:
        count = result.count_by_check(check_name)
        status = "OK" if count == 0 else str(count) + " issue(s)"
        lines.append("  " + check_name.ljust(22) + status)
    lines.append("")

    if len(result.issues) == 0:
        lines.append("No problems found. The capture looks healthy.")
        return "\n".join(lines)

    lines.append("ISSUES")
    lines.append("-" * 72)
    issue_number = 1
    for issue in result.issues:
        lines.append("")
        lines.append("#" + str(issue_number) + " [" + issue.severity + "] " + issue.check + ": " + issue.summary)
        for detail in issue.details:
            lines.append("    " + detail)
        lines.append("    Frames: " + frames_text(issue))
        lines.append("    Wireshark filter: " + issue.wireshark_filter())
        issue_number = issue_number + 1

    return "\n".join(lines)


# ------------------------------------------------------------ markdown

SEVERITY_ICONS = {ERROR: "🔴", WARNING: "🟠", INFO: "🔵"}


def build_markdown_report(result):
    lines = []
    lines.append("# Packet Capture Troubleshooting Report")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append("| **File** | `" + result.file_name() + "` |")
    lines.append("| **Packets** | " + str(result.packet_count) + " |")
    lines.append("| **Captured** | " + format_time(result.start_time) + " → " + format_time(result.end_time)
                 + " (" + str(round(result.duration_seconds(), 1)) + " s) |")
    protocol_parts = []
    for name, count in result.protocol_counts.items():
        protocol_parts.append(name + " " + str(count))
    lines.append("| **Protocols** | " + ", ".join(protocol_parts) + " |")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("**" + str(result.count_by_severity(ERROR)) + "** errors, **"
                 + str(result.count_by_severity(WARNING)) + "** warnings, **"
                 + str(result.count_by_severity(INFO)) + "** info")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for check_name in result.checks_run:
        count = result.count_by_check(check_name)
        status = "✅ OK" if count == 0 else str(count) + " issue(s)"
        lines.append("| " + check_name + " | " + status + " |")
    lines.append("")

    if len(result.issues) == 0:
        lines.append("No problems found. The capture looks healthy.")
        return "\n".join(lines) + "\n"

    lines.append("## Issues")
    issue_number = 1
    for issue in result.issues:
        lines.append("")
        lines.append("### " + str(issue_number) + ". " + SEVERITY_ICONS.get(issue.severity, "")
                     + " " + issue.severity + " — " + issue.check)
        lines.append("")
        lines.append("**" + issue.summary + "**")
        lines.append("")
        for detail in issue.details:
            lines.append("- " + detail.strip())
        lines.append("")
        lines.append("Frames: " + frames_text(issue))
        lines.append("")
        lines.append("```")
        lines.append(issue.wireshark_filter())
        lines.append("```")
        issue_number = issue_number + 1

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- html

HTML_STYLE = """
:root { --bg:#f7f7f5; --card:#ffffff; --text:#1d1d1b; --muted:#6b6b66; --line:#e3e3de;
        --error:#c0392b; --warning:#b9770e; --info:#2e6da4; --ok:#2e7d32; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161615; --card:#21211f; --text:#ecece8; --muted:#a3a39c; --line:#363632;
          --error:#ef6f61; --warning:#e9a94b; --info:#6fa8dc; --ok:#7cc47f; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font:15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width:960px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:24px; margin:0 0 4px; }
h2 { font-size:18px; margin:32px 0 12px; }
.meta { color:var(--muted); margin-bottom:24px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 16px; }
.tile .n { font-size:28px; font-weight:600; }
.tile.error .n { color:var(--error); } .tile.warning .n { color:var(--warning); } .tile.info .n { color:var(--info); }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
td, th { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); }
tr:last-child td { border-bottom:none; }
.ok { color:var(--ok); }
.issue { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--line);
         border-radius:8px; padding:12px 16px; margin-bottom:12px; }
.issue.ERROR { border-left-color:var(--error); } .issue.WARNING { border-left-color:var(--warning); }
.issue.INFO { border-left-color:var(--info); }
.badge { font-size:12px; font-weight:600; padding:2px 8px; border-radius:4px; margin-right:8px; color:#fff; }
.badge.ERROR { background:var(--error); } .badge.WARNING { background:var(--warning); } .badge.INFO { background:var(--info); }
.check { color:var(--muted); font-size:13px; }
.summary { font-weight:600; margin:6px 0; }
ul { margin:6px 0; padding-left:20px; }
code { display:block; background:var(--bg); border:1px solid var(--line); border-radius:4px;
       padding:6px 8px; font-size:13px; overflow-x:auto; white-space:pre; }
.frames { color:var(--muted); font-size:13px; }
"""


def build_html_report(result):
    e = html.escape  # short name for escaping text so it is safe inside HTML
    parts = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>Capture Report - " + e(result.file_name()) + "</title>")
    parts.append("<style>" + HTML_STYLE + "</style></head><body><main>")

    parts.append("<h1>Packet Capture Troubleshooting Report</h1>")
    parts.append("<div class='meta'>" + e(result.file_name()) + " · " + str(result.packet_count) + " packets · "
                 + e(format_time(result.start_time)) + " → " + e(format_time(result.end_time))
                 + " (" + str(round(result.duration_seconds(), 1)) + " s)</div>")

    parts.append("<div class='tiles'>")
    for severity in SEVERITIES:
        label = {ERROR: "Errors", WARNING: "Warnings", INFO: "Info"}[severity]
        parts.append("<div class='tile " + severity.lower() + "'><div class='n'>"
                     + str(result.count_by_severity(severity)) + "</div>" + label + "</div>")
    parts.append("</div>")

    parts.append("<h2>Checks</h2><table><tr><th>Check</th><th>Result</th></tr>")
    for check_name in result.checks_run:
        count = result.count_by_check(check_name)
        if count == 0:
            status = "<span class='ok'>OK</span>"
        else:
            status = str(count) + " issue(s)"
        parts.append("<tr><td>" + e(check_name) + "</td><td>" + status + "</td></tr>")
    parts.append("</table>")

    protocol_parts = []
    for name, count in result.protocol_counts.items():
        protocol_parts.append(e(name) + " " + str(count))
    parts.append("<p class='frames'>Packets per protocol: " + " · ".join(protocol_parts) + "</p>")

    parts.append("<h2>Issues</h2>")
    if len(result.issues) == 0:
        parts.append("<p class='ok'>No problems found. The capture looks healthy.</p>")

    for issue in result.issues:
        parts.append("<div class='issue " + issue.severity + "'>")
        parts.append("<span class='badge " + issue.severity + "'>" + issue.severity + "</span>")
        parts.append("<span class='check'>" + e(issue.check) + "</span>")
        parts.append("<div class='summary'>" + e(issue.summary) + "</div><ul>")
        for detail in issue.details:
            parts.append("<li>" + e(detail.strip()) + "</li>")
        parts.append("</ul><div class='frames'>Frames: " + e(frames_text(issue)) + "</div>")
        parts.append("<div class='frames'>Wireshark filter:</div><code>" + e(issue.wireshark_filter()) + "</code>")
        parts.append("</div>")

    parts.append("</main></body></html>")
    return "\n".join(parts)


# ---------------------------------------------------------------- json

def build_json_report(result):
    issue_list = []
    for issue in result.issues:
        issue_list.append({
            "check": issue.check,
            "severity": issue.severity,
            "summary": issue.summary,
            "details": issue.details,
            "frames": sorted(set(issue.frame_numbers)),
            "wireshark_filter": issue.wireshark_filter(),
        })

    data = {
        "file": result.file_path,
        "packets": result.packet_count,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "protocol_counts": result.protocol_counts,
        "summary": {
            "errors": result.count_by_severity(ERROR),
            "warnings": result.count_by_severity(WARNING),
            "info": result.count_by_severity(INFO),
        },
        "issues": issue_list,
    }
    return json.dumps(data, indent=2)


BUILDERS = {
    "text": build_text_report,
    "markdown": build_markdown_report,
    "html": build_html_report,
    "json": build_json_report,
}

FILE_EXTENSIONS = {"text": ".txt", "markdown": ".md", "html": ".html", "json": ".json"}


def build_report(result, report_format):
    """Build a report in the requested format and return it as a string."""
    builder = BUILDERS.get(report_format)
    if builder is None:
        raise ValueError("Unknown report format: " + report_format)
    return builder(result)
