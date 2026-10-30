# Packet Capture Troubleshooter

A Python tool that reads Wireshark capture files (`.pcap` / `.pcapng`) and flags common network problems, then writes a report listing each issue together with the exact packets involved.

Built with **Python** and **Scapy**, and checked against **Wireshark** (`tshark`): the frame numbers in every report are the same frame numbers Wireshark shows, and each issue comes with a display filter you can paste straight into Wireshark.

## What it detects

| Check | What it looks for | Example cause |
|---|---|---|
| **TCP Handshake** | SYN with no reply, SYN answered by RST, SYN-ACK never ACKed, SYN answered by an ICMP error from a router | Server down, port closed, firewall, missing route |
| **TCP Retransmissions** | Data segments sent again (same sequence numbers), per flow, with retransmission rate | Packet loss, congestion, bad link, MTU black hole |
| **DNS** | Queries that never got an answer (retries grouped), plus SERVFAIL / REFUSED / NXDOMAIN answers | DNS server down, UDP 53 blocked, wrong resolver, typo |
| **DHCP** | DISCOVER with no OFFER, OFFER with no REQUEST, REQUEST with no ACK, NAK, DECLINE | No DHCP server, missing `ip helper-address`, pool exhausted |
| **ARP Conflict** | One IP address claimed by two MAC addresses, ARP probes answered by another device | Duplicate static IP, static IP inside the DHCP pool |
| **ICMP** | Destination Unreachable (network / host / port / fragmentation needed / admin prohibited), Time Exceeded | Missing route, ACL, closed UDP port, MTU, routing loop |

Every issue gets a severity (`ERROR`, `WARNING`, `INFO`), a plain-English explanation with the likely cause, the list of frames involved, and a Wireshark filter such as `frame.number in {6 8 10 12}`.

The tool also avoids common false alarms found on real networks: it tells out-of-order packets apart from retransmissions (using the same rules as Wireshark), ignores mDNS/LLMNR, keep-alives and Ethernet padding, recognises traceroute probes and late DNS replies, knows when a DHCP reply could not have been visible in the capture, and lowers the severity of anything in the last few seconds of a capture.

**Tested on my own network:** on a 44,000-packet capture of my home Wi-Fi, the tool flagged 97% of the data retransmissions Wireshark flags, with only 5 extra (details in [`docs/how_it_works.md`](docs/how_it_works.md#tested-on-my-own-network)).

## Quick start

```bash
# 1. Install (Python 3.9+)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Run it on a capture
python troubleshoot.py captures/routing_lab/missing_route.pcapng
```

Sample output (shortened):

```
SUMMARY
------------------------------------------------------------------------
  Errors: 5   Warnings: 0   Info: 0

  TCP Handshake         1 issue(s)
  TCP Retransmissions   OK
  DNS                   1 issue(s)
  DHCP                  OK
  ARP Conflict          OK
  ICMP                  3 issue(s)

#1 [ERROR] ICMP: Network unreachable: 10.0.12.2 reports 192.168.30.10
    10.0.12.2 sent 4 ICMP 'Network unreachable' message(s) about traffic from 192.168.10.10 to 192.168.30.10.
    Likely cause: a router has no route to the destination network (missing or wrong route).
    Frames: 6, 8, 10, 12
    Wireshark filter: frame.number in {6 8 10 12}
...
#4 [ERROR] TCP Handshake: SYN rejected by router 10.0.12.2: 192.168.10.10:41500 -> 192.168.30.10:80
```

Full example reports are in [`examples/`](examples/) (text, Markdown, HTML and JSON).

## Usage

```bash
python troubleshoot.py <capture> [<capture> ...] [options]
```

| Option | Meaning |
|---|---|
| `-f, --format text\|markdown\|html\|json` | Report format (default `text`) |
| `-o, --output FILE` | Save the report to a file |
| `-d, --output-dir DIR` | One report per capture, saved in `DIR` |
| `--only handshake retransmissions dns dhcp arp icmp` | Run only some checks |
| `--min-severity ERROR\|WARNING\|INFO` | Hide less serious issues |

Examples:

```bash
# HTML report you can open in a browser
python troubleshoot.py my_capture.pcapng -f html -o report.html

# A report for every capture in the routing lab
python troubleshoot.py captures/routing_lab/*.pcapng -d reports -f markdown

# Only DNS and DHCP problems, errors only
python troubleshoot.py my_capture.pcapng --only dns dhcp --min-severity ERROR
```

The exit code is `0` when no errors were found, `1` when errors were found and `2` if a file could not be read, so the tool can be used in scripts.

## Capturing your own network

1. Open Wireshark, pick your Wi-Fi/Ethernet interface, capture for a few minutes while using the network, then **File → Save As** (`.pcapng`).
   Or from a terminal: `./scripts/capture_my_network.sh` (uses `tcpdump`, asks for your password).
2. Run `python troubleshoot.py captures/my_network/<file>.pcapng`.
3. Copy the Wireshark filter from any issue into Wireshark's display filter bar to look at those exact packets.

Tips for good captures: start the capture *before* reproducing the problem (e.g. turn Wi-Fi off and on to catch DHCP), and capture on the machine that has the problem.

## Test captures

`samples/generate_samples.py` uses Scapy to build realistic captures with known faults mixed into normal traffic:

**`captures/basic/`** – one file per problem type on a home network
`healthy_home_network`, `tcp_handshake_failures`, `tcp_retransmissions`, `dns_failures`, `dhcp_failures`, `arp_conflict`, `icmp_unreachable`

**`captures/routing_lab/`** – failures simulated on a three-router lab (diagram in [`docs/routing_lab.md`](docs/routing_lab.md))

| Capture | Simulated fault | What the tool reports |
|---|---|---|
| `missing_route.pcapng` | R2 has no route to LAN B | ICMP network unreachable from R2, unanswered DNS, SYN rejected by R2 |
| `dhcp_relay_missing.pcapng` | No `ip helper-address` on R1 | DISCOVERs with no OFFER for PC2 and PC3 |
| `dhcp_relay_working.pcapng` | Same lab after the fix | No problems |
| `acl_blocking_ssh.pcapng` | ACL on R3 denies SSH | ICMP admin prohibited from R3, SYN to port 22 rejected |
| `routing_loop.pcapng` | R2 and R3 point at each other | TTL exceeded (warning); traceroute probes correctly marked INFO |
| `lossy_wan_link.pcapng` | Errors on the R1–R2 serial link | ~11% retransmissions on the FTP transfer |
| `duplicate_gateway_ip.pcapng` | A PC configured with R1's IP | ARP conflict on 192.168.10.1, connection refused |
| `all_working.pcapng` | Everything fixed | No problems |

Regenerate them any time with `python samples/generate_samples.py`.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

59 tests: unit tests for each check using hand-built packets, plus end-to-end tests that run the tool on every sample capture and compare the results with what Wireshark reports (for example, the retransmission frames match Wireshark's `tcp.analysis.retransmission` exactly).

## Project layout

```
troubleshoot.py                  entry point (python troubleshoot.py ...)
pcap_troubleshooter/
    loader.py                    reads .pcap/.pcapng into numbered frames
    models.py                    Frame and Issue classes
    analyzer.py                  runs all checks on a capture
    report.py                    text / markdown / html / json reports
    cli.py                       command line options
    checks/
        tcp_handshake.py
        tcp_retransmissions.py
        dns_queries.py
        dhcp_exchanges.py
        arp_conflicts.py
        icmp_unreachable.py
        helpers.py               shared helper functions
samples/                         scripts that build the test captures
captures/                        test captures (basic, routing_lab, my_network)
examples/                        example reports
docs/                            how the checks work, routing lab diagram
tests/                           pytest tests
```

## Adding a new check

1. Create `pcap_troubleshooter/checks/my_check.py` with a `CHECK_NAME` and a `find_issues(frames, capture_end)` function that returns a list of `Issue` objects.
2. Add the module to `ALL_CHECKS` in `pcap_troubleshooter/checks/__init__.py`.
3. Add a test in `tests/test_checks.py`.

See [`docs/how_it_works.md`](docs/how_it_works.md) for how each existing check decides what is a problem.

## License

MIT, see [LICENSE](LICENSE).
