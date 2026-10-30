"""
Check: ARP conflicts (two devices using the same IP address).

ARP maps an IP address to a MAC (hardware) address. Every ARP request and
reply tells us "IP address X belongs to MAC address Y". If we see the same
IP address claimed by two different MAC addresses, two devices are probably
configured with the same IP, and traffic will flip between them.

We also catch the case where a device "probes" for an address before using
it (an ARP request sent from 0.0.0.0) and another device answers saying the
address is already taken.

Note: a few setups do this on purpose (router failover with VRRP/HSRP,
proxy ARP). In those cases the report can be safely ignored.
"""

from scapy.layers.l2 import ARP

from pcap_troubleshooter.checks import helpers
from pcap_troubleshooter.models import Issue, ERROR

CHECK_NAME = "ARP Conflict"

ARP_REQUEST = 1
ARP_REPLY = 2
EMPTY_IP = "0.0.0.0"


def find_issues(frames, capture_end):
    """Return an Issue for every IP address claimed by more than one MAC."""

    # ip address -> { mac address -> [frames where that MAC claimed the IP] }
    claims = {}

    # ip address -> list of (prober MAC, frame) for ARP probes asking about that IP
    probes = {}

    for frame in frames:
        packet = frame.packet
        if not packet.haslayer(ARP):
            continue

        arp = packet[ARP]
        operation = int(arp.op)
        sender_ip = arp.psrc
        sender_mac = arp.hwsrc.lower()

        if operation == ARP_REQUEST and sender_ip == EMPTY_IP:
            # ARP probe: "is anyone using this address?"
            target_ip = arp.pdst
            if target_ip not in probes:
                probes[target_ip] = []
            probes[target_ip].append((sender_mac, frame))
            continue

        if operation != ARP_REQUEST and operation != ARP_REPLY:
            continue
        if sender_ip == EMPTY_IP:
            continue

        if sender_ip not in claims:
            claims[sender_ip] = {}
        if sender_mac not in claims[sender_ip]:
            claims[sender_ip][sender_mac] = []
        claims[sender_ip][sender_mac].append(frame)

    issues = []

    # Case 1: one IP address, several MAC addresses claiming it.
    for ip_address, macs in claims.items():
        if len(macs) < 2:
            continue

        details = ["IP address " + ip_address + " is being claimed by " + str(len(macs)) + " different MAC addresses:"]
        involved_frames = []
        for mac, mac_frames in macs.items():
            details.append("  " + mac + " (in " + str(len(mac_frames)) + " ARP packet(s), first at frame "
                           + str(mac_frames[0].number) + ")")
            involved_frames.extend(mac_frames)
        details.append("Likely cause: two devices configured with the same static IP, or a static IP"
                       + " inside the DHCP pool. (Ignore if this is a VRRP/HSRP failover or proxy ARP.)")

        involved_frames.sort(key=lambda f: f.number)
        issues.append(Issue(
            check=CHECK_NAME,
            severity=ERROR,
            summary="Duplicate IP address " + ip_address + " (" + str(len(macs)) + " MACs)",
            details=details,
            frame_numbers=helpers.frame_numbers_of(involved_frames),
        ))

    # Case 2: a device probed for an address and someone else already owns it.
    for ip_address, probe_list in probes.items():
        owners = claims.get(ip_address, {})
        for prober_mac, probe_frame in probe_list:
            for owner_mac, owner_frames in owners.items():
                if owner_mac == prober_mac:
                    continue
                # Only count replies that came after the probe.
                answers = []
                for owner_frame in owner_frames:
                    if owner_frame.number > probe_frame.number:
                        answers.append(owner_frame)
                if len(answers) == 0:
                    continue
                # Do not report again if case 1 already covers this IP.
                if len(owners) >= 2:
                    continue

                involved_frames = [probe_frame]
                involved_frames.extend(answers)
                issues.append(Issue(
                    check=CHECK_NAME,
                    severity=ERROR,
                    summary="Address " + ip_address + " already in use (probe by " + prober_mac + ")",
                    details=[
                        prober_mac + " checked whether " + ip_address + " was free before using it,",
                        "and " + owner_mac + " answered that it already owns that address.",
                        "Likely cause: the address handed out (or typed in) is already used by another device.",
                    ],
                    frame_numbers=helpers.frame_numbers_of(involved_frames),
                ))

    return issues
