"""
Reads a Wireshark capture file (.pcap or .pcapng) into a list of Frame objects.
"""

import os

from scapy.utils import PcapReader

from pcap_troubleshooter.models import Frame


def load_capture(file_path):
    """
    Read every packet in the capture file and return a list of Frame objects.

    Scapy's PcapReader understands both the old .pcap format and the newer
    .pcapng format that Wireshark saves by default.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Capture file not found: " + file_path)

    frames = []
    frame_number = 1

    # PcapReader reads one packet at a time, so even big files
    # do not have to be loaded in a single step.
    reader = PcapReader(file_path)
    try:
        for packet in reader:
            frame = Frame(
                number=frame_number,
                time=float(packet.time),
                packet=packet,
            )
            frames.append(frame)
            frame_number = frame_number + 1
    finally:
        reader.close()

    return frames


def capture_end_time(frames):
    """Return the timestamp of the last packet, or 0 if the capture is empty."""
    if len(frames) == 0:
        return 0.0
    return frames[-1].time


def capture_start_time(frames):
    """Return the timestamp of the first packet, or 0 if the capture is empty."""
    if len(frames) == 0:
        return 0.0
    return frames[0].time
