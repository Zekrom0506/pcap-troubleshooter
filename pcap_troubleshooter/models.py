"""
Small data classes that the rest of the program passes around.

Frame  - one packet from the capture file, plus its Wireshark frame number.
Issue  - one problem the tool found, plus the frames that show the problem.
"""

from dataclasses import dataclass, field


# Severity levels, from most to least serious.
# The report sorts issues using SEVERITY_ORDER.
ERROR = "ERROR"
WARNING = "WARNING"
INFO = "INFO"

SEVERITY_ORDER = {ERROR: 0, WARNING: 1, INFO: 2}


@dataclass
class Frame:
    """One packet read from the capture file."""

    # Wireshark numbers frames starting at 1, so we do the same.
    # That way "frame 42" in our report is "frame 42" in Wireshark too.
    number: int

    # Time the packet was captured, in seconds since the Unix epoch.
    time: float

    # The Scapy packet object itself (Ether / IP / TCP / ... layers).
    packet: object


@dataclass
class Issue:
    """One problem found in the capture."""

    # Which check found it, for example "TCP Handshake".
    check: str

    # ERROR, WARNING or INFO.
    severity: str

    # One line describing the problem.
    summary: str

    # Extra lines of explanation (who, what, how many times, likely cause).
    details: list = field(default_factory=list)

    # Wireshark frame numbers of the packets involved.
    frame_numbers: list = field(default_factory=list)

    def wireshark_filter(self):
        """
        Build a display filter you can paste into Wireshark to see
        exactly the packets involved in this issue.
        """
        if len(self.frame_numbers) == 0:
            return ""

        # Sort and remove duplicates.
        unique_numbers = sorted(set(self.frame_numbers))

        number_strings = []
        for number in unique_numbers:
            number_strings.append(str(number))

        return "frame.number in {" + " ".join(number_strings) + "}"
