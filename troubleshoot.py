"""
Entry point:  python troubleshoot.py <capture file> [options]

Run "python troubleshoot.py --help" to see all options.
"""

import sys

from pcap_troubleshooter.cli import main

if __name__ == "__main__":
    sys.exit(main())
