"""Lets you run the tool with:  python -m pcap_troubleshooter capture.pcap"""

import sys

from pcap_troubleshooter.cli import main

sys.exit(main())
