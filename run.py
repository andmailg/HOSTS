#!/usr/bin/env python3
"""run.py — Пусковой файл с параметрами по умолчанию"""

import subprocess
import sys
from pathlib import Path

script = Path(__file__).parent / "adblock-generator.py"

sys.exit(subprocess.run([
    sys.executable,
    str(script),
    str(Path(__file__).parent / "urls.txt"),
    "1",      # max_depth
    "50",     # max_pages
    "180",    # scan_timeout (сек)
    "5"       # poll_interval (сек)
]).returncode)
