"""CSV / formula injection probe (roadmap §7.2 nice-to-have).

Tests whether an export endpoint round-trips formula-prefix
characters (`=`, `@`, `+`, `-`) into the downloaded CSV without
sanitisation. When that happens, opening the CSV in Excel /
LibreOffice / Google Sheets executes the formula — historical
exfil vector.

Zero-FP design: emit ONLY when the exact nonce-tagged formula
payload is byte-for-byte present in the downloaded CSV. No
substring heuristics on the body; no probabilistic detection.
"""

from .csv_injection_check import csv_injection_check


__all__ = ["csv_injection_check"]
