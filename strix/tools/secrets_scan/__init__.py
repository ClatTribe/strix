"""Secret-detection first-pass tool (roadmap §8.1).

Scans `repository` / `local_code` targets for hard-coded secrets.
Prefers `gitleaks` when installed (highest precision); falls back
to a curated built-in regex catalogue for the high-confidence
patterns when neither external scanner is available.

Zero-FP discipline: only emit findings on patterns that have a
distinctive shape (AWS access key prefix `AKIA`, Stripe key
prefix `sk_live_`, RSA private-key PEM blocks, GitHub PATs that
match the documented prefix). Generic "looks like a long random
string" patterns are deliberately excluded — they're the source
of most secret-scanner false positives.
"""

from .secrets_scan import secrets_scan


__all__ = ["secrets_scan"]
