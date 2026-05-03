"""File-upload abuse harness.

Roadmap §7.2 web-app expert-pentester gap audit (🔴 critical, last item).
Iterates the standard upload-bypass cohort against a known multipart
upload endpoint: extension switch, double extension, null-byte, alt-
case, trailing-dot/space, magic-byte spoofing, content-type spoofing,
SVG XSS, HTML XSS, path-traversal filenames. Confirms uploads via
fetch-back when the response reveals an artifact URL.
"""

from .file_upload_abuse_check import file_upload_abuse_check


__all__ = ["file_upload_abuse_check"]
