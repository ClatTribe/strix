---
name: dspm-pii-classification
description: Data Security Posture Management — sample-and-classify PII / PHI / PCI / secrets in cloud stores (S3 / GCS / Azure Blob / BigQuery / RDS)
triggers: [dspm, data security, pii, phi, pci, gdpr, sensitive data, data classification, scc data sensitivity]
---

# DSPM — Data Security Posture Management

DSPM is Wiz's fastest-growing 2025-2026 revenue line. The thesis: enterprises have *cloud security posture* (CSPM — who can access what) but no *data security posture* (DSPM — which buckets / tables / files contain PII / PHI / PCI / secrets that the access controls protect). Strix already has the cloud graph + asset discovery; DSPM is the data-content layer on top.

This skill is **forward-looking** — DSPM is open in masterroadmap §5 (P1, L). It documents the design space + canonical detection patterns + how it'll integrate with the existing cloud KG so the agent can reason about DSPM findings even before the dedicated specialist ships.

## Why DSPM Matters

**Without DSPM**: "This S3 bucket is public" — severity ambiguous; auditor asks "what's in it?"
**With DSPM**: "This S3 bucket is public AND contains 47 GB of files with SSN-shaped data" — severity unambiguous; auditor escalates immediately.

The CSPM + DSPM combination converts "cloud posture findings" from compliance-theatre into incident-class.

## Data Classes (the standard taxonomy)

| Class | Examples | Regulatory weight |
|---|---|---|
| **PII** (Personally Identifiable Information) | Name + email, name + phone, name + DOB, full address, IP + name | GDPR, CCPA, LGPD, state-level (US) |
| **PHI** (Protected Health Information) | Medical record, diagnosis, procedure code, prescription | HIPAA (US) |
| **PCI** (Payment Card Industry) | Credit card number, CVV, full track data | PCI-DSS |
| **Financial** | Bank account, routing, account balance, transaction history | SOX (where applicable), GLBA, regional |
| **Credentials** | Passwords, API keys, OAuth tokens, SSH keys, private certs | Internal policy + downstream |
| **Trade secrets** | Source code, customer lists, M&A docs, financial projections | Internal + IP law |
| **Geo / location data** | GPS coords, device cell-tower history | GDPR (special category), CCPA |
| **Biometric** | Fingerprints, face vectors, iris scans | GDPR Art. 9, BIPA (Illinois) |

## Detection Patterns

### Pattern 1 — Regex over file content

Cheap, broad-strokes. Run inside the sample window only.

```python
import re

PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card_visa": re.compile(r"\b4\d{12}(\d{3})?\b"),
    "credit_card_mc": re.compile(r"\b5[1-5]\d{14}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone_us": re.compile(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
}

def classify(text: str) -> dict[str, int]:
    return {name: len(p.findall(text)) for name, p in PATTERNS.items() if p.search(text)}
```

### Pattern 2 — Schema-aware (for structured stores)

For RDS / BigQuery / DynamoDB / Snowflake, column NAMES leak intent:

```python
SENSITIVE_COLUMN_PATTERNS = [
    ("ssn", r"\bssn\b|\bsocial[_]?security"),
    ("dob", r"\bdob\b|date[_]?of[_]?birth|birth[_]?date"),
    ("email", r"\bemail\b"),
    ("password", r"\bpassword\b|pwd|passwd"),
    ("api_key", r"api[_]?key|secret[_]?key"),
    ("phone", r"\bphone\b|mobile|cell"),
    ("address", r"address|street|city|zip|postal"),
    ("payment", r"card[_]?num|cvv|cc[_]?num|pan\b"),
]
```

Combined: column name suggests sensitive + the column has values matching the regex = high-confidence.

### Pattern 3 — ML-based (industry-standard tooling)

- **AWS Macie** — managed; SSN, credit card, AWS keys, custom data types
- **GCP Cloud DLP** — managed; 100+ infoTypes
- **Azure Purview** — managed; broad classifier coverage
- **Custom**: Strix can wrap any of these for one-off engagements via subprocess

For mid-market, regex + schema-aware covers 80% at zero marginal cost.

### Pattern 4 — Sampling strategy

Full-bucket scans are prohibitive. Sample:
- First 10 / largest 10 / most-recent 10 objects per bucket
- Random 1% over a 1 GB ceiling
- All objects matching high-value extensions: `.csv`, `.xlsx`, `.json`, `.sql`, `.bak`, `.dump`, `.env`, `.pem`

## Operational Runbook (when the specialist ships)

### Step 1 — enumerate sensitive-likely buckets

```bash
# Start from the cloud KG — buckets are already enumerated
strix kg_query_nodes --type CloudResource --filters '{"service": "s3"}'

# Filter by name heuristics (often the bucket name leaks intent)
SENSITIVE_NAME_PATTERNS='customer|user|prod|backup|export|pii|hr|finance|payroll'
```

### Step 2 — sample + classify

```bash
# Per bucket: sample 10 objects, classify each
strix dspm_scan --bucket <BUCKET_NAME> --sample-size 10 --max-bytes 1048576
```

Output: per-file classification + per-bucket aggregation.

### Step 3 — cross-reference with access posture

```bash
# Join the DSPM finding to the cloud KG
strix kg_query_paths --start <bucket> --end <internet>
# If a path exists AND the bucket contains PII → critical
```

This is the canonical DSPM finding shape: **data sensitivity × access exposure**.

### Step 4 — emit finding

```bash
# Combine DSPM + CSPM signals
emit_finding \
  --title "Public S3 bucket contains PII (1,247 SSN-shaped strings sampled)" \
  --severity critical \
  --category dspm_data_exposure \
  --description "..." \
  --remediation "1. Apply Block Public Access. 2. Encrypt-at-rest with CMK. 3. ..."
```

### Step 5 — compliance overlay

DSPM findings map to specific regulatory controls:

| Finding | Maps to |
|---|---|
| PII in publicly-accessible store | GDPR Art. 32 (security of processing) |
| PHI without encryption at rest | HIPAA §164.312(a)(2)(iv) |
| PCI data in non-PCI-scope storage | PCI-DSS 3.4 |
| Credentials in source-readable storage | SOC 2 CC6.1 |

The wrapper renders this as a compliance dashboard; engine emits the structured mapping.

## Integration with Existing Strix Capability

| Existing capability | DSPM extension |
|---|---|
| `cloud_attack_paths/discovery.py` enumerates buckets | DSPM samples + classifies their contents |
| `_pattern_public_storage_credentials_risk` flags risky shapes | DSPM upgrades severity when content confirms data presence |
| `secrets_scan` (repo-side) for code | DSPM extends to cloud-store-side (S3 / GCS / Blob) |
| `agentless_scan.py` (Trivy on EBS snapshots) | DSPM extends similarly to read mounted FS for sensitive content |
| Compliance overlay (PR #285) | DSPM findings flow through the same CC mapping |

## Specific Engineering Considerations

### Sampling cost vs coverage
- 100% scan of every S3 bucket = prohibitive ($$$, hours)
- 1% sample = misses 99% of objects but catches "all the buckets that contain anything sensitive"
- DSPM is about **classification of buckets** ("this bucket contains X type"), not "exhaustive enumeration of every sensitive string"

### Encrypted-at-rest blockers
- KMS-encrypted objects require `kms:Decrypt`; without it, content unreadable
- Mark "encrypted-at-rest" as a DSPM-positive signal (defence-in-depth) but flag if the principal scanning had to decrypt

### False-positive tuning
- Regex catches "anything that LOOKS like an SSN" — a phone number like `123-45-6789` matches
- Tune via: minimum-count thresholds, contextual co-occurrence (`SSN: 123-...` near the literal `SSN:` is high-confidence)

### Encrypted-in-transit
- Storage Read API + TLS = end-to-end encrypted in transit
- No special handling needed

### Privacy of the scan itself
- Strix MUST NOT exfiltrate sensitive content into events.jsonl / findings.jsonl
- Findings carry COUNTS + classification labels, NOT the literal sensitive strings
- Recommend: hash + offset reference; "47 SSN-shaped matches at offsets [1024, 4096, ...]"; never the actual SSNs

## Wishlist — the actual specialist

When `scan_dspm` ships as a Strix specialist, it should:

1. Walk the cloud KG to find storage resources
2. For each, sample N objects (configurable, default 10)
3. Run regex + schema-aware classification
4. Emit findings with data-class counts + the upstream access posture
5. Stamp the finding with regulatory control mappings
6. NEVER include literal sensitive strings in the finding output

The Trivy team has prior art (`trivy fs --scanners secret`) that's directly extensible.

## Validation (once shipped)

1. Sample produces non-zero classifications on known-bad test data (planted CSV with synthetic SSNs).
2. Compliance mapping renders correctly for each data class.
3. No literal sensitive content appears in `findings.jsonl` (privacy contract).
4. Cross-reference with cloud KG: paths from public-surface to high-data-class buckets surface as critical findings.

## False Positives

- Test data / development buckets with SYNTHETIC SSN-shaped data (e.g., 111-11-1111 placeholder).
- Date columns that pattern-match SSN regex (`MM-DD-YYYY` formatted) — fix via column-name awareness.
- API logs containing customer phone numbers in benign analytics use (legitimate but worth flagging).
- Sample sizes too small to be statistically meaningful — extrapolation should be conservative.

## Impact

- Converts cloud posture findings from "speculative" to "incident-class".
- Maps directly to GDPR / HIPAA / PCI-DSS / SOC 2 controls — auditor-grade.
- Closes Wiz's DSPM moat for the segment we serve.
- High-customer-impact because it converts a CSPM dashboard from "stuff to fix" into "stuff that's actively leaking regulated data".

## Remediation (the customer-facing fix)

1. **Encrypt sensitive stores at rest** with customer-managed CMKs.
2. **Block Public Access** at the account level for all storage services.
3. **Tag data classes** at write-time (`x-amz-meta-data-class: pii`) for downstream policy enforcement.
4. **Per-data-class IAM scoping** — separate KMS keys for PII vs non-PII content; principals scoped accordingly.
5. **DLP at write paths** (AWS Macie / GCP DLP) — block uploads of sensitive content to unapproved locations.
6. **Audit log retention** for `Get*` events on classified-as-sensitive buckets.

## Pro Tips

1. The single most-leaked sensitive data type in real engagements: **employee tax forms** (W-2s in the US, similar elsewhere) — contain SSN + DOB + address + employer + salary in one PDF. Pattern: `*W-2*.pdf` filename heuristic.
2. JSON/CSV exports from CRMs (Salesforce, HubSpot) are bulk-PII concentrate. Filename patterns: `customers-*.csv`, `users-*.json`.
3. Test-data buckets often contain real production data accidentally — engineers say "I just need 10 customer records to test" and end up with 10 real ones.
4. Encrypted-at-rest is necessary but not sufficient — without scoping, principals decrypt at scale anyway.
5. Wiz's DSPM moat is broad coverage (1000+ classifiers); we hit the 80% with the canonical regex + schema set + cloud KG integration.

## Summary

DSPM upgrades cloud posture from "structural risk" to "active data exposure". When it ships, Strix's cloud findings get materially sharper. Until then, the agent can reason about data class via filename heuristics + schema metadata + the cloud KG, then escalate severity manually.
