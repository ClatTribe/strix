"""MFA enforcement attestation (roadmap §16 / PR #132).

Auditors literally ask: "show me a test that MFA is enforced."
This tool produces a structured `mfa_attestation` finding per
target, ALWAYS emitted, with severity reflecting the detection
state. SOC2 CC6.6 / NIST 800-53 IA-2 require MFA on auth surfaces.

Detection layer
---------------

This module produces the deterministic part — probing canonical
auth-flow paths for MFA-related markers:

  * Login page renders (form / fields / labels naming TOTP / OTP /
    Authenticator / SMS / Code / Multi-Factor / 2FA / Two-Factor /
    Verify Code).
  * Login response carries the canonical "challenge" status
    (`mfa_required`, `requires_otp`, `2fa_required`) in JSON.
  * `WWW-Authenticate` header advertises FIDO2 / WebAuthn.
  * MFA-setup endpoints exist (`/auth/mfa/setup`, `/settings/2fa`,
    `/account/security`).

The MORE we see → higher attestation score. Less = no public
indicator that MFA is enforced (this DOESN'T mean MFA is
absent — could be deeper in the flow — but the auditor's
"prove it" question is unanswered).

Severity ladder (always emits exactly one finding):

  * **Info** — score ≥ 3 (MFA visibly part of the auth flow)
  * **Low** — score 1-2 (some signal; not definitive)
  * **Medium** — score 0 (no public MFA indicators on a
    customer-facing app — auditor red-flag)

This is positive-attestation, not a vuln-claim. Companion to the
agent's deeper MFA-flow probing (signup / password-reset /
sensitive-action) which lives in §8.2 specialist work.
"""

from .mfa_attestation import mfa_attestation_check


__all__ = ["mfa_attestation_check"]
