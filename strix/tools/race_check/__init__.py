"""Race-condition prober (roadmap §7.2 important).

Turbo-Intruder-style: send N concurrent requests within
milliseconds to test for TOCTOU on state-changing endpoints
(purchase, redeem, transfer, change-password, vote, claim-coupon).

Zero-FP via N+1 verification: emit ONLY when the same probe
fires twice in a row with the same race outcome — a flaky
serial-but-fast endpoint won't reproduce; a real race condition
will.
"""

from .race_check import race_condition_check


__all__ = ["race_condition_check"]
