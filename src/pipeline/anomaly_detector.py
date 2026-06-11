"""
Assignment 11 — Bonus Layer: Session Anomaly Detector

What: tracks, per user, how many times their requests were blocked by the
input guardrails (injection / topic) within a rolling session. If a single
user crosses a threshold of repeated injection-like attempts, the detector
flags the session as anomalous and the pipeline escalates (e.g., temporary
lockout or HITL review) — even if each individual attempt was already
blocked.

Why: the other layers evaluate each message in isolation. A single blocked
injection attempt is normal (users explore, make typos, or are simply
curious). Many blocked attempts in a row from the same user is a different
signal entirely — it suggests a deliberate attacker probing for a bypass.
This layer turns a *per-message* signal into a *per-session* signal, which
is exactly the kind of pattern individual guardrails cannot see.
"""
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class AnomalyResult:
    """Outcome of an anomaly check for one user."""
    flagged: bool
    injection_attempts: int
    reason: str


class SessionAnomalyDetector:
    """Flags users who repeatedly trigger the input guardrails."""

    def __init__(self, max_injection_attempts: int = 3):
        self.max_injection_attempts = max_injection_attempts
        self.injection_counts: dict[str, int] = defaultdict(int)

    def record_block(self, user_id: str, layer: str) -> AnomalyResult:
        """Record that `user_id` was blocked by `layer` and check for anomalies.

        Only injection-related blocks count toward the anomaly threshold —
        a user who repeatedly asks off-topic questions isn't necessarily an
        attacker, but repeated prompt-injection attempts are a strong signal.
        """
        if layer == "input_injection":
            self.injection_counts[user_id] += 1

        count = self.injection_counts[user_id]
        if count >= self.max_injection_attempts:
            return AnomalyResult(
                flagged=True,
                injection_attempts=count,
                reason=(
                    f"User '{user_id}' triggered the injection detector "
                    f"{count} times — possible coordinated attack. "
                    "Escalating to human review."
                ),
            )
        return AnomalyResult(flagged=False, injection_attempts=count, reason="")

    def reset(self, user_id: str | None = None):
        """Clear anomaly history for one user, or everyone (testing helper)."""
        if user_id is None:
            self.injection_counts.clear()
        else:
            self.injection_counts.pop(user_id, None)
