"""
Assignment 11 — Layer 5: Audit Log

What: records every interaction that flows through the pipeline — input,
output, which layer (if any) blocked the request, latency, and metadata
about each guardrail's verdict.

Why: guardrails will sometimes be wrong (false positives/negatives). Without
an audit trail there is no way to investigate an incident after the fact, no
way to compute the metrics the Monitoring layer needs, and no way to prove
to a regulator/compliance team what the system did and why. This layer never
blocks anything — it is purely observational.
"""
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class AuditEntry:
    """One row of the audit log — a single user request/response cycle."""
    timestamp: str
    user_id: str
    user_input: str
    final_response: str
    blocked: bool
    blocked_layer: str | None
    layer_results: dict = field(default_factory=dict)
    latency_ms: float = 0.0


class AuditLog:
    """In-memory audit log with JSON export."""

    def __init__(self):
        self.entries: list[AuditEntry] = []

    def record(
        self,
        user_id: str,
        user_input: str,
        final_response: str,
        blocked: bool,
        blocked_layer: str | None,
        layer_results: dict,
        latency_ms: float,
    ) -> AuditEntry:
        """Append one entry to the log and return it."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            user_input=user_input,
            final_response=final_response,
            blocked=blocked,
            blocked_layer=blocked_layer,
            layer_results=layer_results,
            latency_ms=latency_ms,
        )
        self.entries.append(entry)
        return entry

    def export_json(self, filepath: str = "audit_log.json"):
        """Dump the full audit log to a JSON file for offline analysis."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(e) for e in self.entries],
                f,
                indent=2,
                default=str,
                ensure_ascii=False,
            )

    def __len__(self):
        return len(self.entries)
