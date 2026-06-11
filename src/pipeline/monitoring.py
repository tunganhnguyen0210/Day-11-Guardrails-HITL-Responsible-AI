"""
Assignment 11 — Layer 6: Monitoring & Alerts

What: reads the AuditLog produced by the pipeline and computes aggregate
metrics (overall block rate, rate-limit hit rate, judge fail rate, average
latency, breakdown of which layer blocked what). Fires alerts when a metric
crosses a configurable threshold.

Why: a single blocked request is not actionable, but a *trend* is. If the
block rate suddenly jumps from 5% to 60%, that could mean an attack
campaign is underway (or that a guardrail update introduced false
positives). Monitoring is what turns the audit log from a passive record
into something an on-call engineer can act on.
"""
from collections import Counter

from pipeline.audit_log import AuditLog


class MonitoringAlert:
    """Computes metrics from an AuditLog and raises threshold-based alerts."""

    DEFAULT_THRESHOLDS = {
        "block_rate": 0.30,        # alert if >30% of requests are blocked
        "rate_limit_rate": 0.20,   # alert if >20% of requests are rate-limited
        "judge_fail_rate": 0.20,   # alert if >20% of judged responses fail
    }

    def __init__(self, audit_log: AuditLog, thresholds: dict | None = None):
        self.audit_log = audit_log
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}

    def compute_metrics(self) -> dict:
        """Aggregate the audit log into summary metrics.

        Returns a dict with totals, block rate, per-layer block counts,
        rate-limit hit rate, judge fail rate, and average latency.
        """
        entries = self.audit_log.entries
        total = len(entries)
        if total == 0:
            return {
                "total_requests": 0,
                "blocked": 0,
                "block_rate": 0.0,
                "blocked_by_layer": {},
                "rate_limit_hits": 0,
                "rate_limit_rate": 0.0,
                "judge_failures": 0,
                "judge_checks": 0,
                "judge_fail_rate": 0.0,
                "avg_latency_ms": 0.0,
            }

        blocked = sum(1 for e in entries if e.blocked)
        blocked_by_layer = Counter(
            e.blocked_layer for e in entries if e.blocked_layer
        )

        rate_limit_hits = blocked_by_layer.get("rate_limiter", 0)

        judge_checks = sum(
            1 for e in entries if "output_judge" in e.layer_results
        )
        judge_failures = sum(
            1
            for e in entries
            if e.layer_results.get("output_judge", {}).get("safe") is False
        )

        avg_latency_ms = sum(e.latency_ms for e in entries) / total

        return {
            "total_requests": total,
            "blocked": blocked,
            "block_rate": blocked / total,
            "blocked_by_layer": dict(blocked_by_layer),
            "rate_limit_hits": rate_limit_hits,
            "rate_limit_rate": rate_limit_hits / total,
            "judge_failures": judge_failures,
            "judge_checks": judge_checks,
            "judge_fail_rate": (judge_failures / judge_checks) if judge_checks else 0.0,
            "avg_latency_ms": avg_latency_ms,
        }

    def check_alerts(self, verbose: bool = True) -> list[str]:
        """Compare current metrics against thresholds and return any alerts."""
        metrics = self.compute_metrics()
        alerts = []

        if metrics["block_rate"] > self.thresholds["block_rate"]:
            alerts.append(
                f"ALERT: block rate {metrics['block_rate']:.0%} exceeds "
                f"threshold {self.thresholds['block_rate']:.0%}"
            )
        if metrics["rate_limit_rate"] > self.thresholds["rate_limit_rate"]:
            alerts.append(
                f"ALERT: rate-limit hit rate {metrics['rate_limit_rate']:.0%} "
                f"exceeds threshold {self.thresholds['rate_limit_rate']:.0%}"
            )
        if metrics["judge_fail_rate"] > self.thresholds["judge_fail_rate"]:
            alerts.append(
                f"ALERT: LLM-as-Judge fail rate {metrics['judge_fail_rate']:.0%} "
                f"exceeds threshold {self.thresholds['judge_fail_rate']:.0%}"
            )

        if verbose:
            if alerts:
                for a in alerts:
                    print(a)
            else:
                print("No alerts — all metrics within thresholds.")

        return alerts

    def print_dashboard(self):
        """Print a human-readable summary of pipeline health."""
        m = self.compute_metrics()
        print("\n" + "=" * 60)
        print("MONITORING DASHBOARD")
        print("=" * 60)
        print(f"Total requests:     {m['total_requests']}")
        print(f"Blocked:            {m['blocked']} ({m['block_rate']:.0%})")
        print(f"Blocked by layer:   {m['blocked_by_layer']}")
        print(f"Rate-limit hits:    {m['rate_limit_hits']} ({m['rate_limit_rate']:.0%})")
        print(f"Judge fail rate:    {m['judge_failures']}/{m['judge_checks']} "
              f"({m['judge_fail_rate']:.0%})")
        print(f"Avg latency:        {m['avg_latency_ms']:.1f} ms")
        print("-" * 60)
        self.check_alerts(verbose=True)
        print("=" * 60)
