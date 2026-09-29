"""Evaluation metrics computed from the analyst's recorded decisions.

Pure functions over data already on disk: no AI involved. These numbers show
how the triage is performing in practice (how many alerts turn out to be noise,
how quickly a human gets to them), which is the evidence a real SOC would ask for.
"""

from datetime import datetime
from statistics import median
from uuid import UUID

from pydantic import BaseModel

from sentinelai.audit import AuditRecord
from sentinelai.models import Alert, AlertStatus, Severity


class SeverityCounts(BaseModel):
    total: int = 0
    pending: int = 0
    confirmed: int = 0
    false_positive: int = 0


class ReviewMetrics(BaseModel):
    total_alerts: int
    pending: int
    confirmed: int
    false_positives: int
    false_positive_rate: float | None  # None until at least one alert is reviewed
    median_seconds_to_review: float | None  # None until a reviewed alert has a first-seen time
    by_severity: dict[Severity, SeverityCounts]


def compute_review_metrics(
    alerts: list[Alert],
    decisions: dict[UUID, AuditRecord],
    first_seen: dict[UUID, datetime],
) -> ReviewMetrics:
    """Summarise review outcomes for the alerts currently produced by the rules.

    Decisions for alerts that no longer exist (e.g. after the sample data
    changed) are ignored so the numbers always describe the current alert set.
    """
    by_severity = {severity: SeverityCounts() for severity in Severity}
    confirmed = false_positives = 0
    durations: list[float] = []

    for alert in alerts:
        counts = by_severity[alert.severity]
        counts.total += 1
        decision = decisions.get(alert.alert_id)

        if decision is None:
            counts.pending += 1
            continue

        if decision.decision is AlertStatus.CONFIRMED:
            confirmed += 1
            counts.confirmed += 1
        elif decision.decision is AlertStatus.FALSE_POSITIVE:
            false_positives += 1
            counts.false_positive += 1

        seen_at = first_seen.get(alert.alert_id)
        if seen_at is not None:
            durations.append(max(0.0, (decision.decided_at - seen_at).total_seconds()))

    reviewed = confirmed + false_positives
    return ReviewMetrics(
        total_alerts=len(alerts),
        pending=len(alerts) - reviewed,
        confirmed=confirmed,
        false_positives=false_positives,
        false_positive_rate=false_positives / reviewed if reviewed else None,
        median_seconds_to_review=median(durations) if durations else None,
        by_severity=by_severity,
    )


def format_duration(seconds: float | None) -> str:
    """Human-friendly duration for the dashboard (e.g. '45 s', '3.2 min', '1.5 h')."""
    if seconds is None:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"
