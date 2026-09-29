from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sentinelai.audit import AuditRecord
from sentinelai.metrics import compute_review_metrics
from sentinelai.models import Alert, AlertStatus, EventType, SecurityEvent, Severity


def _alert(severity: Severity) -> Alert:
    event = SecurityEvent(
        timestamp=datetime(2026, 9, 8, 10, 0, tzinfo=UTC),
        event_type=EventType.AUTH_FAILURE,
        source_ip="203.0.113.42",
        message="Invalid password",
    )
    return Alert(
        title="Test alert",
        severity=severity,
        risk_score=50,
        summary="summary",
        evidence=[event],
        recommendation="recommendation",
    )


def test_metrics_with_no_decisions_are_all_pending() -> None:
    alerts = [_alert(Severity.HIGH), _alert(Severity.MEDIUM)]

    metrics = compute_review_metrics(alerts, decisions={}, first_seen={})

    assert metrics.total_alerts == 2
    assert metrics.pending == 2
    assert metrics.false_positive_rate is None
    assert metrics.median_seconds_to_review is None


def test_false_positive_rate_and_time_to_review_are_computed() -> None:
    confirmed_alert = _alert(Severity.HIGH)
    fp_alert = _alert(Severity.LOW)
    seen_at = datetime(2026, 9, 8, 10, 0, tzinfo=UTC)

    decisions = {
        confirmed_alert.alert_id: AuditRecord(
            alert_id=confirmed_alert.alert_id,
            decision=AlertStatus.CONFIRMED,
            decided_at=seen_at + timedelta(seconds=30),
        ),
        fp_alert.alert_id: AuditRecord(
            alert_id=fp_alert.alert_id,
            decision=AlertStatus.FALSE_POSITIVE,
            decided_at=seen_at + timedelta(seconds=90),
        ),
    }
    first_seen = {confirmed_alert.alert_id: seen_at, fp_alert.alert_id: seen_at}

    metrics = compute_review_metrics([confirmed_alert, fp_alert], decisions, first_seen)

    assert metrics.false_positive_rate == 0.5
    assert metrics.median_seconds_to_review == 60.0
    assert metrics.pending == 0


def test_decisions_for_alerts_no_longer_present_are_ignored() -> None:
    current_alert = _alert(Severity.HIGH)
    stale_decision = {
        uuid4(): AuditRecord(alert_id=uuid4(), decision=AlertStatus.CONFIRMED)
    }

    metrics = compute_review_metrics([current_alert], stale_decision, first_seen={})

    assert metrics.total_alerts == 1
    assert metrics.pending == 1
