from pathlib import Path
from uuid import uuid4

import pytest

from sentinelai.audit import iter_records, latest_decisions, record_decision
from sentinelai.models import AlertStatus


def test_record_decision_appends_and_is_readable(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"
    alert_id = uuid4()

    record_decision(alert_id, AlertStatus.CONFIRMED, "Looked legitimate to analyst.", log_path)

    records = list(iter_records(log_path))
    assert len(records) == 1
    assert records[0].alert_id == alert_id
    assert records[0].decision is AlertStatus.CONFIRMED
    assert records[0].analyst_note == "Looked legitimate to analyst."


def test_latest_decisions_keeps_most_recent_entry_per_alert(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"
    alert_id = uuid4()

    record_decision(alert_id, AlertStatus.CONFIRMED, log_path=log_path)
    record_decision(alert_id, AlertStatus.FALSE_POSITIVE, "Reanalysed, was noise.", log_path)

    decisions = latest_decisions(log_path)

    assert decisions[alert_id].decision is AlertStatus.FALSE_POSITIVE
    assert decisions[alert_id].analyst_note == "Reanalysed, was noise."


def test_pending_review_cannot_be_recorded_as_a_decision(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"

    with pytest.raises(ValueError):
        record_decision(uuid4(), AlertStatus.PENDING_REVIEW, log_path=log_path)
