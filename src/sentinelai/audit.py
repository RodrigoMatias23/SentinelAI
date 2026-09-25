"""Append-only audit trail of human review decisions on alerts.

Every decision an analyst makes (confirm / mark as false positive) is
recorded here with a timestamp and an optional note. The ledger is
append-only JSON Lines: past entries are never rewritten, only new
entries are added, which keeps the review history trustworthy.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field

from sentinelai.models import AlertStatus

DEFAULT_AUDIT_LOG = Path("data/audit_log.jsonl")


class AuditRecord(BaseModel):
    """One human decision about one alert."""

    alert_id: UUID
    decision: AlertStatus
    analyst_note: str | None = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def record_decision(
    alert_id: UUID,
    decision: AlertStatus,
    analyst_note: str | None = None,
    log_path: Path = DEFAULT_AUDIT_LOG,
) -> AuditRecord:
    """Append a new decision to the audit log and return the record written."""
    if decision is AlertStatus.PENDING_REVIEW:
        raise ValueError("PENDING_REVIEW is not a decision that can be recorded.")

    record = AuditRecord(alert_id=alert_id, decision=decision, analyst_note=analyst_note)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")
    return record


def iter_records(log_path: Path = DEFAULT_AUDIT_LOG) -> Iterator[AuditRecord]:
    """Yield every audit record on file, oldest first."""
    if not log_path.exists():
        return
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield AuditRecord.model_validate(json.loads(line))


def latest_decisions(log_path: Path = DEFAULT_AUDIT_LOG) -> dict[UUID, AuditRecord]:
    """Return the most recent decision per alert_id (later entries win)."""
    decisions: dict[UUID, AuditRecord] = {}
    for record in iter_records(log_path):
        decisions[record.alert_id] = record
    return decisions
