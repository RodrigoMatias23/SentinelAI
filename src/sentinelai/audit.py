"""Append-only audit trail of human review decisions on alerts.

Every decision an analyst makes (confirm / mark as false positive) is
recorded here with a timestamp and an optional note. The ledger is
append-only JSON Lines: past entries are never rewritten, only new
entries are added, which keeps the review history trustworthy.
"""

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field

from sentinelai.models import AlertStatus

DEFAULT_AUDIT_LOG = Path("data/audit_log.jsonl")
DEFAULT_SEEN_LOG = Path("data/alerts_seen.jsonl")


class AuditRecord(BaseModel):
    """One human decision about one alert.

    source_ips and rule_title are stored alongside the decision (not just the
    alert_id) so that future alerts - which get a fresh alert_id whenever the
    underlying log events differ - can still be matched back to past
    decisions about the same source IP. This is what lets the AI layer look
    up "have we seen this IP before?" instead of judging each alert in
    isolation.
    """

    alert_id: UUID
    decision: AlertStatus
    analyst_note: str | None = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_ips: list[str] = Field(default_factory=list)
    rule_title: str | None = None


def record_decision(
    alert_id: UUID,
    decision: AlertStatus,
    analyst_note: str | None = None,
    log_path: Path = DEFAULT_AUDIT_LOG,
    source_ips: list[str] | None = None,
    rule_title: str | None = None,
) -> AuditRecord:
    """Append a new decision to the audit log and return the record written."""
    if decision is AlertStatus.PENDING_REVIEW:
        raise ValueError("PENDING_REVIEW is not a decision that can be recorded.")

    record = AuditRecord(
        alert_id=alert_id,
        decision=decision,
        analyst_note=analyst_note,
        source_ips=source_ips or [],
        rule_title=rule_title,
    )
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


class SeenRecord(BaseModel):
    """The moment an alert was first shown to the analyst (needed for time-to-review)."""

    alert_id: UUID
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def first_seen_times(log_path: Path = DEFAULT_SEEN_LOG) -> dict[UUID, datetime]:
    """Return when each alert was first seen (earliest entry wins)."""
    seen: dict[UUID, datetime] = {}
    if not log_path.exists():
        return seen
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = SeenRecord.model_validate(json.loads(line))
            seen.setdefault(record.alert_id, record.first_seen_at)
    return seen


def record_first_seen(
    alert_ids: Iterable[UUID], log_path: Path = DEFAULT_SEEN_LOG
) -> None:
    """Append a first-seen entry for every alert not yet on file (idempotent).

    Streamlit re-runs the script on every click, so this is called repeatedly;
    alerts already recorded are skipped, keeping the ledger append-only.
    """
    known = first_seen_times(log_path)
    new_ids = [i for i in dict.fromkeys(alert_ids) if i not in known]
    if not new_ids:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        for alert_id in new_ids:
            handle.write(SeenRecord(alert_id=alert_id).model_dump_json() + "\n")


class SourceIPHistory(BaseModel):
    """What the audit log already knows about a set of source IPs.

    This is computed with plain Python from data already on disk - no AI
    involved. It is the "tool call" step of the triage agent: gather facts
    first, then hand them to the model to explain, instead of asking the
    model to reason from nothing.
    """

    source_ips: list[str]
    times_seen: int
    confirmed: int
    false_positive: int

    @property
    def has_history(self) -> bool:
        return self.times_seen > 0


def history_for_source_ips(
    source_ips: list[str],
    exclude_alert_id: UUID | None = None,
    log_path: Path = DEFAULT_AUDIT_LOG,
) -> SourceIPHistory:
    """Summarise past analyst decisions for any of the given source IPs.

    Uses each alert_id's *latest* decision only (an IP reviewed twice counts
    once, with its most recent verdict), and never includes exclude_alert_id
    itself, so an alert never "sees" its own not-yet-made decision.
    """
    wanted = set(source_ips)
    latest_per_alert = latest_decisions(log_path)

    confirmed = false_positive = 0
    for aid, record in latest_per_alert.items():
        if aid == exclude_alert_id or not wanted.intersection(record.source_ips):
            continue
        if record.decision is AlertStatus.CONFIRMED:
            confirmed += 1
        elif record.decision is AlertStatus.FALSE_POSITIVE:
            false_positive += 1

    return SourceIPHistory(
        source_ips=source_ips,
        times_seen=confirmed + false_positive,
        confirmed=confirmed,
        false_positive=false_positive,
    )