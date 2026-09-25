"""Typed domain models for normalised security events and alerts."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, Field


class EventType(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    WEB_SUSPICIOUS_PATH = "web_suspicious_path"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class SecurityEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    event_type: EventType
    source_ip: str
    username: str | None = None
    target: str | None = None
    message: str


class Alert(BaseModel):
    alert_id: UUID = Field(default_factory=uuid4)
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    summary: str
    evidence: list[SecurityEvent]
    recommendation: str
    status: AlertStatus = AlertStatus.PENDING_REVIEW


def stable_alert_id(rule_name: str, evidence: list[SecurityEvent]) -> UUID:
    """Compute a deterministic alert_id from the rule name and the evidence it fired on.

    The same underlying events, run through the same rule, always produce the
    same alert_id. This matters because Streamlit re-runs the whole script on
    every interaction (button click, etc.): without a stable id, each rerun
    would build brand-new Alert objects with fresh random UUIDs, silently
    breaking button clicks and the audit trail (both keyed by alert_id).
    """
    fingerprint = "|".join(
        f"{event.timestamp.isoformat()}:{event.event_type}:{event.source_ip}:"
        f"{event.username or ''}:{event.target or ''}"
        for event in evidence
    )
    return uuid5(NAMESPACE_URL, f"{rule_name}|{fingerprint}")


class AITriage(BaseModel):
    """AI-generated explanation for an alert, kept separate from the alert itself.

    The severity, risk_score and evidence on the Alert always come from the
    deterministic rules and are never overwritten by this. This model only
    holds the model's narrative explanation and expanded mitigation text,
    which an analyst should read as a *draft* to verify, not a verdict.
    """

    alert_id: UUID
    model_used: str
    explanation: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
