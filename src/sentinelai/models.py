"""Typed domain models for normalised security events and alerts."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

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
