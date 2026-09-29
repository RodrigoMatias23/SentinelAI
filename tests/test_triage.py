from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
import requests

from sentinelai.audit import SourceIPHistory, record_decision
from sentinelai.mitre import BRUTE_FORCE
from sentinelai.models import Alert, AlertStatus, EventType, SecurityEvent, Severity
from sentinelai.triage import OllamaUnavailableError, build_prompt, generate_triage


def _sample_alert() -> Alert:
    event = SecurityEvent(
        timestamp=datetime(2026, 9, 8, 10, 0, tzinfo=UTC),
        event_type=EventType.AUTH_FAILURE,
        source_ip="203.0.113.42",
        username="admin",
        target="ssh://lab-server",
        message="Invalid password",
    )
    return Alert(
        title="Repeated authentication failures",
        severity=Severity.HIGH,
        risk_score=70,
        summary="5 failed authentication attempts from 203.0.113.42 within 5 minutes.",
        evidence=[event],
        recommendation="Validate whether the source is expected.",
        mitre_techniques=[BRUTE_FORCE],
    )


def test_build_prompt_includes_facts_and_forbids_inventing_evidence() -> None:
    alert = _sample_alert()
    no_history = SourceIPHistory(
        source_ips=["203.0.113.42"], times_seen=0, confirmed=0, false_positive=0
    )

    prompt = build_prompt(alert, no_history)

    assert "203.0.113.42" in prompt
    assert str(alert.risk_score) in prompt
    assert "never invent log lines" in prompt
    assert "T1110 Brute Force" in prompt
    assert "first sighting" in prompt


def test_build_prompt_includes_prior_history_when_available() -> None:
    alert = _sample_alert()
    history = SourceIPHistory(
        source_ips=["203.0.113.42"], times_seen=3, confirmed=2, false_positive=1
    )

    prompt = build_prompt(alert, history)

    assert "3 previously reviewed alert" in prompt
    assert "2 confirmed" in prompt
    assert "1 marked as false positives" in prompt


def test_generate_triage_returns_parsed_explanation(tmp_path) -> None:
    alert = _sample_alert()
    fake_response = MagicMock()
    fake_response.json.return_value = {"response": "This looks like a brute-force attempt."}
    fake_response.raise_for_status.return_value = None

    with patch("sentinelai.triage.requests.post", return_value=fake_response) as mock_post:
        triage = generate_triage(
            alert, model="llama3.2", audit_log_path=tmp_path / "audit_log.jsonl"
        )

    assert triage.alert_id == alert.alert_id
    assert triage.model_used == "llama3.2"
    assert "brute-force" in triage.explanation
    mock_post.assert_called_once()


def test_generate_triage_grounds_prompt_in_real_prior_history(tmp_path) -> None:
    """The agent step: a repeat-offender IP must show up in the prompt sent to the model."""
    alert = _sample_alert()
    log_path = tmp_path / "audit_log.jsonl"
    record_decision(
        alert.alert_id.__class__(int=alert.alert_id.int ^ 1),  # a different, past alert_id
        AlertStatus.CONFIRMED,
        log_path=log_path,
        source_ips=["203.0.113.42"],
        rule_title=alert.title,
    )
    fake_response = MagicMock()
    fake_response.json.return_value = {"response": "Repeat offender, escalate."}
    fake_response.raise_for_status.return_value = None

    with patch("sentinelai.triage.requests.post", return_value=fake_response) as mock_post:
        generate_triage(alert, audit_log_path=log_path)

    sent_prompt = mock_post.call_args.kwargs["json"]["prompt"]
    assert "1 previously reviewed alert" in sent_prompt
    assert "1 confirmed" in sent_prompt


def test_generate_triage_raises_clear_error_when_ollama_unreachable(tmp_path) -> None:
    alert = _sample_alert()

    with patch("sentinelai.triage.requests.post", side_effect=requests.ConnectionError):
        with pytest.raises(OllamaUnavailableError):
            generate_triage(alert, audit_log_path=tmp_path / "audit_log.jsonl")


def test_generate_triage_raises_when_model_returns_empty_response(tmp_path) -> None:
    alert = _sample_alert()
    fake_response = MagicMock()
    fake_response.json.return_value = {"response": ""}
    fake_response.raise_for_status.return_value = None

    with patch("sentinelai.triage.requests.post", return_value=fake_response):
        with pytest.raises(OllamaUnavailableError):
            generate_triage(alert, audit_log_path=tmp_path / "audit_log.jsonl")
