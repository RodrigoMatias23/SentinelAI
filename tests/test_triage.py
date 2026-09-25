from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
import requests

from sentinelai.models import Alert, EventType, Severity, SecurityEvent
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
    )


def test_build_prompt_includes_facts_and_forbids_inventing_evidence() -> None:
    alert = _sample_alert()

    prompt = build_prompt(alert)

    assert "203.0.113.42" in prompt
    assert str(alert.risk_score) in prompt
    assert "never invent log lines" in prompt


def test_generate_triage_returns_parsed_explanation() -> None:
    alert = _sample_alert()
    fake_response = MagicMock()
    fake_response.json.return_value = {"response": "This looks like a brute-force attempt."}
    fake_response.raise_for_status.return_value = None

    with patch("sentinelai.triage.requests.post", return_value=fake_response) as mock_post:
        triage = generate_triage(alert, model="llama3.2")

    assert triage.alert_id == alert.alert_id
    assert triage.model_used == "llama3.2"
    assert "brute-force" in triage.explanation
    mock_post.assert_called_once()


def test_generate_triage_raises_clear_error_when_ollama_unreachable() -> None:
    alert = _sample_alert()

    with patch("sentinelai.triage.requests.post", side_effect=requests.ConnectionError):
        with pytest.raises(OllamaUnavailableError):
            generate_triage(alert)


def test_generate_triage_raises_when_model_returns_empty_response() -> None:
    alert = _sample_alert()
    fake_response = MagicMock()
    fake_response.json.return_value = {"response": ""}
    fake_response.raise_for_status.return_value = None

    with patch("sentinelai.triage.requests.post", return_value=fake_response):
        with pytest.raises(OllamaUnavailableError):
            generate_triage(alert)
