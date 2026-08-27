from pathlib import Path

from sentinelai.detections import (
    detect_repeated_authentication_failures,
    detect_success_after_failures,
)
from sentinelai.ingestion import load_jsonl_events
from sentinelai.models import Severity


def test_authentication_attack_scenario_produces_two_alerts() -> None:
    events = load_jsonl_events(Path("data/samples/auth_events.jsonl"))

    repeated_failures = detect_repeated_authentication_failures(events)
    success_after_failures = detect_success_after_failures(events)

    assert len(repeated_failures) == 1
    assert repeated_failures[0].severity is Severity.HIGH
    assert len(success_after_failures) == 1
    assert success_after_failures[0].severity is Severity.CRITICAL
