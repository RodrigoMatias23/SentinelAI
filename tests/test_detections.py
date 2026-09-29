from pathlib import Path

from sentinelai.detections import (
    detect_repeated_authentication_failures,
    detect_success_after_failures,
    detect_suspicious_web_path_scan,
)
from sentinelai.ingestion import load_jsonl_events
from sentinelai.models import Severity


def test_authentication_attack_scenario_produces_two_alerts() -> None:
    events = load_jsonl_events(Path("data/samples/auth_events.jsonl")).events

    repeated_failures = detect_repeated_authentication_failures(events)
    success_after_failures = detect_success_after_failures(events)

    assert len(repeated_failures) == 1
    assert repeated_failures[0].severity is Severity.HIGH
    assert len(success_after_failures) == 1
    assert success_after_failures[0].severity is Severity.CRITICAL


def test_web_path_scan_scenario_produces_one_alert() -> None:
    events = load_jsonl_events(Path("data/samples/web_scan_events.jsonl")).events

    alerts = detect_suspicious_web_path_scan(events)

    assert len(alerts) == 1
    assert alerts[0].severity is Severity.MEDIUM
    assert len(alerts[0].evidence) == 3


def test_alert_id_is_stable_across_repeated_runs_on_same_events() -> None:
    """Streamlit re-runs the whole script on every click, rebuilding all alerts.

    If alert_id were random (e.g. plain uuid4), every rerun would produce a
    different id for "the same" alert, silently breaking button clicks and
    the audit trail. This test guards against that regression.
    """
    events = load_jsonl_events(Path("data/samples/auth_events.jsonl")).events

    first_run = detect_repeated_authentication_failures(events)
    second_run = detect_repeated_authentication_failures(events)

    assert [a.alert_id for a in first_run] == [a.alert_id for a in second_run]


def test_each_rule_maps_to_expected_mitre_techniques() -> None:
    auth_events = load_jsonl_events(Path("data/samples/auth_events.jsonl")).events
    web_events = load_jsonl_events(Path("data/samples/web_scan_events.jsonl")).events

    def ids(alert) -> list[str]:
        return [t.technique_id for t in alert.mitre_techniques]

    assert ids(detect_repeated_authentication_failures(auth_events)[0]) == ["T1110"]
    assert ids(detect_success_after_failures(auth_events)[0]) == ["T1110", "T1078"]
    assert ids(detect_suspicious_web_path_scan(web_events)[0]) == ["T1595"]


def test_mitre_technique_url_points_to_official_page() -> None:
    from sentinelai.mitre import BRUTE_FORCE
    from sentinelai.models import MitreTechnique

    assert BRUTE_FORCE.url == "https://attack.mitre.org/techniques/T1110/"
    sub = MitreTechnique(
        technique_id="T1595.003", name="Wordlist Scanning", tactics=("Reconnaissance",)
    )
    assert sub.url == "https://attack.mitre.org/techniques/T1595/003/"
