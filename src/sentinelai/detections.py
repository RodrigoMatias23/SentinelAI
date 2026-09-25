"""Deterministic detection rules used before AI-assisted triage is introduced."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import timedelta

from sentinelai.models import Alert, EventType, SecurityEvent, Severity, stable_alert_id


def detect_repeated_authentication_failures(
    events: Iterable[SecurityEvent], threshold: int = 5, window_minutes: int = 5
) -> list[Alert]:
    """Raise one alert when an IP reaches failed-login threshold within a time window."""
    recent_failures: dict[str, deque[SecurityEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type is not EventType.AUTH_FAILURE:
            continue

        failures = recent_failures[event.source_ip]
        failures.append(event)
        while failures and event.timestamp - failures[0].timestamp > window:
            failures.popleft()

        if len(failures) == threshold:
            evidence = list(failures)
            alerts.append(
                Alert(
                    alert_id=stable_alert_id("repeated_authentication_failures", evidence),
                    title="Repeated authentication failures",
                    severity=Severity.HIGH,
                    risk_score=70,
                    summary=(
                        f"{threshold} failed authentication attempts from {event.source_ip} "
                        f"within {window_minutes} minutes."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Validate whether the source is expected. If it is not, temporarily block "
                        "the source IP and review the targeted account."
                    ),
                )
            )

    return alerts


def detect_suspicious_web_path_scan(
    events: Iterable[SecurityEvent], threshold: int = 3, window_minutes: int = 5
) -> list[Alert]:
    """Raise one alert when a source IP probes multiple suspicious web paths in a window."""
    recent_hits: dict[str, deque[SecurityEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type is not EventType.WEB_SUSPICIOUS_PATH:
            continue

        hits = recent_hits[event.source_ip]
        hits.append(event)
        while hits and event.timestamp - hits[0].timestamp > window:
            hits.popleft()

        if len(hits) == threshold:
            evidence = list(hits)
            targets = ", ".join(sorted({item.target for item in evidence if item.target}))
            alerts.append(
                Alert(
                    alert_id=stable_alert_id("suspicious_web_path_scan", evidence),
                    title="Suspicious web path scanning",
                    severity=Severity.MEDIUM,
                    risk_score=55,
                    summary=(
                        f"{threshold} requests to suspicious paths from {event.source_ip} "
                        f"within {window_minutes} minutes. Targets probed: {targets}."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Review the requested paths for signs of directory traversal, "
                        "credential file access or common exploit probes. Consider rate-limiting "
                        "or blocking the source IP if the pattern is confirmed malicious."
                    ),
                )
            )

    return alerts


def detect_success_after_failures(
    events: Iterable[SecurityEvent], threshold: int = 5, window_minutes: int = 10
) -> list[Alert]:
    """Detect a login success that follows a burst of failed attempts from the same IP."""
    failures_by_ip: dict[str, deque[SecurityEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        failures = failures_by_ip[event.source_ip]
        while failures and event.timestamp - failures[0].timestamp > window:
            failures.popleft()

        if event.event_type is EventType.AUTH_FAILURE:
            failures.append(event)
            continue

        if event.event_type is EventType.AUTH_SUCCESS and len(failures) >= threshold:
            evidence = [*failures, event]
            alerts.append(
                Alert(
                    alert_id=stable_alert_id("success_after_failures", evidence),
                    title="Successful login after repeated failures",
                    severity=Severity.CRITICAL,
                    risk_score=90,
                    summary=(
                        f"A successful login for {event.username or 'an unknown user'} from "
                        f"{event.source_ip} followed {len(failures)} failures within "
                        f"{window_minutes} minutes."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Ask an analyst to validate the session immediately. If it is not "
                        "legitimate, revoke active sessions, reset credentials and investigate "
                        "the source IP."
                    ),
                )
            )

    return alerts
