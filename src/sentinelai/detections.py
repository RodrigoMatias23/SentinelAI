"""Deterministic detection rules used before AI-assisted triage is introduced."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import timedelta

from sentinelai.models import Alert, EventType, SecurityEvent, Severity


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
