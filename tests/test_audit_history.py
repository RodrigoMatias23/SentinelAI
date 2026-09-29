from pathlib import Path
from uuid import uuid4

from sentinelai.audit import history_for_source_ips, record_decision
from sentinelai.models import AlertStatus


def test_no_history_for_unseen_ip(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"

    history = history_for_source_ips(["203.0.113.42"], log_path=log_path)

    assert not history.has_history
    assert history.times_seen == 0


def test_history_counts_confirmed_and_false_positive_separately(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"
    ip = "203.0.113.42"

    record_decision(
        uuid4(), AlertStatus.CONFIRMED, log_path=log_path, source_ips=[ip], rule_title="Rule A"
    )
    record_decision(
        uuid4(),
        AlertStatus.FALSE_POSITIVE,
        log_path=log_path,
        source_ips=[ip],
        rule_title="Rule B",
    )
    record_decision(  # unrelated IP, must not be counted
        uuid4(),
        AlertStatus.CONFIRMED,
        log_path=log_path,
        source_ips=["198.51.100.9"],
        rule_title="Rule A",
    )

    history = history_for_source_ips([ip], log_path=log_path)

    assert history.times_seen == 2
    assert history.confirmed == 1
    assert history.false_positive == 1


def test_history_excludes_the_alert_being_looked_up() -> None:
    """An alert must never see a decision about itself as 'prior history'."""
    log_path = Path("data/audit_log.jsonl")  # unused path; no file needed for this check
    alert_id = uuid4()

    history = history_for_source_ips(
        ["203.0.113.42"], exclude_alert_id=alert_id, log_path=log_path
    )

    assert not history.has_history
