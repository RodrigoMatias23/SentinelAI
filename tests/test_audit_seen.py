from pathlib import Path
from uuid import uuid4

from sentinelai.audit import first_seen_times, record_first_seen


def test_record_first_seen_is_idempotent(tmp_path: Path) -> None:
    log_path = tmp_path / "alerts_seen.jsonl"
    alert_id = uuid4()

    record_first_seen([alert_id], log_path)
    first_time = first_seen_times(log_path)[alert_id]
    record_first_seen([alert_id], log_path)  # simulate a Streamlit rerun
    second_time = first_seen_times(log_path)[alert_id]

    assert first_time == second_time
    assert log_path.read_text().count("\n") == 1
