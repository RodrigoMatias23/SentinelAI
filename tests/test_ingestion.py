import json
from pathlib import Path

import pytest

from sentinelai.ingestion import load_jsonl_events, load_jsonl_events_from_dir


def test_missing_file_raises_clear_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Log file not found"):
        load_jsonl_events(tmp_path / "does_not_exist.jsonl")


def test_malformed_json_line_is_skipped_not_raised(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    good_event = {
        "timestamp": "2026-09-08T10:00:00Z",
        "event_type": "auth_failure",
        "source_ip": "203.0.113.42",
        "message": "Invalid password",
    }
    log_path.write_text(
        json.dumps(good_event) + "\n"
        + "{this is not valid json\n"
        + "\n"  # blank line, must be ignored silently, not counted as skipped
        + json.dumps({**good_event, "message": "Invalid password again"}) + "\n"
    )

    result = load_jsonl_events(log_path)

    assert len(result.events) == 2
    assert result.has_skipped_lines
    assert len(result.skipped) == 1
    assert result.skipped[0].line_number == 2


def test_line_failing_schema_validation_is_also_skipped(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    log_path.write_text(json.dumps({"event_type": "not_a_real_type"}) + "\n")

    result = load_jsonl_events(log_path)

    assert result.events == []
    assert len(result.skipped) == 1


def test_load_from_missing_directory_returns_empty_result_not_an_error(tmp_path: Path) -> None:
    result = load_jsonl_events_from_dir(tmp_path / "does_not_exist")

    assert result.events == []
    assert result.skipped == []


def test_load_from_dir_merges_all_jsonl_files_and_collects_skips(tmp_path: Path) -> None:
    good_event = {
        "timestamp": "2026-09-08T10:00:00Z",
        "event_type": "auth_failure",
        "source_ip": "203.0.113.42",
        "message": "Invalid password",
    }
    (tmp_path / "a.jsonl").write_text(json.dumps(good_event) + "\n")
    (tmp_path / "b.jsonl").write_text("not json at all\n")

    result = load_jsonl_events_from_dir(tmp_path)

    assert len(result.events) == 1
    assert len(result.skipped) == 1
