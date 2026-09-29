"""Read newline-delimited JSON logs into normalised models.

Real log sources (an attack lab, a production box) are messier than the
hand-written synthetic samples this project started with: a line can be
truncated, hand-edited, or written by a tool with a slightly different
schema. A single bad line must never take down the whole triage run, but it
also must never be silently dropped without a trace - so malformed lines are
skipped and reported, not raised or ignored.
"""

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from sentinelai.models import SecurityEvent


class SkippedLine(BaseModel):
    """A log line that could not be parsed into a SecurityEvent."""

    source: str
    line_number: int
    reason: str


class IngestionResult(BaseModel):
    """Everything load_jsonl_events learned from one file: good events and bad lines."""

    events: list[SecurityEvent]
    skipped: list[SkippedLine]

    @property
    def has_skipped_lines(self) -> bool:
        return len(self.skipped) > 0


def load_jsonl_events(path: Path) -> IngestionResult:
    """Load one JSON object per line, skipping blank and malformed lines.

    Raises FileNotFoundError with a clear message if the file itself is
    missing - that is a setup mistake the caller should know about
    immediately, unlike a single bad line within an otherwise good file.
    """
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    events: list[SecurityEvent] = []
    skipped: list[SkippedLine] = []

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(SecurityEvent.model_validate(json.loads(line)))
        except (json.JSONDecodeError, ValidationError) as exc:
            skipped.append(
                SkippedLine(source=str(path), line_number=line_number, reason=str(exc))
            )

    return IngestionResult(events=events, skipped=skipped)


def load_jsonl_events_from_dir(directory: Path) -> IngestionResult:
    """Load and merge every *.jsonl file in a directory, in sorted (deterministic) order.

    Missing directories or ones with no matching files simply yield no
    events - that is a normal "nothing to show yet" state, not an error.
    """
    if not directory.exists():
        return IngestionResult(events=[], skipped=[])

    all_events: list[SecurityEvent] = []
    all_skipped: list[SkippedLine] = []
    for file_path in sorted(directory.glob("*.jsonl")):
        result = load_jsonl_events(file_path)
        all_events.extend(result.events)
        all_skipped.extend(result.skipped)

    return IngestionResult(events=all_events, skipped=all_skipped)
