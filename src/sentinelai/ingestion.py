"""Read synthetic newline-delimited JSON logs into normalised models."""

import json
from pathlib import Path

from sentinelai.models import SecurityEvent


def load_jsonl_events(path: Path) -> list[SecurityEvent]:
    """Load one JSON object per line, ignoring blank lines."""
    return [
        SecurityEvent.model_validate(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
