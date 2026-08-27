"""Minimal analyst dashboard for the first SentinelAI detection scenario."""

from pathlib import Path

import streamlit as st

from sentinelai.detections import (
    detect_repeated_authentication_failures,
    detect_success_after_failures,
)
from sentinelai.ingestion import load_jsonl_events

st.set_page_config(page_title="SentinelAI", page_icon="🛡️", layout="wide")
st.title("🛡️ SentinelAI")
st.caption("Human-in-the-loop security event triage — synthetic data only")

sample_log = Path("data/samples/auth_events.jsonl")
events = load_jsonl_events(sample_log)
alerts = [
    *detect_repeated_authentication_failures(events),
    *detect_success_after_failures(events),
]

st.metric("Normalised events", len(events))
st.metric("Alerts awaiting review", len(alerts))

for alert in alerts:
    with st.expander(f"{alert.severity.upper()} · {alert.title}", expanded=True):
        st.progress(alert.risk_score, text=f"Risk score: {alert.risk_score}/100")
        st.write(alert.summary)
        st.subheader("Evidence")
        st.json([event.model_dump(mode="json") for event in alert.evidence])
        st.subheader("Recommended next step")
        st.write(alert.recommendation)
        st.info("No action is performed automatically. An analyst must review this alert.")
