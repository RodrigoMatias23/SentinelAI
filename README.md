# SentinelAI

SentinelAI is a personal cybersecurity project: a human-in-the-loop agent for security event triage.

It ingests synthetic security logs, detects suspicious behaviour, calculates a transparent risk score and prepares evidence-based recommendations for a human analyst. It does not automatically block accounts, change configurations or execute remediation actions.

## Initial scope

- Detect repeated authentication failures from the same source.
- Detect a successful login following repeated failures.
- Assign a risk score with visible reasoning.
- Let an analyst mark an alert as confirmed or a false positive.
- Keep an audit record of the human decision.

## Project principles

- **Evidence first:** every conclusion must point to concrete log events.
- **Human approval:** the system recommends; a human decides.
- **Synthetic data only:** no real organisational logs or credentials are stored in this repository.
- **Explainable detections:** risk scores are deterministic in the first version.

## Local setup

These commands will be run after Python is available in the terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
streamlit run app.py
```

## Planned architecture

```text
Synthetic logs -> normalisation -> detection rules -> risk scoring
                                                   -> analyst review
                                                   -> audit record
```

The AI-assisted triage layer will be added after the detection pipeline is testable without an LLM.
