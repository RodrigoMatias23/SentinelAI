# SentinelAI

SentinelAI is a personal cybersecurity project: a human-in-the-loop agent for security event triage.

It ingests synthetic security logs, detects suspicious behaviour, calculates a transparent risk score and prepares evidence-based recommendations for a human analyst. It does not automatically block accounts, change configurations or execute remediation actions.

## Initial scope

- [x] Detect repeated authentication failures from the same source.
- [x] Detect a successful login following repeated failures.
- [x] Detect suspicious web path scanning from the same source.
- [x] Assign a risk score with visible reasoning.
- [x] Let an analyst mark an alert as confirmed or a false positive.
- [x] Keep an audit record of the human decision.
- [x] AI-assisted triage layer (explanation + mitigation suggestions on top of
      the deterministic risk score), backed by a local Ollama model.

## Project principles

- **Evidence first:** every conclusion must point to concrete log events.
- **Human approval:** the system recommends; a human decides.
- **Synthetic data only:** no real organisational logs or credentials are stored in this repository.
- **Explainable detections:** risk scores are deterministic in the first version.

## Local setup

Requires Python 3.12+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
streamlit run app.py
```

## Running tests

```powershell
pytest
```

## Architecture

```text
Synthetic logs -> normalisation -> detection rules -> risk scoring
                                                   -> AI explanation (optional, on-demand)
                                                   -> analyst review (Streamlit)
                                                   -> audit record (data/audit_log.jsonl)
```

The detection pipeline is fully testable without an LLM — severity, risk
score and evidence always come from the deterministic rules in
`detections.py` and are never generated or altered by the AI layer. The AI
(`triage.py`) only reads those already-computed facts and drafts a
human-readable explanation and an expanded mitigation suggestion, which the
analyst reviews before deciding.

## AI layer (local, via Ollama)

The AI explanation runs against a local model through
[Ollama](https://ollama.com), so no data leaves the machine and there are no
per-call costs.

```powershell
# one-time setup
# 1. install Ollama: https://ollama.com/download
# 2. pull a model
ollama pull llama3.2
```

In the dashboard, each alert has an "🤖 Explain with local AI (Ollama)"
button that calls the local model on demand — nothing runs automatically.

## Roadmap

- [ ] Map each detection rule to a MITRE ATT&CK technique.
- [ ] Evaluation metrics from the audit log (false positive rate, time to review).
- [ ] Additional log sources from an isolated attack lab (brute force, scans, path traversal).