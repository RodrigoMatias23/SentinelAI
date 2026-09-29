"""Small, explicit catalogue of the MITRE ATT&CK techniques SentinelAI maps alerts to.

The mapping is deliberately deterministic: each detection rule declares which
techniques it corresponds to. The AI layer never chooses or changes them, so a
technique shown on an alert is always traceable to a rule a human can read.

Reference: https://attack.mitre.org/ (verify IDs there if the matrix is updated).
"""

from sentinelai.models import MitreTechnique

BRUTE_FORCE = MitreTechnique(
    technique_id="T1110",
    name="Brute Force",
    tactics=("Credential Access",),
)

VALID_ACCOUNTS = MitreTechnique(
    technique_id="T1078",
    name="Valid Accounts",
    tactics=("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"),
)

ACTIVE_SCANNING = MitreTechnique(
    technique_id="T1595",
    name="Active Scanning",
    tactics=("Reconnaissance",),
)
