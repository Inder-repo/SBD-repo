
from typing import Tuple, List
from data_model import Threat

MITRE_CONTROL_MAP = {
    "Phishing Attacks": {
        "mitre": ["T1566"],
        "controls": ["NIST AC-7", "ISO A.9.4.2", "CIS 16.10"]
    },
    "SQL Injection": {
        "mitre": ["T1505.001"],
        "controls": ["NIST SI-10", "ISO A.14.2.5", "CIS 18.9"]
    },
    "DDoS Attacks": {
        "mitre": ["T1499"],
        "controls": ["NIST SC-5", "ISO A.13.1.1", "CIS 9.1"]
    },
    "Data Exfiltration": {
        "mitre": ["T1020"],
        "controls": ["NIST AC-4", "ISO A.13.2.3", "CIS 13.7"]
    },
    "Unauthorized Data Access": {
        "mitre": ["T1078"],
        "controls": ["NIST AC-6", "ISO A.9.2.3", "CIS 4.4"]
    },
    "Lateral Movement": {
        "mitre": ["T1021"],
        "controls": ["NIST SC-7(1)", "ISO A.13.1.3", "CIS 14.6"]
    },
    "Cross-Site Scripting (XSS)": {
        "mitre": ["T1059.007"],
        "controls": ["NIST SI-10", "ISO A.14.2.5", "CIS 18.8"]
    },
    "Authentication Bypass": {
        "mitre": ["T1078"],
        "controls": ["NIST IA-2", "ISO A.9.4.2", "CIS 16.3"]
    },
    "Credential Stuffing": {
        "mitre": ["T1110.004"],
        "controls": ["NIST IA-5", "ISO A.9.4.3", "CIS 16.11"]
    },
    "Financial Fraud": {
        "mitre": ["T1650"],
        "controls": ["NIST AU-6", "ISO A.12.4.1", "CIS 10.3"]
    },
    "Payment Gateway Bypass": {
        "mitre": ["T1609"],
        "controls": ["NIST SC-12", "ISO A.14.1.2", "CIS 11.2"]
    }
}

def calculate_risk(likelihood: int, impact: int) -> Tuple[int, str]:
    risk_score = likelihood * impact
    if risk_score >= 15:
        return risk_score, "Critical"
    elif risk_score >= 10:
        return risk_score, "High"
    elif risk_score >= 5:
        return risk_score, "Medium"
    else:
        return risk_score, "Low"

def enrich_threat(threat: Threat) -> Threat:
    risk_score, risk_level = calculate_risk(threat.likelihood, threat.impact)
    threat.risk_score = risk_score
    threat.risk_level = risk_level
    mapping = MITRE_CONTROL_MAP.get(threat.name)
    if mapping:
        threat.mitre_ids = mapping["mitre"]
        threat.control_refs = mapping["controls"]
    return threat
