SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

def score_findings(all_findings: list) -> list:
    for f in all_findings:
        f.setdefault("severity", "UNKNOWN")
    
    sorted_findings = sorted(
        all_findings,
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 4)
    )
    
    return sorted_findings

def summarize(findings: list) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        severity = f.get("severity", "UNKNOWN")
        summary[severity] = summary.get(severity, 0) + 1
    return summary