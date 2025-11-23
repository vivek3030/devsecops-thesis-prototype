    input.slsa_build.level >= 3
    input.slsa_build.provenance_verified
    input.slsa_build.hermetic_build
    input.slsa_build.signed
}

# ---------------------------
# SBOM Check
# ---------------------------
sbom_attached if {
    count(input.sbom.components) > 0
}

# ---------------------------
# CVE Checks
# ---------------------------
no_critical_cve if {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Critical"]) == 0
}

no_high_cve if {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "High"]) == 0
}

# ---------------------------
# SAST Checks (Semgrep Format)
# ---------------------------
no_critical_sast if {
    count([r | r := input.sast.results[_]; r.extra.severity == "ERROR"]) == 0
}

no_high_sast if {
    count([r | r := input.sast.results[_]; r.extra.severity == "WARNING"]) == 0
}

# ---------------------------
# Secret Detection Check
# ---------------------------
no_secrets_detected if {
    count(input.secrets) == 0
}

# ---------------------------
# Deny rules (blocking conditions)
# ---------------------------
deny contains {"type": "SLSA", "msg": "SLSA level requirement not satisfied"} if {
    not slsa_level_ok
}

deny contains {"type": "SBOM", "msg": "SBOM is missing or empty"} if {
    not sbom_attached
}

deny contains {"type": "CVE", "msg": msg} if {
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "Critical"
    msg := sprintf("Critical CVE found: %v", [m.vulnerability.id])
}

deny contains {"type": "SAST", "msg": msg} if {
    r := input.sast.results[_]
    r.extra.severity == "ERROR"
    msg := sprintf("Critical SAST issue found: %v at line %v", [r.rule_id, r.start.line])
}

deny contains {"type": "SAST", "msg": msg} if {
    r := input.sast.results[_]
    r.extra.severity == "WARNING"
    msg := sprintf("High SAST issue found: %v at line %v", [r.rule_id, r.start.line])
}

deny contains {"type": "SECRET", "msg": msg} if {
    s := input.secrets[_]
    msg := sprintf("Hardcoded secret detected: %v in %v", [s.type, s.file_path])
}

# ---------------------------
# Warnings (optional) - partial set
# ---------------------------
warnings contains {"type": "CVE", "msg": msg} if {
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "High"
    msg := sprintf("High CVE found: %v", [m.vulnerability.id])
}

warnings contains {"type": "SAST", "msg": msg} if {
    i := input.sast.Issues[_]
    i.severity == "MEDIUM"
    msg := sprintf("High SAST issue found: %v at line %v", [i.rule_id, i.line])
}

# ---------------------------
# Compliance report
# ---------------------------
compliance_report = report if {
    critical_cves := [m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Critical"]
    high_cves := [m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "High"]
    medium_cves := [m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Medium"]
    low_cves := [m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Low"]

    critical_sast := [i | i := input.sast.Issues[_]; i.severity == "HIGH"]
    high_sast := [i | i := input.sast.Issues[_]; i.severity == "MEDIUM"]
    medium_sast := [i | i := input.sast.Issues[_]; i.severity == "LOW"]

    report := {
        "slsa_level": input.slsa_build.level,
        "slsa_verified": slsa_level_ok,
        "sbom_attached": sbom_attached,
        "cve": {
            "critical": count(critical_cves),
            "high": count(high_cves),
            "medium": count(medium_cves),
            "low": count(low_cves)
        },
        "sast": {
            "critical": count(critical_sast),
            "high": count(high_sast),
            "medium": count(medium_sast),
            "total": count(input.sast.Issues)
        },
        "deny": [d | d := deny[_]],
        "warnings": [w | w := warnings[_]]
    }
}