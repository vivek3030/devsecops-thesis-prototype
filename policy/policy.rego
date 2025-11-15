package main

# Top-level allow rule
allow if {
    slsa_level_ok
    sbom_attached
    no_critical_cve
    no_critical_sast
}

# ---------------------------
# SLSA Level
# ---------------------------
slsa_level_ok if {
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
# SAST Checks
# ---------------------------
no_critical_sast if {
    count([i | i := input.sast.Issues[_]; i.severity == "HIGH"]) == 0
}

no_high_sast if {
    count([i | i := input.sast.Issues[_]; i.severity == "MEDIUM"]) == 0
}

# ---------------------------
# Deny rules (partial set)
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
    i := input.sast.Issues[_]
    i.severity == "HIGH"
    msg := sprintf("Critical SAST issue found: %v at line %v", [i.rule_id, i.line])
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