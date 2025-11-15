package main

# Top-level allow rule
allow {
    slsa_level_ok
    sbom_attached
    no_critical_cve
    no_critical_sast
}

# ---------------------------
# SLSA Level
# ---------------------------
slsa_level_ok {
    input.slsa_build.level >= 3
    input.slsa_build.provenance_verified
    input.slsa_build.hermetic_build
    input.slsa_build.signed
}

# ---------------------------
# SBOM Check
# ---------------------------
sbom_attached {
    count(input.sbom.components) > 0
}

# ---------------------------
# CVE Checks
# ---------------------------
no_critical_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Critical"]) == 0
}

no_high_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "High"]) == 0
}

# ---------------------------
# SAST Checks
# ---------------------------
no_critical_sast {
    count([i | i := input.sast.Issues[_]; i.severity == "HIGH"]) == 0
}

no_high_sast {
    count([i | i := input.sast.Issues[_]; i.severity == "MEDIUM"]) == 0
}

# ---------------------------
# Deny rules
# ---------------------------
deny[{"type": "SLSA", "msg": "SLSA level requirement not satisfied"}] {
    not slsa_level_ok
}

deny[{"type": "SBOM", "msg": "SBOM is missing or empty"}] {
    not sbom_attached
}

deny[{"type": "CVE", "msg": msg}] {
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "Critical"
    msg := sprintf("Critical CVE found: %v", [m.vulnerability.id])
}

deny[{"type": "SAST", "msg": msg}] {
    i := input.sast.Issues[_]
    i.severity == "HIGH"
    msg := sprintf("Critical SAST issue found: %v at line %v", [i.rule_id, i.line])
}

# ---------------------------
# Warnings (optional)
# ---------------------------
warnings[{"type": "CVE", "msg": msg}] {
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "High"
    msg := sprintf("High CVE found: %v", [m.vulnerability.id])
}

warnings[{"type": "SAST", "msg": msg}] {
    i := input.sast.Issues[_]
    i.severity == "MEDIUM"
    msg := sprintf("High SAST issue found: %v at line %v", [i.rule_id, i.line])
}

# ---------------------------
# Compliance report
# ---------------------------
compliance_report = report {
    report := {
        "slsa_level": input.slsa_build.level,
        "slsa_verified": slsa_level_ok,
        "sbom_attached": sbom_attached,
        "cve": {
            "critical": count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Critical"]),
            "high": count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "High"]),
            "medium": count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Medium"]),
            "low": count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Low"])
        },
        "sast": {
            "critical": count([i | i := input.sast.Issues[_]; i.severity == "HIGH"]),
            "high": count([i | i := input.sast.Issues[_]; i.severity == "MEDIUM"]),
            "medium": count([i | i := input.sast.Issues[_]; i.severity == "LOW"]),
            "total": count(input.sast.Issues)
        },
        "deny": [d | d := deny[_]],
        "warnings": [w | w := warnings[_]]
    }
}
