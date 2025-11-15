package main

# ================================================
# Top-level allow rule
# Returns true if all checks pass
# ================================================
allow {
    slsa_level_ok
    sbom_attached
    no_critical_cve
    no_critical_sast
}

# ================================================
# SLSA Level check
# ================================================
slsa_level_ok {
    input.slsa_build.level >= 3
    input.slsa_build.provenance_verified
    input.slsa_build.hermetic_build
    input.slsa_build.signed
}

# ================================================
# SBOM check
# ================================================
sbom_attached {
    count(input.sbom.components) > 0
}

# ================================================
# CVE severity checks
# ================================================
no_critical_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Critical"]) == 0
}

no_high_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "High"]) == 0
}

no_medium_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Medium"]) == 0
}

no_low_cve {
    count([m | m := input.vulnerabilities.matches[_]; m.vulnerability.severity == "Low"]) == 0
}

# ================================================
# SAST severity checks
# Gosec: HIGH -> critical, MEDIUM -> high, LOW -> medium
# ================================================
no_critical_sast {
    count([i | i := input.sast.Issues[_]; i.severity == "HIGH"]) == 0
}

no_high_sast {
    count([i | i := input.sast.Issues[_]; i.severity == "MEDIUM"]) == 0
}

no_medium_sast {
    count([i | i := input.sast.Issues[_]; i.severity == "LOW"]) == 0
}

# ================================================
# Deny rules - return violations for reporting
# ================================================
deny[{"type": "SLSA", "msg": msg}] {
    not slsa_level_ok
    msg := "SLSA level requirement not satisfied"
}

deny[{"type": "SBOM", "msg": msg}] {
    not sbom_attached
    msg := "SBOM is missing or empty"
}

deny[{"type": "CVE", "msg": msg}] {
    some m
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "Critical"
    msg := sprintf("Critical CVE found: %v", [m.vulnerability.id])
}

deny[{"type": "SAST", "msg": msg}] {
    some i
    i := input.sast.Issues[_]
    i.severity == "HIGH"
    msg := sprintf("Critical SAST issue found: %v at line %v", [i.rule_id, i.line])
}

# Optional warnings (e.g., high severity CVEs)
warnings[{"type": "CVE", "msg": msg}] {
    some m
    m := input.vulnerabilities.matches[_]
    m.vulnerability.severity == "High"
    msg := sprintf("High CVE found: %v", [m.vulnerability.id])
}

warnings[{"type": "SAST", "msg": msg}] {
    some i
    i := input.sast.Issues[_]
    i.severity == "MEDIUM"
    msg := sprintf("High SAST issue found: %v at line %v", [i.rule_id, i.line])
}

# ================================================
# Compliance report - structured summary
# ================================================
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
