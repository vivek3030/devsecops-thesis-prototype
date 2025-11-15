package main

# Default = deny unless requirements met
default allow = false

#
# ===============================
# ALLOW RULE
# ===============================
#

allow {
    slsa_level_3_compliant
    no_critical_vulnerabilities
    no_high_vulnerabilities
    medium_vulnerabilities_acceptable
    sbom_requirements_met
}

#
# ===============================
# SLSA REQUIREMENTS
# ===============================
#

slsa_level_3_compliant {
    input.slsa_build.level == 3
    input.slsa_build.provenance_verified == true
    input.slsa_build.hermetic_build == true
    input.slsa_build.builder_id != ""
}

#
# ===============================
# VULNERABILITY RULES
# ===============================
#

no_critical_vulnerabilities {
    count(critical_vulnerabilities) == 0
}

no_high_vulnerabilities {
    count(high_vulnerabilities) == 0
}

medium_vulnerabilities_acceptable {
    count(medium_vulnerabilities) <= 5
}

#
# ===============================
# SBOM REQUIREMENTS
# ===============================
#

sbom_requirements_met {
    input.sbom != null
    input.sbom.components != null
    count(input.sbom.components) > 0
    input.sbom.metadata != null
}

#
# ===============================
# Vulnerability Collections
# ===============================
#

critical_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "critical"
    v := match
}

high_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "high"
    v := match
}

medium_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "medium"
    v := match
}

low_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "low"
    v := match
}

#
# ===============================
# DENY MESSAGES
# ===============================
#

deny[msg] {
    count(critical_vulnerabilities) > 0
    ids := [c.vulnerability.id | c := critical_vulnerabilities[_]]
    msg := sprintf("❌ Critical vulnerabilities found: %v", [ids])
}

deny[msg] {
    count(high_vulnerabilities) > 0
    ids := [h.vulnerability.id | h := high_vulnerabilities[_]]
    msg := sprintf("❌ High vulnerabilities found: %v", [ids])
}

deny[msg] {
    count(medium_vulnerabilities) > 5
    msg := sprintf("⚠️ Too many medium vulnerabilities: %d (max 5)", [count(medium_vulnerabilities)])
}

deny[msg] {
    not slsa_level_3_compliant
    msg := "❌ SLSA L3 compliance requirements not met"
}

deny[msg] {
    not sbom_requirements_met
    msg := "❌ SBOM does not meet minimum requirements"
}

#
# ===============================
# WARNINGS
# ===============================
#

warnings[msg] {
    count(medium_vulnerabilities) > 0
    count(medium_vulnerabilities) <= 5
    msg := sprintf("⚠️ Medium vulnerabilities present: %d (acceptable)", [count(medium_vulnerabilities)])
}

warnings[msg] {
    count(low_vulnerabilities) > 10
    msg := sprintf("ℹ️ Many low vulnerabilities: %d", [count(low_vulnerabilities)])
}

#
# ===============================
# COMPLIANCE REPORT (Optional)
# ===============================
#

compliance_report = report {
    report := {
        "compliant": allow,
        "critical": count(critical_vulnerabilities),
        "high": count(high_vulnerabilities),
        "medium": count(medium_vulnerabilities),
        "low": count(low_vulnerabilities),
        "violations": [d | d := deny[_]],
        "warnings": [w | w := warnings[_]]
    }
}