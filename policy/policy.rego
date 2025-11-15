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
    no_critical_cve_vulnerabilities
    no_high_cve_vulnerabilities
    medium_cve_vulnerabilities_acceptable
    no_critical_sast_issues
    no_high_sast_issues
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
# CVE VULNERABILITY RULES
# ===============================
#

no_critical_cve_vulnerabilities {
    count(critical_cve_vulnerabilities) == 0
}

no_high_cve_vulnerabilities {
    count(high_cve_vulnerabilities) == 0
}

medium_cve_vulnerabilities_acceptable {
    count(medium_cve_vulnerabilities) <= 5
}

#
# ===============================
# SAST (Code Quality) RULES
# ===============================
#

no_critical_sast_issues {
    count(critical_sast_issues) == 0
}

no_high_sast_issues {
    count(high_sast_issues) <= 3
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
# CVE Vulnerability Collections
# ===============================
#

critical_cve_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "critical"
    v := match
}

high_cve_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "high"
    v := match
}

medium_cve_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "medium"
    v := match
}

low_cve_vulnerabilities[v] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "low"
    v := match
}

#
# ===============================
# SAST Issue Collections
# ===============================
#

critical_sast_issues[issue] {
    some i
    sast_issue := input.sast.Issues[i]
    sast_issue.severity == "HIGH"  # Gosec HIGH = Critical
    issue := sast_issue
}

high_sast_issues[issue] {
    some i
    sast_issue := input.sast.Issues[i]
    sast_issue.severity == "MEDIUM"  # Gosec MEDIUM = High
    issue := sast_issue
}

medium_sast_issues[issue] {
    some i
    sast_issue := input.sast.Issues[i]
    sast_issue.severity == "LOW"  # Gosec LOW = Medium
    issue := sast_issue
}

#
# ===============================
# DENY MESSAGES
# ===============================
#

deny[msg] {
    count(critical_cve_vulnerabilities) > 0
    ids := [c.vulnerability.id | c := critical_cve_vulnerabilities[_]]
    msg := sprintf("❌ Critical CVE vulnerabilities found: %v", [ids])
}

deny[msg] {
    count(high_cve_vulnerabilities) > 0
    ids := [h.vulnerability.id | h := high_cve_vulnerabilities[_]]
    msg := sprintf("❌ High CVE vulnerabilities found: %v", [ids])
}

deny[msg] {
    count(medium_cve_vulnerabilities) > 5
    msg := sprintf("⚠️ Too many medium CVE vulnerabilities: %d (max 5)", [count(medium_cve_vulnerabilities)])
}

deny[msg] {
    count(critical_sast_issues) > 0
    rules := [issue.rule_id | issue := critical_sast_issues[_]]
    msg := sprintf("❌ Critical code security issues found: %v", [rules])
}

deny[msg] {
    count(high_sast_issues) > 3
    msg := sprintf("❌ Too many high severity code issues: %d (max 3)", [count(high_sast_issues)])
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
    count(medium_cve_vulnerabilities) > 0
    count(medium_cve_vulnerabilities) <= 5
    msg := sprintf("⚠️ Medium CVE vulnerabilities present: %d (acceptable)", [count(medium_cve_vulnerabilities)])
}

warnings[msg] {
    count(low_cve_vulnerabilities) > 10
    msg := sprintf("ℹ️ Many low CVE vulnerabilities: %d", [count(low_cve_vulnerabilities)])
}

warnings[msg] {
    count(high_sast_issues) > 0
    count(high_sast_issues) <= 3
    msg := sprintf("⚠️ High severity code issues present: %d (acceptable)", [count(high_sast_issues)])
}

warnings[msg] {
    count(medium_sast_issues) > 5
    msg := sprintf("ℹ️ Medium severity code issues: %d", [count(medium_sast_issues)])
}

#
# ===============================
# COMPLIANCE REPORT
# ===============================
#

compliance_report = report {
    report := {
        "compliant": allow,
        "cve_vulnerabilities": {
            "critical": count(critical_cve_vulnerabilities),
            "high": count(high_cve_vulnerabilities),
            "medium": count(medium_cve_vulnerabilities),
            "low": count(low_cve_vulnerabilities)
        },
        "sast_issues": {
            "critical": count(critical_sast_issues),
            "high": count(high_sast_issues),
            "medium": count(medium_sast_issues)
        },
        "violations": [d | d := deny[_]],
        "warnings": [w | w := warnings[_]],
        "slsa_compliant": slsa_level_3_compliant,
        "sbom_valid": sbom_requirements_met
    }
}