package main

#
# ===============================
# DEFAULTS
# ===============================
#

default allow = false

# If ANY deny rule fires → allow = false.
# Allow only when allow_conditions is true AND no deny rules exist.
allow {
    allow_conditions
    not deny_exists
}

deny_exists {
    deny[_]
}

#
# ===============================
# ALLOW CONDITIONS
# ===============================
#

allow_conditions {
    slsa_level_3_compliant
    no_critical_cve
    no_high_cve
    medium_cve_acceptable
    no_critical_sast
    high_sast_acceptable
    sbom_valid
}

#
# ===============================
# SAFE HELPERS
# ===============================
#

# Safe getter — returns empty array if field missing.
get_array(obj, field) = arr {
    arr := obj[field]
} else = [] { true }

# Safe lowercase
lower_safe(x) = y {
    y := lower(x)
} else = "" { true }

#
# ===============================
# SLSA REQUIREMENTS (Null-safe)
# ===============================
#

slsa := input.slsa_build

slsa_level_3_compliant {
    slsa.level == 3
    slsa.provenance_verified == true
    slsa.hermetic_build == true
    slsa.builder_id != ""
}

#
# ===============================
# CVE VULNERABILITY HANDLING
# ===============================
#

vuln_data := input.vulnerabilities
matches := get_array(vuln_data, "matches")

critical_cve[v] {
    v := matches[_]
    lower_safe(v.vulnerability.severity) == "critical"
}

high_cve[v] {
    v := matches[_]
    lower_safe(v.vulnerability.severity) == "high"
}

medium_cve[v] {
    v := matches[_]
    lower_safe(v.vulnerability.severity) == "medium"
}

low_cve[v] {
    v := matches[_]
    lower_safe(v.vulnerability.severity) == "low"
}

# ---- Policy Rules ----
no_critical_cve {
    count(critical_cve) == 0
}

no_high_cve {
    count(high_cve) == 0
}

medium_cve_acceptable {
    count(medium_cve) <= 5
}

#
# ===============================
# SAST (Null-safe)
# ===============================
#

sast := input.sast
issues := get_array(sast, "Issues")

critical_sast[i] {
    issue := issues[_]
    lower_safe(issue.severity) == "high"   # Gosec HIGH = Critical
    i := issue
}

high_sast[i] {
    issue := issues[_]
    lower_safe(issue.severity) == "medium" # Gosec MEDIUM = High
    i := issue
}

medium_sast[i] {
    issue := issues[_]
    lower_safe(issue.severity) == "low"
    i := issue
}

no_critical_sast {
    count(critical_sast) == 0
}

high_sast_acceptable {
    count(high_sast) <= 3
}

#
# ===============================
# SBOM (Null-safe)
# ===============================
#

sbom := input.sbom

sbom_valid {
    sbom != null
    sbom.components != null
    count(sbom.components) > 0
}

#
# ===============================
# DENY RULES (Fail reasons)
# ===============================
#

deny[msg] {
    count(critical_cve) > 0
    critical_ids := [c.vulnerability.id | c := critical_cve[_]]
    msg := sprintf("❌ Critical CVEs found: %v", [critical_ids])
}

deny[msg] {
    count(high_cve) > 0
    high_ids := [h.vulnerability.id | h := high_cve[_]]
    msg := sprintf("❌ High severity CVEs found: %v", [high_ids])
}

deny[msg] {
    count(medium_cve) > 5
    msg := sprintf("⚠️ Too many medium CVEs: %d (max 5)", [count(medium_cve)])
}

deny[msg] {
    count(critical_sast) > 0
    critical_rules := [c.rule_id | c := critical_sast[_]]
    msg := sprintf("❌ Critical SAST issues found: %v", [critical_rules])
}

deny[msg] {
    count(high_sast) > 3
    msg := sprintf("❌ Too many high SAST issues: %d (max 3)", [count(high_sast)])
}

deny[msg] {
    not slsa_level_3_compliant
    msg := "❌ SLSA L3 compliance not met"
}

deny[msg] {
    not sbom_valid
    msg := "❌ Invalid or incomplete SBOM"
}

#
# ===============================
# WARNINGS
# ===============================
#

warnings[msg] {
    count(medium_cve) > 0
    count(medium_cve) <= 5
    msg := sprintf("⚠️ Medium CVEs present: %d (acceptable)", [count(medium_cve)])
}

warnings[msg] {
    count(low_cve) > 10
    msg := sprintf("ℹ️ Many low CVEs: %d", [count(low_cve)])
}

warnings[msg] {
    count(high_sast) > 0
    count(high_sast) <= 3
    msg := sprintf("⚠️ High severity SAST issues present: %d (acceptable)", [count(high_sast)])
}

warnings[msg] {
    count(medium_sast) > 5
    msg := sprintf("ℹ️ Medium severity SAST issues: %d", [count(medium_sast)])
}

#
# ===============================
# COMPLIANCE REPORT
# ===============================
#

compliance_report = report {
    report := {
        "compliant": allow,
        "violations": [d | d := deny[_]],
        "warnings": [w | w := warnings[_]],
        "cve": {
            "critical": count(critical_cve),
            "high": count(high_cve),
            "medium": count(medium_cve),
            "low": count(low_cve),
        },
        "sast": {
            "critical": count(critical_sast),
            "high": count(high_sast),
            "medium": count(medium_sast),
        },
        "slsa": slsa_level_3_compliant,
        "sbom": sbom_valid,
    }
}