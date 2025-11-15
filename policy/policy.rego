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
    obj[field]
    arr := obj[field]
} else = [] { 
    true 
}

# Safe lowercase
lower_safe(x) = y {
    y := lower(x)
} else = "" { 
    true 
}

#
# ===============================
# SLSA REQUIREMENTS (Null-safe)
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
# CVE VULNERABILITY HANDLING
# ===============================
#

vuln_data := input.vulnerabilities
matches := get_array(vuln_data, "matches")

critical_cve_count = count {
    critical_cve = [v | v := matches[_]; lower_safe(v.vulnerability.severity) == "critical"]
    count = count(critical_cve)
}

high_cve_count = count {
    high_cve = [v | v := matches[_]; lower_safe(v.vulnerability.severity) == "high"]
    count = count(high_cve)
}

medium_cve_count = count {
    medium_cve = [v | v := matches[_]; lower_safe(v.vulnerability.severity) == "medium"]
    count = count(medium_cve)
}

low_cve_count = count {
    low_cve = [v | v := matches[_]; lower_safe(v.vulnerability.severity) == "low"]
    count = count(low_cve)
}

# ---- Policy Rules ----
no_critical_cve {
    critical_cve_count == 0
}

no_high_cve {
    high_cve_count == 0
}

medium_cve_acceptable {
    medium_cve_count <= 5
}

#
# ===============================
# SAST (Null-safe)
# ===============================
#

sast_data := input.sast
issues := get_array(sast_data, "Issues")

critical_sast_count = count {
    critical_sast = [i | i := issues[_]; lower_safe(i.severity) == "high"]
    count = count(critical_sast)
}

high_sast_count = count {
    high_sast = [i | i := issues[_]; lower_safe(i.severity) == "medium"]
    count = count(high_sast)
}

medium_sast_count = count {
    medium_sast = [i | i := issues[_]; lower_safe(i.severity) == "low"]
    count = count(medium_sast)
}

no_critical_sast {
    critical_sast_count == 0
}

high_sast_acceptable {
    high_sast_count <= 3
}

#
# ===============================
# SBOM (Null-safe)
# ===============================
#

sbom_valid {
    input.sbom != null
    input.sbom.components != null
    count(input.sbom.components) > 0
}

#
# ===============================
# DENY RULES (Fail reasons)
# ===============================
#

deny[msg] {
    critical_cve_count > 0
    critical_ids := [c.vulnerability.id | c := get_array(input.vulnerabilities, "matches")[_]; lower_safe(c.vulnerability.severity) == "critical"]
    msg := sprintf("❌ Critical CVEs found: %v", [critical_ids])
}

deny[msg] {
    high_cve_count > 0
    high_ids := [h.vulnerability.id | h := get_array(input.vulnerabilities, "matches")[_]; lower_safe(h.vulnerability.severity) == "high"]
    msg := sprintf("❌ High severity CVEs found: %v", [high_ids])
}

deny[msg] {
    medium_cve_count > 5
    msg := sprintf("⚠️ Too many medium CVEs: %d (max 5)", [medium_cve_count])
}

deny[msg] {
    critical_sast_count > 0
    critical_rules := [c.rule_id | c := get_array(input.sast, "Issues")[_]; lower_safe(c.severity) == "high"]
    msg := sprintf("❌ Critical SAST issues found: %v", [critical_rules])
}

deny[msg] {
    high_sast_count > 3
    msg := sprintf("❌ Too many high SAST issues: %d (max 3)", [high_sast_count])
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
    medium_cve_count > 0
    medium_cve_count <= 5
    msg := sprintf("⚠️ Medium CVEs present: %d (acceptable)", [medium_cve_count])
}

warnings[msg] {
    low_cve_count > 10
    msg := sprintf("ℹ️ Many low CVEs: %d", [low_cve_count])
}

warnings[msg] {
    high_sast_count > 0
    high_sast_count <= 3
    msg := sprintf("⚠️ High severity SAST issues present: %d (acceptable)", [high_sast_count])
}

warnings[msg] {
    medium_sast_count > 5
    msg := sprintf("ℹ️ Medium severity SAST issues: %d", [medium_sast_count])
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
            "critical": critical_cve_count,
            "high": high_cve_count,
            "medium": medium_cve_count,
            "low": low_cve_count,
        },
        "sast": {
            "critical": critical_sast_count,
            "high": high_sast_count,
            "medium": medium_sast_count,
        },
        "slsa": slsa_level_3_compliant,
        "sbom": sbom_valid,
    }
}