package main

#
# ===============================
# DEFAULTS
# ===============================
#

default allow = false

# Allow only if conditions are met AND no deny rules fire
allow {
    allow_conditions
    count(deny) == 0
}

#
# ===============================
# NULL-SAFE HELPERS
# ===============================
#

# Safe get: return [] if field does not exist or is null
get_array(obj, field) = arr {
    obj[field] != null
    arr := obj[field]
} else = []


# Safe lowercase conversion
lower_safe(x) = y {
    x != null
    y := lower(x)
} else = ""

#
# ===============================
# SAFE INPUT ARRAYS
# ===============================
#

vulns := get_array(input.vulnerabilities, "matches")
sast_issues := get_array(input.sast, "Issues")

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
# CVE COUNTS (NULL SAFE)
# ===============================
#

critical_cve_count = count(critical) {
    critical := [v |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "critical"
    ]
}

high_cve_count = count(high) {
    high := [v |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "high"
    ]
}

medium_cve_count = count(med) {
    med := [v |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "medium"
    ]
}

low_cve_count = count(low) {
    low := [v |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "low"
    ]
}

#
# ===============================
# CVE POLICY RULES
# ===============================
#

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
# SAST COUNTS (NULL SAFE)
# ===============================
#

critical_sast_count = count(crit) {
    crit := [i |
        i := sast_issues[_];
        lower_safe(i.severity) == "high"  # Gosec HIGH → Critical
    ]
}

high_sast_count = count(high) {
    high := [i |
        i := sast_issues[_];
        lower_safe(i.severity) == "medium"  # MEDIUM → High
    ]
}

medium_sast_count = count(med) {
    med := [i |
        i := sast_issues[_];
        lower_safe(i.severity) == "low"     # LOW → Medium
    ]
}

#
# ===============================
# SAST POLICY RULES
# ===============================
#

no_critical_sast {
    critical_sast_count == 0
}

high_sast_acceptable {
    high_sast_count <= 3
}

#
# ===============================
# SBOM VALIDATION (NULL SAFE)
# ===============================
#

sbom_valid {
    input.sbom != null
    input.sbom.components != null
    count(input.sbom.components) > 0
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
# DENY RULES
# ===============================
#

deny[msg] {
    critical_cve_count > 0
    ids := [v.vulnerability.id |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "critical"
    ]
    msg := sprintf("Critical CVEs found: %v", [ids])
}

deny[msg] {
    high_cve_count > 0
    ids := [v.vulnerability.id |
        v := vulns[_];
        lower_safe(v.vulnerability.severity) == "high"
    ]
    msg := sprintf("High severity CVEs found: %v", [ids])
}

deny[msg] {
    medium_cve_count > 5
    msg := sprintf("Too many medium CVEs: %d (max 5)", [medium_cve_count])
}

deny[msg] {
    critical_sast_count > 0
    rules := [i.rule_id |
        i := sast_issues[_];
        lower_safe(i.severity) == "high"
    ]
    msg := sprintf("Critical SAST issues found: %v", [rules])
}

deny[msg] {
    high_sast_count > 3
    msg := sprintf("Too many high SAST issues: %d (max 3)", [high_sast_count])
}

deny[msg] {
    not slsa_level_3_compliant
    msg := "SLSA L3 compliance not met"
}

deny[msg] {
    not sbom_valid
    msg := "Invalid or incomplete SBOM"
}

#
# ===============================
# WARNINGS
# ===============================
#

warnings[msg] {
    medium_cve_count > 0
    medium_cve_count <= 5
    msg := sprintf("Medium CVEs present: %d (acceptable)", [medium_cve_count])
}

warnings[msg] {
    low_cve_count > 10
    msg := sprintf("Many low CVEs: %d", [low_cve_count])
}

warnings[msg] {
    high_sast_count > 0
    high_sast_count <= 3
    msg := sprintf("High severity SAST issues present: %d (acceptable)", [high_sast_count])
}

warnings[msg] {
    medium_sast_count > 5
    msg := sprintf("Medium severity SAST issues: %d", [medium_sast_count])
}

#
# ===============================
# COMPLIANCE REPORT
# ===============================
#

compliance_report = r {
    r := {
        "compliant": allow,
        "violations": deny,
        "warnings": warnings,
        "cve": {
            "critical": critical_cve_count,
            "high": high_cve_count,
            "medium": medium_cve_count,
            "low": low_cve_count
        },
        "sast": {
            "critical": critical_sast_count,
            "high": high_sast_count,
            "medium": medium_sast_count
        },
        "slsa": slsa_level_3_compliant,
        "sbom": sbom_valid
    }
}
