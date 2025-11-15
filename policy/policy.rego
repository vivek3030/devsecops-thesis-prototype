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
    count(deny) == 0
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
} else = [] 

# Safe lowercase
lower_safe(x) = y {
    y := lower(x)
} else = ""

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
# CVE VULNERABILITY HANDLING
# ===============================
#

# Count critical CVEs
critical_cve_count = count {
    critical := [v | v := input.vulnerabilities.matches[_]; lower_safe(v.vulnerability.severity) == "critical"]
    count := count(critical)
} else = 0

# Count high CVEs  
high_cve_count = count {
    high := [v | v := input.vulnerabilities.matches[_]; lower_safe(v.vulnerability.severity) == "high"]
    count := count(high)
} else = 0

# Count medium CVEs
medium_cve_count = count {
    medium := [v | v := input.vulnerabilities.matches[_]; lower_safe(v.vulnerability.severity) == "medium"]
    count := count(medium)
} else = 0

# Count low CVEs
low_cve_count = count {
    low := [v | v := input.vulnerabilities.matches[_]; lower_safe(v.vulnerability.severity) == "low"]
    count := count(low)
} else = 0

# CVE Policy Rules
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
# SAST HANDLING
# ===============================
#

# Count critical SAST issues
critical_sast_count = count {
    critical := [i | i := input.sast.Issues[_]; lower_safe(i.severity) == "high"]
    count := count(critical)
} else = 0

# Count high SAST issues
high_sast_count = count {
    high := [i | i := input.sast.Issues[_]; lower_safe(i.severity) == "medium"]
    count := count(high)
} else = 0

# Count medium SAST issues
medium_sast_count = count {
    medium := [i | i := input.sast.Issues[_]; lower_safe(i.severity) == "low"]
    count := count(medium)
} else = 0

# SAST Policy Rules
no_critical_sast {
    critical_sast_count == 0
}

high_sast_acceptable {
    high_sast_count <= 3
}

#
# ===============================
# SBOM VALIDATION
# ===============================
#

sbom_valid {
    input.sbom.components != null
    count(input.sbom.components) > 0
}

#
# ===============================
# DENY RULES
# ===============================
#

deny[msg] {
    critical_cve_count > 0
    critical_ids := [c.vulnerability.id | c := input.vulnerabilities.matches[_]; lower_safe(c.vulnerability.severity) == "critical"]
    msg := sprintf("Critical CVEs found: %v", [critical_ids])
}

deny[msg] {
    high_cve_count > 0
    high_ids := [h.vulnerability.id | h := input.vulnerabilities.matches[_]; lower_safe(h.vulnerability.severity) == "high"]
    msg := sprintf("High severity CVEs found: %v", [high_ids])
}

deny[msg] {
    medium_cve_count > 5
    msg := sprintf("Too many medium CVEs: %d (max 5)", [medium_cve_count])
}

deny[msg] {
    critical_sast_count > 0
    critical_rules := [c.rule_id | c := input.sast.Issues[_]; lower_safe(c.severity) == "high"]
    msg := sprintf("Critical SAST issues found: %v", [critical_rules])
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

compliance_report = report {
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