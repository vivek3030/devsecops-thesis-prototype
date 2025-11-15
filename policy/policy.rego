package main

default allow = false
default deny = []
default warnings = []
default compliance_report = {}

###################################
# Utility: safe value extraction
###################################
safe_get(obj, key, defval) = val {
    some obj[key]
    val := obj[key]
} else = val {
    val := defval
}

###################################
# Allow rule (no critical vulns)
###################################
allow {
    count(input.vulnerabilities.matches) == 0
}

###################################
# Deny: Critical vulnerabilities
###################################
deny[msg] {
    m := input.vulnerabilities.matches[_]
    sev := safe_get(m.vulnerability, "severity", "UNKNOWN")
    sev == "Critical"
    msg := sprintf("Critical vulnerability: %s", [m.vulnerability.id])
}

###################################
# Deny: High vulnerabilities
###################################
deny[msg] {
    m := input.vulnerabilities.matches[_]
    sev := safe_get(m.vulnerability, "severity", "UNKNOWN")
    sev == "High"
    msg := sprintf("High vulnerability: %s", [m.vulnerability.id])
}

###################################
# Warnings (Medium/Low)
###################################
warnings[msg] {
    m := input.vulnerabilities.matches[_]
    sev := safe_get(m.vulnerability, "severity", "UNKNOWN")
    sev == "Medium"
    msg := sprintf("Medium severity vulnerability: %s", [m.vulnerability.id])
}

warnings[msg] {
    m := input.vulnerabilities.matches[_]
    sev := safe_get(m.vulnerability, "severity", "UNKNOWN")
    sev == "Low"
    msg := sprintf("Low severity vulnerability: %s", [m.vulnerability.id])
}

###################################
# Compliance report
###################################
compliance_report := {
    "total":       count(input.vulnerabilities.matches),
    "critical":    count([m | m := input.vulnerabilities.matches[_];
                              safe_get(m.vulnerability, "severity", "UNKNOWN") == "Critical"]),
    "high":        count([m | m := input.vulnerabilities.matches[_];
                              safe_get(m.vulnerability, "severity", "UNKNOWN") == "High"]),
    "medium":      count([m | m := input.vulnerabilities.matches[_];
                              safe_get(m.vulnerability, "severity", "UNKNOWN") == "Medium"]),
    "low":         count([m | m := input.vulnerabilities.matches[_];
                              safe_get(m.vulnerability, "severity", "UNKNOWN") == "Low"])
}
