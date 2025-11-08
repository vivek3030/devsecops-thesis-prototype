package main

default allow := false

# --- Allow build if no Critical or High vulnerabilities ---
allow if {
    count(critical_vulnerabilities) == 0
    count(high_vulnerabilities) == 0
}

# --- Collect critical vulnerabilities (case-insensitive) ---
critical_vulnerabilities contains id if {
    some i
    vuln := input.vulnerabilities.matches[i]
    lower(vuln.vulnerability.severity) == "critical"
    id := vuln.vulnerability.id
}

# --- Collect high vulnerabilities ---
high_vulnerabilities contains id if {
    some i
    vuln := input.vulnerabilities.matches[i]
    lower(vuln.vulnerability.severity) == "high"
    id := vuln.vulnerability.id
}

# --- Collect medium vulnerabilities (optional use) ---
medium_vulnerabilities contains id if {
    some i
    vuln := input.vulnerabilities.matches[i]
    lower(vuln.vulnerability.severity) == "medium"
    id := vuln.vulnerability.id
}

# --- Deny messages for logging ---
deny contains msg if {
    not allow
    crits := [r | critical_vulnerabilities[r]]
    count(crits) > 0
    msg := sprintf("Build denied: critical vulnerabilities found: %v", [crits])
}

deny contains msg if {
    not allow
    highs := [r | high_vulnerabilities[r]]
    count(highs) > 0
    msg := sprintf("Build denied: high vulnerabilities found: %v", [highs])
}
