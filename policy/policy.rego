package main

# Import time functions for the age-based rule
import data.time

# ---
# DEFAULT POLICY: Deny by default
# ---
default allow := false

# ---
# PRIMARY ALLOW RULE:
# Allow if there are NO violations from our deny rules.
# ---
allow if {
    count(deny) == 0
}

# ---
# DENY - VULNERABILITIES (Severity)
# ---
deny contains msg if {
    some id
    critical_vulnerabilities[id]
    msg := sprintf("Build denied: Critical vulnerability found: %v", [id])
}

deny contains msg if {
    some id
    high_vulnerabilities[id]
    msg := sprintf("Build denied: High vulnerability found: %v", [id])
}

# ---
# DENY - VULNERABILITIES (Age)
# This is your advanced "Age-based Prioritization" rule
# ---
deny contains msg if {
    some id
    high_risk_old_vulnerabilities[id]
    msg := sprintf("Build denied: Found 90+ day old HIGH vulnerability: %v", [id])
}

# ---
# DENY - LICENSE COMPLIANCE
# This is your "License Compliance" rule
# ---
deny contains msg if {
    some component
    prohibited_licenses[component]
    msg := sprintf("License violation: Component %v uses prohibited license", [component])
}

# ---
# DENY - SUPPLY CHAIN ATTACK DETECTION
# This is your "Suspicious Component" rule
# ---
deny contains msg if {
    some component
    suspicious_components[component]
    msg := sprintf("Supply chain risk: Suspicious component name found: %v", [component])
}

# ---
# HELPER: Collect Critical vulnerabilities (case-insensitive)
# ---
critical_vulnerabilities contains id if {
    vuln := input.vulnerabilities.matches[_]
    lower(vuln.vulnerability.severity) == "critical"
    id := vuln.vulnerability.id
}

# ---
# HELPER: Collect High vulnerabilities (case-insensitive)
# ---
high_vulnerabilities contains id if {
    vuln := input.vulnerabilities.matches[_]
    lower(vuln.vulnerability.severity) == "high"
    id := vuln.vulnerability.id
}

# ---
# HELPER: Collect 90+ day old "High" vulnerabilities
# ---
high_risk_old_vulnerabilities contains id if {
    vuln := input.vulnerabilities.matches[_]
    lower(vuln.vulnerability.severity) == "high"
    
    # Check if the published date is more than 90 days ago
    days_old(vuln.vulnerability.published) > 90
    
    id := vuln.vulnerability.id
}

# ---
# HELPER: Collect components with prohibited licenses
# ---
prohibited_licenses contains component_name if {
    # Define your list of banned licenses
    banned = {"AGPL-3.0", "GPL-3.0", "GPL-2.0"}
    
    component := input.sbom.components[_]
    license_id := component.licenses[_].license.id
    
    banned[license_id]
    component_name := component.name
}

# ---
# HELPER: Collect components with suspicious names
# ---
suspicious_components contains component_name if {
    component := input.sbom.components[_]
    
    # Check for suspicious patterns
    contains(component.name, "malicious-pattern")
    # You could also check for typosquatting, e.g., "reqeusts"
    
    component_name := component.name
}


# ---
# HELPER FUNCTION: days_old(iso_timestamp)
# Calculates the number of days between an
# ISO 8601 timestamp and the current time.
# ---
days_old(timestamp_str) = days if {
    # 1. Parse the vulnerability's published date string
    # E.g., "2025-10-26T17:29:38.859Z"
    parsed_time_ns := time.parse_rfc3339_ns(timestamp_str)
    
    # 2. Get the current time
    now_ns := time.now_ns()
    
    # 3. Calculate difference in nanoseconds
    diff_ns := now_ns - parsed_time_ns
    
    # 4. Convert nanoseconds to days
    # (1e9 ns/s) * (3600 s/hr) * (24 hr/day) = 8.64e+13 ns/day
    days := diff_ns / 8.64e+13
}