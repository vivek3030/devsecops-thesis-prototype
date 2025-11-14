package main

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