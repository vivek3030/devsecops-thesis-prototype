package main

default allow = false

# Basic security policy
allow {
    # SLSA Level 3 compliance
    input.slsa_build.level == 3
    input.slsa_build.provenance_verified == true
    
    # No critical vulnerabilities
    count([v | v := input.vulnerabilities.matches[_]; v.vulnerability.severity == "Critical"]) == 0
    
    # No high vulnerabilities  
    count([v | v := input.vulnerabilities.matches[_]; v.vulnerability.severity == "High"]) == 0
    
    # SBOM exists
    count(input.sbom.components) > 0
}

# Deny rules for critical issues
deny[msg] {
    count([v | v := input.vulnerabilities.matches[_]; v.vulnerability.severity == "Critical"]) > 0
    msg := "Critical vulnerabilities found"
}

deny[msg] {
    count([v | v := input.vulnerabilities.matches[_]; v.vulnerability.severity == "High"]) > 0
    msg := "High severity vulnerabilities found"
}

deny[msg] {
    input.slsa_build.level != 3
    msg := "SLSA Level 3 not met"
}

deny[msg] {
    count(input.sbom.components) == 0
    msg := "No SBOM components found"
}

# Warnings for informational purposes
warnings[msg] {
    count(input.vulnerabilities.matches) > 0
    msg := sprintf("Total vulnerabilities found: %d", [count(input.vulnerabilities.matches)])
}

warnings[msg] {
    count(input.sast.Issues) > 0
    msg := sprintf("SAST issues found: %d", [count(input.sast.Issues)])
}

# Simple compliance report
compliance_report = {
    "compliant": allow,
    "violations": deny,
    "warnings": warnings,
    "summary": {
        "vulnerabilities": count(input.vulnerabilities.matches),
        "components": count(input.sbom.components),
        "sast_issues": count(input.sast.Issues)
    }
}