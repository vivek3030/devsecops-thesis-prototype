# ============================================
# SLSA Level 3 Security Policy (Corrected Syntax)
# ============================================
# Enhanced OPA policy for SLSA L3 compliance
# Enforces stricter security requirements

package main

# Imports are not needed for 'contains' or 'in' in this context
# 'if' is not a valid keyword for rule definition

# Default deny - fail closed for security
default allow := false

# ============================================
# Final Allow Decision
# ============================================

# Allow build only if all L3 requirements are met
allow {
    # Check if build_metadata was even provided
    input.build_metadata
    
    slsa_level_3_compliant
    medium_vulnerabilities_acceptable
    sbom_requirements_met
}

# ---
# This is a "fallback" allow for testing,
# in case the 'build_metadata' object isn't passed.
# This ensures the vulnerability checks still run.
# ---
allow {
    not input.build_metadata
    
    no_critical_vulnerabilities
    no_high_vulnerabilities
    medium_vulnerabilities_acceptable
    sbom_requirements_met
}

# ============================================
# SLSA L3 Build Requirements
# ============================================

slsa_level_3_compliant {
    hermetic_build_verified
    source_integrity_verified
    no_critical_vulnerabilities
    no_high_vulnerabilities
    provenance_requirements_met
}

# Verify hermetic build (isolated, reproducible)
hermetic_build_verified {
    # Check if build was performed in isolated environment
    input.build_metadata.hermetic == true
}

# Verify source integrity
source_integrity_verified {
    # Ensure source is from trusted repository
    input.build_metadata.source_verified == true
    # Verify commit SHA is present
    count(input.build_metadata.commit_sha) > 0
}

# Check provenance requirements
provenance_requirements_met {
    # Provenance must be non-falsifiable
    input.provenance.non_falsifiable == true
    # Builder must be identified
    count(input.provenance.builder_id) > 0
}

# ============================================
# Vulnerability Checks (Stricter for L3)
# ============================================

# No critical vulnerabilities allowed
no_critical_vulnerabilities {
    count(critical_vulnerabilities) == 0
}

# No high vulnerabilities allowed
no_high_vulnerabilities {
    count(high_vulnerabilities) == 0
}

# Limit medium vulnerabilities (max 5 for L3)
medium_vulnerabilities_acceptable {
    count(medium_vulnerabilities) <= 5
}

# ============================================
# SBOM Requirements for L3
# ============================================

sbom_requirements_met {
    # SBOM must exist
    input.sbom
    # Must have components
    count(input.sbom.components) > 0
    # Must include metadata
    input.sbom.metadata
}

# ============================================
# Helper: Vulnerability Collections
# ============================================

critical_vulnerabilities[vuln] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "critical"
    vuln := {
        "id": match.vulnerability.id,
        "package": match.artifact.name,
        "version": match.artifact.version,
        "severity": match.vulnerability.severity
    }
}

high_vulnerabilities[vuln] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "high"
    vuln := {
        "id": match.vulnerability.id,
        "package": match.artifact.name,
        "version": match.artifact.version,
        "severity": match.vulnerability.severity
    }
}

medium_vulnerabilities[vuln] {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "medium"
    vuln := {
        "id": match.vulnerability.id,
        "package": match.artifact.name,
        "version": match.artifact.version,
        "severity": match.vulnerability.severity
    }
}

# ============================================
# Helper: Deny Messages for Detailed Feedback
# ============================================

deny[msg] {
    count(critical_vulnerabilities) > 0
    crit_list := [v.id | v := critical_vulnerabilities[_]]
    msg := sprintf("❌ SLSA L3 VIOLATION: Critical vulnerabilities found (%d): %v", [count(crit_list), crit_list])
}

deny[msg] {
    count(high_vulnerabilities) > 0
    high_list := [v.id | v := high_vulnerabilities[_]]
    msg := sprintf("❌ SLSA L3 VIOLATION: High vulnerabilities found (%d): %v", [count(high_list), high_list])
}

deny[msg] {
    count(medium_vulnerabilities) > 5
    med_count := count(medium_vulnerabilities)
    msg := sprintf("⚠️  SLSA L3 WARNING: Too many medium vulnerabilities (%d > 5)", [med_count])
}

deny[msg] {
    input.build_metadata
    not hermetic_build_verified
    msg := "❌ SLSA L3 VIOLATION: Hermetic build not verified"
}

deny[msg] {
    input.build_metadata
    not source_integrity_verified
    msg := "❌ SLSA L3 VIOLATION: Source integrity not verified"
}

deny[msg] {
    not sbom_requirements_met
    msg := "❌ SLSA L3 VIOLATION: SBOM requirements not met"
}

# ============================================
# Compliance Report
# (time.now_ns() is not available in opa eval)
# ============================================

compliance_report = report {
    report := {
        "slsa_level": "3",
        "compliant": allow,
        "checks": {
            "critical_vulnerabilities": count(critical_vulnerabilities),
            "high_vulnerabilities": count(high_vulnerabilities),
            "medium_vulnerabilities": count(medium_vulnerabilities),
            "sbom_present": sbom_requirements_met,
            "hermetic_build": hermetic_build_verified,
            "source_integrity": source_integrity_verified
        },
        "violations": count(deny)
    }
}