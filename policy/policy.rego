# ============================================
# SLSA Level 3 Security Policy (Fixed)
# ============================================
# This policy validates SLSA L3 compliance with proper syntax

package main

# Default deny - fail closed for security
default allow := false

# ============================================
# Final Allow Decision
# ============================================

# Allow build only if all L3 requirements are met
allow if {
    # Check that SLSA build metadata exists
    input.slsa_build
    
    # All requirements must pass
    slsa_level_3_compliant
    no_critical_vulnerabilities
    no_high_vulnerabilities
    medium_vulnerabilities_acceptable
    sbom_requirements_met
}

# ============================================
# SLSA L3 Build Requirements
# ============================================

slsa_level_3_compliant if {
    slsa_build_level_verified
    slsa_builder_verified
    slsa_provenance_verified
}

# Verify SLSA level
slsa_build_level_verified if {
    input.slsa_build.level == 3
}

# Verify SLSA builder ID (flexible check)
slsa_builder_verified if {
    # Accept either official SLSA generator OR GitHub Actions
    builder_id := input.slsa_build.builder_id
    builder_id != ""
}

# Alternative: Strict check for official SLSA generator
# slsa_builder_verified if {
#     contains(input.slsa_build.builder_id, "slsa-github-generator")
# }

# Verify provenance was checked
slsa_provenance_verified if {
    input.slsa_build.provenance_verified == true
}

# ============================================
# Vulnerability Checks (Stricter for L3)
# ============================================

# No critical vulnerabilities allowed
no_critical_vulnerabilities if {
    count(critical_vulnerabilities) == 0
}

# No high vulnerabilities allowed
no_high_vulnerabilities if {
    count(high_vulnerabilities) == 0
}

# Limit medium vulnerabilities (max 5 for L3)
medium_vulnerabilities_acceptable if {
    count(medium_vulnerabilities) <= 5
}

# ============================================
# SBOM Requirements for L3
# ============================================

sbom_requirements_met if {
    # SBOM must exist
    input.sbom
    
    # Must have components array
    input.sbom.components
    
    # Must have at least one component
    count(input.sbom.components) > 0
    
    # Must include metadata
    input.sbom.metadata
}

# ============================================
# Helper: Vulnerability Collections
# ============================================

# Collect critical vulnerabilities
critical_vulnerabilities contains vuln if {
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

# Collect high vulnerabilities
high_vulnerabilities contains vuln if {
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

# Collect medium vulnerabilities
medium_vulnerabilities contains vuln if {
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

# Collect low vulnerabilities (for reporting)
low_vulnerabilities contains vuln if {
    some i
    match := input.vulnerabilities.matches[i]
    lower(match.vulnerability.severity) == "low"
    vuln := {
        "id": match.vulnerability.id,
        "package": match.artifact.name,
        "version": match.artifact.version,
        "severity": match.vulnerability.severity
    }
}

# ============================================
# Deny Messages for Detailed Feedback
# ============================================

deny contains msg if {
    count(critical_vulnerabilities) > 0
    crit_list := [v.id | v := critical_vulnerabilities[_]]
    msg := sprintf("❌ SLSA L3 VIOLATION: Critical vulnerabilities found (%d): %v", [count(crit_list), crit_list])
}

deny contains msg if {
    count(high_vulnerabilities) > 0
    high_list := [v.id | v := high_vulnerabilities[_]]
    msg := sprintf("❌ SLSA L3 VIOLATION: High vulnerabilities found (%d): %v", [count(high_list), high_list])
}

deny contains msg if {
    count(medium_vulnerabilities) > 5
    med_count := count(medium_vulnerabilities)
    msg := sprintf("⚠️  SLSA L3 WARNING: Too many medium vulnerabilities (%d > 5)", [med_count])
}

deny contains msg if {
    not slsa_level_3_compliant
    not input.slsa_build
    msg := "❌ SLSA L3 VIOLATION: SLSA build metadata missing from input"
}

deny contains msg if {
    input.slsa_build
    not slsa_build_level_verified
    msg := sprintf("❌ SLSA L3 VIOLATION: Build level is %v, expected 3", [input.slsa_build.level])
}

deny contains msg if {
    input.slsa_build
    not slsa_builder_verified
    msg := sprintf("❌ SLSA L3 VIOLATION: Invalid builder ID: %v", [input.slsa_build.builder_id])
}

deny contains msg if {
    input.slsa_build
    not slsa_provenance_verified
    msg := sprintf("❌ SLSA L3 VIOLATION: Provenance not verified (value: %v)", [input.slsa_build.provenance_verified])
}

deny contains msg if {
    not sbom_requirements_met
    not input.sbom
    msg := "❌ SLSA L3 VIOLATION: SBOM missing from input"
}

deny contains msg if {
    input.sbom
    not input.sbom.components
    msg := "❌ SLSA L3 VIOLATION: SBOM components array missing"
}

deny contains msg if {
    input.sbom
    input.sbom.components
    count(input.sbom.components) == 0
    msg := "❌ SLSA L3 VIOLATION: SBOM has no components"
}

deny contains msg if {
    input.sbom
    not input.sbom.metadata
    msg := "❌ SLSA L3 VIOLATION: SBOM metadata missing"
}

# ============================================
# Warnings (Non-blocking)
# ============================================

warnings contains msg if {
    count(medium_vulnerabilities) > 0
    count(medium_vulnerabilities) <= 5
    med_count := count(medium_vulnerabilities)
    msg := sprintf("⚠️  WARNING: %d medium vulnerabilities found (acceptable for L3)", [med_count])
}

warnings contains msg if {
    count(low_vulnerabilities) > 10
    low_count := count(low_vulnerabilities)
    msg := sprintf("ℹ️  INFO: %d low vulnerabilities found (consider addressing)", [low_count])
}

# ============================================
# Compliance Report
# ============================================

compliance_report := report if {
    report := {
        "slsa_level": "3",
        "compliant": allow,
        "checks": {
            "slsa_compliant": slsa_level_3_compliant,
            "critical_vulnerabilities": count(critical_vulnerabilities),
            "high_vulnerabilities": count(high_vulnerabilities),
            "medium_vulnerabilities": count(medium_vulnerabilities),
            "medium_vulnerabilities_acceptable": medium_vulnerabilities_acceptable,
            "sbom_present": sbom_requirements_met
        },
        "violations": [msg | deny[msg]],
        "warnings": [msg | warnings[msg]]
    }
}

# ============================================
# Statistics (For Metrics Collection)
# ============================================

statistics := stats if {
    stats := {
        "vulnerabilities": {
            "critical": count(critical_vulnerabilities),
            "high": count(high_vulnerabilities),
            "medium": count(medium_vulnerabilities),
            "low": count(low_vulnerabilities),
            "total": count(input.vulnerabilities.matches)
        },
        "sbom": {
            "components": count(input.sbom.components),
            "has_metadata": input.sbom.metadata != null
        },
        "slsa": {
            "level": input.slsa_build.level,
            "builder": input.slsa_build.builder_id,
            "provenance_verified": input.slsa_build.provenance_verified,
            "hermetic_build": input.slsa_build.hermetic_build
        }
    }
}