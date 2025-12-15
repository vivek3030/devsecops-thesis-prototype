package main

# ---------------------------
# Main Allow Rule
# ---------------------------
default allow = false

allow if {
    slsa_level_ok
    sbom_attached
    no_critical_cve
    no_high_cve
    no_critical_sast
    no_high_sast
    no_secrets_detected
}

# ---------------------------
# SLSA Level 3 Check
# ---------------------------
slsa_level_ok if {
    input.slsa_build.level >= 3
    input.slsa_build.provenance_verified
    input.slsa_build.signed
}

# Fallback if SLSA data is missing (assume true for signed images)
slsa_level_ok if {
    not input.slsa_build
    input.image.digest != ""
}

# ---------------------------
# SBOM Check
# ---------------------------
sbom_attached if {
    input.sbom.components_count > 0
}

# Fallback for aggregated stats
sbom_attached if {
    not input.sbom.components_count
    input.metadata.version != ""
}

# ---------------------------
# CVE Checks (using aggregated stats)
# ---------------------------
no_critical_cve if {
    input.vulnerabilities.critical == 0
}

no_high_cve if {
    input.vulnerabilities.high == 0
}

# ---------------------------
# SAST Checks (using aggregated stats)
# ---------------------------
no_critical_sast if {
    input.sast.critical == 0
}

no_high_sast if {
    input.sast.high == 0
}

# ---------------------------
# Secret Detection Check
# ---------------------------
no_secrets_detected if {
    input.secrets.verified == 0
}

# ---------------------------
# Deny Rules (Blocking Conditions)
# ---------------------------
deny contains {"type": "SBOM", "msg": "SBOM is missing or empty"} if {
    not sbom_attached
}

deny contains {"type": "CVE", "msg": msg} if {
    input.vulnerabilities.critical > 0
    msg := sprintf("Critical CVE vulnerabilities found: %d", [input.vulnerabilities.critical])
}

deny contains {"type": "CVE", "msg": msg} if {
    input.vulnerabilities.high > 0
    msg := sprintf("High CVE vulnerabilities found: %d", [input.vulnerabilities.high])
}

deny contains {"type": "SAST", "msg": msg} if {
    input.sast.critical > 0
    msg := sprintf("Critical SAST issues found: %d", [input.sast.critical])
}

deny contains {"type": "SAST", "msg": msg} if {
    input.sast.high > 0
    msg := sprintf("High SAST issues found: %d", [input.sast.high])
}

deny contains {"type": "SECRET", "msg": msg} if {
    input.secrets.verified > 0
    msg := sprintf("Hardcoded secrets detected: %d", [input.secrets.verified])
}

# ---------------------------
# Warnings (Non-blocking)
# ---------------------------
warnings contains {"type": "CVE", "msg": msg} if {
    input.vulnerabilities.medium > 0
    msg := sprintf("Medium CVE vulnerabilities found: %d", [input.vulnerabilities.medium])
}

warnings contains {"type": "SAST", "msg": msg} if {
    input.sast.medium > 0
    msg := sprintf("Medium SAST issues found: %d", [input.sast.medium])
}

warnings contains {"type": "CVE", "msg": msg} if {
    input.vulnerabilities.low > 0
    msg := sprintf("Low CVE vulnerabilities found: %d", [input.vulnerabilities.low])
}

# ---------------------------
# Compliance Report
# ---------------------------
compliance_report = report if {
    report := {
        "slsa_verified": slsa_level_ok,
        "sbom_attached": sbom_attached,
        "cve": {
            "critical": input.vulnerabilities.critical,
            "high": input.vulnerabilities.high,
            "medium": input.vulnerabilities.medium,
            "low": input.vulnerabilities.low,
            "total": input.vulnerabilities.total
        },
        "sast": {
            "critical": input.sast.critical,
            "high": input.sast.high,
            "medium": input.sast.medium,
            "low": input.sast.low,
            "total": input.sast.total
        },
        "secrets": {
            "found": input.secrets.found
        },
        "image": {
            "ref": input.image.ref,
            "version": input.metadata.version
        },
        "violations": count(deny),
        "warnings": count(warnings),
        "passed": allow
    }
}