# File: policy/policy.rego
# This is the "brain" of the security gate.
# It receives input from the CI pipeline (bom.json and vulnerabilities.json).
package main

# By default, the build is allowed.
# We will write rules that set 'allow' to false.
default allow = true

# --- Vulnerability Rules ---
# Reads from the 'vulnerabilities.json' (Grype) report.

# DENY if any vulnerability is 'Critical'
allow = false {
    # 'some match' iterates over the list of found vulnerabilities
    some match in input.vulnerabilities.matches
    match.vulnerability.severity == "Critical"
    # Print a message when this rule triggers
    print(format("POLICY_VIOLATION: Build blocked due to CRITICAL vulnerability: %s", [match.vulnerability.id]))
}

# DENY if any vulnerability is 'High'
allow = false {
    some match in input.vulnerabilities.matches
    match.vulnerability.severity == "High"
    print(format("POLICY_VIOLATION: Build blocked due to HIGH vulnerability: %s", [match.vulnerability.id]))
}

# --- License Rules ---
# Reads from the 'bom.json' (Syft) report.

# DENY if a forbidden license is found.
# For this example, we block "GPL-3.0".
allow = false {
    some comp in input.sbom.components
    some lic in comp.licenses
    lic.license.id == "GPL-3.0"
    print(format("POLICY_VIOLATION: Build blocked due to forbidden license 'GPL-3.0' in component '%s'", [comp.name]))
}

