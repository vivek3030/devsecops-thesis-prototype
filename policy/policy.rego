package main

#
# This policy defines the security gate for the CI/CD pipeline.
#
# The 'input' document is a JSON object with two keys:
# {
#   "vulnerabilities": { ... Grype report ... },
#   "sbom": { ... Syft report ... }
# }
#

# ---
# Main Rule: 'allow'
# ---
# By default, deny the build.
default allow = false

# ALLOW the build if all policies pass
allow if {
	count(critical_vulnerabilities) == 0
	count(high_vulnerabilities) == 0
	count(medium_vulnerabilities) == 0
}

# ---
# Helper Rule: Find Critical Vulnerabilities
# THE FIX IS HERE: Added the 'if' keyword
# ---
critical_vulnerabilities[id] if {
	# Find any vulnerability match
	vuln := input.vulnerabilities.matches[_]
	
	# Check if its severity is "Critical"
	vuln.vulnerability.severity == "Critical"
	
	# Return the ID of the vulnerability
	id := vuln.vulnerability.id
}

# ---
# Helper Rule: Find High Vulnerabilities
# THE FIX IS HERE: Added the 'if' keyword
# ---
high_vulnerabilities[id] if {
	vuln := input.vulnerabilities.matches[_]
	vuln.vulnerability.severity == "High"
	id := vuln.vulnerability.id
}

# ---
# Helper Rule: Find Medium Vulnerabilities
# THE FIX IS HERE: Added the 'if' keyword
# ---
medium_vulnerabilities[id] if {
	vuln := input.vulnerabilities.matches[_]
	vuln.vulnerability.severity == "Medium"
	id := vuln.vulnerability.id
}