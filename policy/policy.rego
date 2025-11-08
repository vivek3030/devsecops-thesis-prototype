package main

# Default: deny builds
default allow = false

# Allow if there are no high/critical vulnerabilities
allow {
  count(critical_vulnerabilities) == 0
  count(high_vulnerabilities) == 0
}

# Collect critical vulnerabilities (case-insensitive)
critical_vulnerabilities[id] {
  some i
  vuln := input.vulnerabilities.matches[i]
  severity := lower(vuln.vulnerability.severity)
  severity == "critical"
  id := vuln.vulnerability.id
}

# Collect high vulnerabilities (case-insensitive)
high_vulnerabilities[id] {
  some i
  vuln := input.vulnerabilities.matches[i]
  severity := lower(vuln.vulnerability.severity)
  severity == "high"
  id := vuln.vulnerability.id
}

# Helpful deny message rule (for human readable output)
deny[msg] {
  not allow
  reasons := [r | critical_vulnerabilities[r]]
  count(reasons) > 0
  msg := sprintf("Build denied: critical vulnerabilities found: %v", [reasons])
}

deny[msg] {
  not allow
  reasons := [r | high_vulnerabilities[r]]
  count(reasons) > 0
  msg := sprintf("Build denied: high vulnerabilities found: %v", [reasons])
}