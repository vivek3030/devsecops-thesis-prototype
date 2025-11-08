package main

# Default: deny builds
default allow = false

# Allow only when there are no critical or high vulnerabilities.
# You may change thresholds if you want to allow a small number of medium issues.
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

# Collect medium vulnerabilities (optional)
medium_vulnerabilities[id] {
  some i
  vuln := input.vulnerabilities.matches[i]
  severity := lower(vuln.vulnerability.severity)
  severity == "medium"
  id := vuln.vulnerability.id
}

# Human-readable deny messages (helpful for logs/CI output)
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