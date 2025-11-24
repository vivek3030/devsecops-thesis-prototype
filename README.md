# DevSecOps Thesis Prototype: Secure CPU Monitor

This repository demonstrates a **SLSA Level 3 compliant DevSecOps pipeline** for a Python Flask application. It integrates automated security scanning, policy enforcement, and secure software supply chain practices.

## 🚀 Application Overview

The application is a lightweight **Realtime CPU Usage Monitor** built with:
- **Backend**: Python Flask
- **Server**: Gunicorn (Production-grade WSGI server)
- **Frontend**: HTML/JS (served via Flask templates)
- **Container**: Docker (Distroless-style slim image)

## 🛡️ Security Architecture

This project implements a "Shift Left" security approach using the following tools:

| Tool | Purpose | Stage |
|------|---------|-------|
| **Syft** | SBOM (Software Bill of Materials) Generation | Build |
| **Cosign** | Container Signing & Attestation (Keyless) | Build |
| **Grype** | SCA (Software Composition Analysis) - CVE Scanning | Scan |
| **Semgrep** | SAST (Static Application Security Testing) | Scan |
| **TruffleHog** | Secret Scanning (API keys, passwords) | Scan |
| **OPA** | Policy as Code (Open Policy Agent) | Gate |

## ⛓️ The Pipeline (GitHub Actions)

The pipeline is defined in `.github/workflows/main.yml` and consists of 5 stages:

### 1. Prepare & Verify
- Checks out code and generates a unique version tag based on the commit SHA and run number.
- Verifies the source directory structure.

### 2. Build (SLSA Level 3)
- **Hermetic Build**: Uses Docker Buildx to build the image in an isolated environment.
- **Signing**: Signs the image using **Sigstore/Cosign** (Keyless mode with OIDC).
- **SBOM**: Generates a CycloneDX JSON SBOM and attaches it to the image registry as an attestation.
- **Verification**: Verifies the signature immediately to ensure non-falsifiable provenance.

### 3. Security Scanning
- **SCA**: Scans the generated SBOM for known CVEs (Common Vulnerabilities and Exposures).
- **SAST**: Scans the source code (`app/`) for insecure coding patterns (e.g., SQL injection, XSS).
- **Secrets**: Scans the entire git history for hardcoded secrets.

### 4. Policy Enforcement (The Gatekeeper)
- Uses **OPA (Open Policy Agent)** to evaluate the results from Stage 3 against `policy/policy.rego`.
- **Decision Logic**:
    - **ALLOW** if: No Critical/High CVEs, No Critical/High SAST issues, No Secrets, SLSA L3 requirements met.
    - **DENY** if: Any blocking condition is met.

### 5. Reporting
- Generates a detailed markdown summary and uploads artifacts.

---

## 📊 Understanding the Pipeline Summary

The GitHub Actions summary provides a snapshot of the security posture. Here's what each element means:

### 📦 Build Information
- **Version**: The unique tag assigned to this build (e.g., `v1.0.123-abc1234`).
- **Image**: The full registry path to the built container.

### 📋 SBOM Analysis
- **Components**: The total number of software libraries, packages, and OS dependencies found inside the container. A higher number increases the attack surface.

### 🔍 Security Scan Results
This section breaks down vulnerabilities by severity:
- **CVE Vulnerabilities**: Known flaws in dependencies (e.g., an old version of `flask` or `glibc`).
    - **Critical/High**: Immediate action required (Blocks deployment).
    - **Medium/Low**: Warnings (May not block, depending on policy).
- **Code Security (SAST)**: Flaws in *your* code (e.g., `app.run()` in production, missing input validation).
- **Secrets**: Hardcoded credentials found in the code.

### 🛡️ Policy Enforcement
- **Status**: `PASSED` or `FAILED`.
- **Decision**: `APPROVED` (Deployable) or `REJECTED` (Blocked).
- **Violations**: The number of specific policy rules broken (e.g., "1 High CVE found").

### 🏆 SLSA Level 3 Compliance
- **Provenance**: Verifies that the artifact was built by *this* specific CI/CD workflow (authenticated via OIDC).
- **Hermetic**: The build process was isolated and reproducible.
- **Signing**: The artifact is cryptographically signed.

---

## 💻 Local Development

To run the application locally (requires Docker):

```bash
# Build the image
docker build -t cpu-monitor app/

# Run the container
docker run -p 5000:5000 cpu-monitor
```

Access the dashboard at `http://localhost:5000`.

## 🔧 Configuration

- **Policy**: Edit `policy/policy.rego` to change blocking criteria (e.g., allow Medium CVEs).
- **Pipeline**: Edit `.github/workflows/main.yml` to adjust scan settings or timeouts.
