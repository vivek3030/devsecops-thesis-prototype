# Automating Software Supply Chain Security: A Framework for Integrating SBOM and SLSA Compliance in CI/CD Pipelines

**Author:** Vivekkumar Kasundra  
**University:** Hochschule Albstadt Sigmaringen

---

## 1. Motivation and Problem

Today, software companies release new code very fast (DevOps). To work efficiently, they utilize a significant amount of open-source code. However, using outside code is a security risk. Famous attacks like **SolarWinds** and **Log4j** showed that bad actors can hide harmful code in these open-source parts.

To fix this problem, there are new security standards:
- **Software Bill of Materials (SBOM):** A list of all code parts inside a software.
- **Supply-chain Levels for Software Artifacts (SLSA):** Rules to make the software building process safer.

The main problem is that using these rules is often a slow, manual process. **The Research Problem:** There is no complete, automatic system that puts SBOM and SLSA security checks directly into the fast CI/CD pipeline. This thesis builds and tests such a system.

## 2. Research Questions

To solve this problem, this thesis answers three main questions:

- **RQ1:** How can we add automatic SBOM creation and security scans into a CI/CD pipeline, without making the process too slow?
- **RQ2:** What are the most important rules we need to write as code to meet the SLSA security standard?
- **RQ3:** How can we demonstrate that this new automatic security system is effective? (e.g., reduces risk, easy for developers).

## 3. Research Method: Design Science Research (DSR)

This project uses the DSR method to build a new IT solution for a real-world problem.

1.  **Study and Learn:** Researching DevSecOps, SBOM, SLSA, and tools like Syft, Grype, and Sigstore.
2.  **Design and Build a Working Model:** Creating a secure CI/CD pipeline (this repository).
3.  **Test the Model:** Measuring security effectiveness, speed, and ease of use.

---

## 4. The Working Model (Prototype Implementation)

This repository contains the **Working Example** of the thesis: a SLSA Level 3 compliant DevSecOps pipeline for a Python Flask application.

### 🚀 Application Overview
The application is a lightweight **Realtime CPU Usage Monitor** built with:
- **Backend**: Python Flask, Gunicorn
- **Frontend**: HTML/JS
- **Container**: Docker (Distroless-style slim image)

### 🛡️ Security Architecture (Shift Left)

| Tool | Purpose | Stage |
|------|---------|-------|
| **Syft** | SBOM Generation (CycloneDX) | Build |
| **Cosign** | Container Signing & Attestation (Keyless) | Build |
| **Grype** | SCA (Vulnerability Scanning) | Scan |
| **Semgrep** | SAST (Static Code Analysis) | Scan |
| **TruffleHog** | Secret Scanning | Scan |
| **OPA** | Policy Enforcement (Gatekeeper) | Gate |

### ⛓️ The Pipeline (GitHub Actions)

The pipeline (`.github/workflows/main.yml`) implements the secure supply chain:

1.  **Prepare & Verify:** Versioning and source verification.
2.  **Build (SLSA L3):**
    *   **Hermetic Build:** Isolated Docker Buildx environment.
    *   **Signing:** Keyless signing with Sigstore/Cosign.
    *   **Attestation:** SBOM attached to the image registry.
3.  **Security Scanning:** Automated SCA, SAST, and Secret scans.
4.  **Policy Enforcement:** **OPA** evaluates results against `policy/policy.rego`.
    *   **ALLOW** if: No Critical/High Vulnerabilities, No Secrets, SLSA L3 met.
    *   **DENY** if: Blocking conditions are met.
5.  **Reporting:** Generates a detailed security summary.

---

## 5. Expected Results

This thesis produces:
- **A Tested Plan for Security:** A complete guide for building this system.
- **A Working Example:** This real, deployable pipeline.
- **Real Data:** Metrics on system speed and effectiveness.
- **Good Advice:** Tips for companies implementing supply chain security.

---

## 💻 Local Development

To run the prototype application locally:

```bash
# Build the image
docker build -t cpu-monitor app/

# Run the container
docker run -p 5000:5000 cpu-monitor
```

Access the dashboard at `http://localhost:5000`.
