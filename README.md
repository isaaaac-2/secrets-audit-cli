# secrets-audit-cli

A security-first CLI tool that scans codebases for hardcoded secrets, API keys, private keys, and misconfigured environment variables. Findings are tracked in a local SQLite database with severity classification, remediation status, and risk-accepted notes, giving teams a clear audit trail from detection to resolution.

Built as a DevSecOps portfolio project demonstrating secure development practices, CI/CD pipeline gating, container security scanning, and infrastructure-as-code hardening.

## What problem am I solving?

Secrets leak into codebases constantly. Most teams discover them after deployment, during audits, or worse, after a breach. Existing tools either just flag issues without tracking remediation, or require expensive SaaS platforms. This project bridges that gap with a lightweight, self-contained scanner that integrates directly into CI/CD pipelines as a security gate.

## Why does it matter?

Security scanning only works if it's part of the workflow developers already use. A standalone scanner gets ignored; a pipeline gate that blocks insecure pushes and tracks findings through resolution actually changes behavior. This project demonstrates that security can be automated, auditable, and developer-friendly without adding friction.

## Features

- Scans directories recursively for multiple secret types (AWS keys, generic API keys, private keys, connection strings, hardcoded passwords, env var leaks)
- Configurable regex-based detection with severity levels (Critical, High, Medium, Low)
- Tracks remediation lifecycle: open → in-progress → resolved / risk-accepted
- Stores reviewer notes and masks detected values before writing to the database
- Generates summary reports by severity and status
- Self-gating CI/CD pipeline via GitHub Actions that blocks pushes with unresolved critical findings
- Containerized with Docker and scanned with Trivy as a build gate
- Static analysis with Semgrep (p/security-audit ruleset) on every push

## Tech Stack

- Backend: FastAPI
- CLI: Typer
- Database: SQLite (with CHECK constraints and automatic timestamps)
- Containerization: Docker
- CI/CD: GitHub Actions (self-gating security pipeline)
- Security tools: Trivy (container image scanning), Semgrep (SAST)

## Quick Start

1. Clone the repository

```bash
git clone https://github.com/isaaaac-2/secrets-audit-cli.git
cd secrets-audit-cli
```

2. Create and activate a virtual environment

```bash
python -m venv secret-cli
# Linux / macOS
source secret-cli/bin/activate
# Windows (PowerShell)
secret-cli\Scripts\Activate.ps1
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Scan a directory for secrets:

```bash
python -m app.cli scan ./your-project
```

List all findings:

```bash
python -m app.cli list
```

List findings filtered by status:

```bash
python -m app.cli list --status open
```

Resolve a finding with remediation notes:

```bash
python -m app.cli resolve <finding_id> --notes "Rotated API key via AWS Secrets Manager"
```

Generate a summary report:

```bash
python -m app.cli report
```

## Detection Patterns

Patterns are defined in `app/secret-patterns.json` and are pre-compiled by the scanner. Each pattern includes a severity level and can be extended without modifying code:

- AWS Access Keys: `AKIA[0-9A-Z]{16}` (Critical)
- Generic API Keys: `api[_-]?key|apikey` (High)
- Private Keys: `-----BEGIN.*PRIVATE KEY-----` (Critical)
- Connection Strings: `mongodb://|postgres://|mysql://` (High)
- Environment Variables: `os\.environ\[|os\.getenv\(` (Medium)
- Hardcoded Passwords: `password\s*=\s*['\"]` (High)

Add or modify patterns in `app/secret-patterns.json`. No code changes required.

## Architecture

```text
                User runs CLI command
                        │
                        ▼
          ┌──────────────────────────────────┐
          │          app/cli.py              │ 
          │         Typer Commands           │  
          │  scan | list | resolve | report  │
          │                                  │
          └──────────────┬───────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
┌───────────────────────┐   ┌───────────────────────┐
│   app/scanner.py      │   │   app/models.py       │
│   Detection Engine    │   │   Database Layer      │
│                       │   │                       │
│ • Loads regex patterns│   │ • SQLite schema       │
│ • Line-by-line scan   │   │ • _mask_secret()      │
│ • Returns raw findings│   │ • CRUD operations     │
└───────────┬───────────┘   │ • Summary reports     │
            │               └───────────┬───────────┘
            │                           │
            ▼                           ▼
┌───────────────────────┐   ┌───────────────────────┐
│ secret-patterns.json  │   │   SQLite DB           │
│ Regex + Severity      │   │   secret_findings     │
└───────────────────────┘   └───────────────────────┘

Security Controls:
• Plaintext secrets never stored or displayed
• CHECK constraints on severity and status
• Auto-updating timestamp trigger
• .gitignore excludes *.db, .env, venv
```

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs three security gates on every push to main:

1. Secret scanner runs against test fixtures to validate detection logic
2. Docker image is built and scanned with Trivy for container vulnerabilities
3. Semgrep performs static analysis using the p/security-audit ruleset

Any HIGH or CRITICAL finding fails the build. Unfixed OS-level vulnerabilities without available patches are documented in `.trivyignore` with justification. This mirrors how production DevSecOps teams handle vulnerability management: fix what you can, document and accept what you can't.

## Security Design Decisions

- Masking occurs at the database layer (`_mask_secret()` in models.py) to ensure plaintext credentials never reach persistent storage, regardless of what the scanner passes in
- The `test/` directory intentionally contains dummy secrets (e.g. `AKIAIOSFODNN7EXAMPLE`) for validation. These are obviously fake and safe to commit
- `.gitignore` excludes runtime artifacts (`*.db`, `.env`, virtual environment directories) to prevent accidental credential or state leakage
- Trivy ignore file documents accepted risks with CVE IDs and justification, following industry-standard vulnerability management practices
- Starlette DoS CVEs (CVE-2025-62727, CVE-2026-48818, CVE-2026-54283) are accepted because this is a CLI tool with no HTTP server running; these vulnerabilities require an active web endpoint to exploit

## Known Tradeoffs

- Starlette vulnerabilities accepted via .trivyignore: This project is a CLI scanner, not a web server. The three Starlette CVEs require an active HTTP endpoint to exploit and are not applicable here. Documented rather than suppressed globally.
- OS-level vulnerabilities in Debian base image: Several HIGH/CRITICAL CVEs in perl, ncurses, and util-linux have no available patches yet. These are upstream issues, not introduced by this project. Tracked in .trivyignore with ignore-unfixed flag so the pipeline only fails on actionable findings.
- Test fixtures committed to repo: The test/ folder contains intentional dummy secrets for validation. A production deployment would use mounted volumes or separate test infrastructure instead.
- SQLite for storage: Chosen for portability and zero-config setup. A production system would use PostgreSQL or similar for concurrent access and scalability.

## Project Structure

```
secrets-audit-cli/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── scanner.py
│   ├── models.py
│   ├── cli.py
│   └── secret-patterns.json
├── test/
│   ├── sample.py
│   └── test_api.py
├── .github/workflows/ci.yml
├── Dockerfile
├── docker-compose.yml
├── .trivyignore
├── requirements.txt
├── .gitignore
└── README.md
```

## License

Apache 2.0
