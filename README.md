# secrets-audit-cli

A security-first CLI tool that scans codebases for hardcoded secrets, API keys, private keys, and misconfigured environment variables. Findings are tracked in a local SQLite database with severity classification, remediation status, and risk-accepted notes, giving teams a clear audit trail from detection to resolution.

Built as a DevSecOps portfolio project demonstrating secure development practices, CI/CD integration, and infrastructure-as-code hardening.

## Features

• Scans directories recursively for 6+ secret types (AWS keys, generic API keys, private keys, connection strings, hardcoded passwords, env var leaks)
• Classifies findings by severity (Critical, High, Medium, Low) using configurable regex patterns
• Tracks remediation lifecycle: open → in-progress → resolved or risk-accepted
• Stores reviewer notes with justification for accepted risks
• Generates summary reports showing severity and status breakdowns
• Masks all detected secrets before storage so plaintext credentials never touch the DB or terminal
• Self-gating CI/CD integration via GitHub Actions
• Containerized with Docker and scanned with Trivy as a container security gate

## Tech Stack

• Backend: FastAPI
• CLI: Typer
• Database: SQLite with CHECK constraints and auto-updating timestamps
• Containerization: Docker
• CI/CD: GitHub Actions
• Security Scanning: Trivy (container), Semgrep (SAST)
• Deployment Target: Azure App Service (free tier)

## Features

- Scans directories recursively for multiple secret types (AWS keys, generic API keys, private keys, connection strings, hardcoded passwords, env var leaks).
- Configurable regex-based detection with severity levels (Critical, High, Medium, Low).
- Tracks remediation lifecycle: `open` → `in-progress` → `resolved` / `risk-accepted`.
- Stores reviewer notes and masks detected values before writing to the database.
- Generates summary reports by severity and status.
- CI/CD friendly: designed for GitHub Actions gating and container scanning (Trivy).

## Tech Stack

- Backend: FastAPI
- CLI: Typer
- Database: SQLite (with CHECK constraints and automatic timestamps)
- Containerization: Docker
- CI/CD: GitHub Actions
- Security tools: Trivy (image scanning), Semgrep (SAST)

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
secret-cli\\Scripts\\Activate.ps1
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

- Scan a directory:

```bash
python -m app.cli scan ./your-project
```

- List all findings:

```bash
python -m app.cli list
```

- List findings filtered by status:

```bash
python -m app.cli list --status open
```

- Resolve a finding:

```bash
python -m app.cli resolve <finding_id> --notes "Rotated API key"
```

- Generate a summary report:

```bash
python -m app.cli report
```

## Detection Patterns

Patterns are defined in `app/secret-patterns.json` and are pre-compiled by the scanner. Example patterns included by default:

- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- Generic API Keys: `api[_-]?key|apikey`
- Private Keys: `-----BEGIN.*PRIVATE KEY-----`
- Connection Strings: `mongodb://|postgres://|mysql://`
- Environment Variables: `os\\.environ\\[|os\\.getenv\\(`
- Hardcoded Passwords: `password\\s*=\\s*['\\\"]`

Add or modify patterns in `app/secret-patterns.json` — no code changes required.

## Architecture

```mermaid
flowchart TD
    User[User] -->|runs CLI command| CLI[app/cli.py<br/>Typer Commands]
    CLI -->|scan| Scanner[app/scanner.py<br/>Detection Engine]
    CLI -->|list / resolve / report| Models[app/models.py<br/>Database Layer]
    Scanner -->|loads patterns| Config[app/secret-patterns.json<br/>Regex + Severity]
    Scanner -->|raw findings| Models
    Models -->|masked write / read| DB[(SQLite<br/>secret_findings)]
    subgraph Security_Controls
        Mask[_mask_secret()<br/>Plaintext never stored]
        Check[CHECK Constraints<br/>Severity + Status]
        Trigger[Auto Timestamp<br/>updated_at]
    end
    Models --- Mask
    Models --- Check
    Models --- Trigger
    subgraph CI_CD_Pipeline
        GHA[GitHub Actions<br/>Self-gating]
        Trivy[Trivy<br/>Container Scan]
        Semgrep[Semgrep<br/>SAST]
    end
    GHA -->|blocks on critical| Models
    Trivy -->|scans image| Docker[Dockerfile]
    Semgrep -->|static analysis| Scanner
```

## Security Design Decisions

- Masking occurs at the database layer to ensure plaintext never reaches persistent storage.
- The `test/` directory intentionally contains dummy secrets (e.g. `AKIAIOSFODNN7EXAMPLE`) for validation — these are fake and safe to commit.
- `.gitignore` excludes runtime artifacts (`*.db`, `*.env`, virtual environment directories) to reduce accidental leakage.

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
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
├── requirements.txt
├── .gitignore
└── README.md
```

## License

MIT
