import os
import typer
from app.scanner import load_secret_patterns, scan_text_block
from app.models import create_table, insert_finding, list_findings, update_status, get_summary_report

app = typer.Typer()

@app.command()
def scan(directory: str):
    print(f"Scanning directory: {directory}")
    """Scan a directory for secrets and store findings in the DB."""
    create_table()
    patterns = load_secret_patterns()
    total_findings = 0

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', 'venv', '.git')]

        for filename in files:
            if filename.endswith(('.py', '.js', '.ts', '.json', '.yml', '.yaml', '.env', '.cfg', '.ini', '.toml', '.sh', '.bash')):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    findings = scan_text_block(content, patterns, file_path=filepath)
                    for finding in findings:
                        insert_finding(
                            file_path=finding['file_path'],
                            line_number=finding['line_number'],
                            secret_type=finding['secret_type'],
                            severity=finding['severity'],
                            matched_text=finding['matched_text']
                        )
                        total_findings += 1
                except Exception as e:
                    print(f"Skipping {filepath}: {e}")

    print(f"Scan complete: {total_findings} findings stored.")

@app.command()
def list(status: str = None):
    """List findings, optionally filtered by status."""
    findings = list_findings(status)
    # Pretty print each finding

@app.command()
def resolve(finding_id: int, notes: str = None):
    """Mark a finding as resolved."""
    update_status(finding_id, "resolved", notes)

@app.command()
def report():
    """Show severity and status breakdown."""
    summary = get_summary_report()
    # Pretty print the summary
