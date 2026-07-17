import typer
from app.scanner import load_secret_patterns, scan_text_block
from app.models import create_table, insert_finding, list_findings, update_status, get_summary_report

app = typer.Typer()

@app.command()
def scan(directory: str):
    """Scan a directory for secrets and store findings in the DB."""
    create_table()
    patterns = load_secret_patterns()
    # Walk through files, read each one, call scan_text_block with file_path
    # For each finding, call insert_finding
    # Print summary of how many findings were stored

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
