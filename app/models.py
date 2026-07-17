import sqlite3
from typing import Dict, List, Optional

DB_PATH = "secrets_audit.db"


def get_db_connection() -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    # Enable row factory to access columns by name (e.g., row['file_path'])
    conn.row_factory = sqlite3.Row
    return conn

def mask_secret(secret_text: str) -> str:
    """Masks a secret string so plaintext credentials are never logged or stored.
    
    Examples:
        "AKIAIOSFODNN7EXAMPLE" -> "AKIA************"
        "short"                -> "sh***"
    """
    if not secret_text:
        return ""
    
    # Clean whitespace or surrounding quotes captured by regex
    clean_text = secret_text.strip("'\" \t\n\r")
    text_length = len(clean_text)
    
    # Dynamic masking based on length
    if text_length <= 4:
        return "*" * text_length
    elif text_length <= 8:
        return f"{clean_text[:2]}***"
    else:
        # Keep the first 4 characters (e.g., 'AKIA') and mask the rest
        return f"{clean_text[:4]}{'*' * (text_length - 4)}"


def create_table() -> None:
    """Initializes the database schema and sets up the timestamp trigger."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Create findings table with explicit business constraints
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS secret_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                secret_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in-progress', 'resolved', 'risk-accepted')),
                notes TEXT DEFAULT NULL,
                matched_text TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """
        )

        # Create trigger to automatically track the updated_at timestamp
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS update_secret_findings_timestamp 
            AFTER UPDATE ON secret_findings
            BEGIN
                UPDATE secret_findings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        """
        )
        conn.commit()


def insert_finding(
    file_path: str, line_number: int, secret_type: str, severity: str, matched_text: str
) -> int:
    """Inserts a newly discovered secret vulnerability into the database.

    Returns the auto-generated ID of the new record.
    """
    query = """
        INSERT INTO secret_findings (file_path, line_number, secret_type, severity, matched_text)
        VALUES (?, ?, ?, ?, ?)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            query, (file_path, line_number, secret_type, severity, matched_text)
        )
        conn.commit()
        return cursor.lastrowid


def list_findings(status: Optional[str] = None) -> List[Dict]:
    """Retrieves finding records from the database.

    Optionally filters records by status (e.g., 'open', 'resolved').
    """
    query = "SELECT * FROM secret_findings"
    params = []

    if status:
        query += " WHERE status = ?"
        params.append(status)

    query += " ORDER BY id DESC"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        # Convert sqlite3.Row objects into standard Python dictionaries
        return [dict(row) for row in cursor.fetchall()]


def update_status(finding_id: int, status: str, notes: Optional[str] = None) -> bool:
    """Updates the status and updates/appends reviewer notes for a specific finding."""
    query = "UPDATE secret_findings SET status = ?"
    params = [status]

    if notes is not None:
        query += ", notes = ?"
        params.append(notes)

    query += " WHERE id = ?"
    params.append(finding_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor.rowcount > 0


def get_summary_report() -> Dict[str, Dict[str, int]]:
    """Generates a quantitative breakdown of secrets grouped by Severity and Status.

    Returns:
        {
            "severity_counts": {"Critical": 1, "High": 5, "Medium": 2, "Low": 0},
            "status_counts": {"open": 6, "in-progress": 2, "resolved": 0, "risk-accepted": 0}
        }
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Aggregate counts grouped by severity
        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM secret_findings GROUP BY severity"
        )
        severity_data = cursor.fetchall()

        # Aggregate counts grouped by lifecycle status
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM secret_findings GROUP BY status"
        )
        status_data = cursor.fetchall()

    return {
        "severity_counts": {row["severity"]: row["count"] for row in severity_data},
        "status_counts": {row["status"]: row["count"] for row in status_data},
    }


# --- Example Local Testing Harness ---
if __name__ == "__main__":
    import json

    print("Initializing Database...")
    create_table()

    # 1. Test record insertion
    print("\nInserting sample secrets...")
    new_id_1 = insert_finding(
        file_path="src/auth.py",
        line_number=12,
        secret_type="AWS Access Key",
        severity="High",
        matched_text="AKIAIOSFODNN7EXAMPLE",
    )
    new_id_2 = insert_finding(
        file_path="config/db.json",
        line_number=45,
        secret_type="Connection String",
        severity="Critical",
        matched_text="postgres://admin:password@localhost:5432",
    )

    # 2. Test status and audit notes update
    print(f"\nTriage action: Updating finding ID {new_id_1} to 'in-progress'...")
    update_status(
        finding_id=new_id_1,
        status="in-progress",
        notes="Contacting dev ops team to cycle this key.",
    )

    # 3. Test listing records with filtering
    print("\nListing all 'in-progress' findings:")
    in_progress_findings = list_findings(status="in-progress")
    print(json.dumps(in_progress_findings, indent=2, default=str))

    # 4. View aggregated dashboard metrics
    print("\nGenerating final metrics report summary:")
    report = get_summary_report()
    print(json.dumps(report, indent=2))