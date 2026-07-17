import sqlite3
from typing import Dict, List, Optional

DB_PATH = "secrets_audit.db"


def _mask_secret(secret_text: str) -> str:
    """Internal helper to obfuscate plaintext credentials before database insertion.

    Keeps the first 4 characters (e.g., 'AKIA') to help identify the key type,
    then replaces the remaining text with asterisks.
    """
    if not secret_text:
        return ""

    # Clean whitespace or quotes captured by the scanner regex
    clean_text = secret_text.strip("'\" \t\n\r")
    text_length = len(clean_text)

    if text_length <= 4:
        return "*" * text_length
    elif text_length <= 8:
        return f"{clean_text[:2]}***"
    else:
        return f"{clean_text[:4]}{'*' * (text_length - 4)}"


def get_db_connection() -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_table() -> None:
    """Initializes the database schema and sets up the timestamp trigger."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

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

    Automatically masks the 'matched_text' to prevent plaintext exposure in logs or files.
    """
    # ENFORCE MASKING HERE: The database layer sanitizes the text automatically
    safe_masked_text = _mask_secret(matched_text)

    query = """
        INSERT INTO secret_findings (file_path, line_number, secret_type, severity, matched_text)
        VALUES (?, ?, ?, ?, ?)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            query, (file_path, line_number, secret_type, severity, safe_masked_text)
        )
        conn.commit()
        return cursor.lastrowid


def list_findings(status: Optional[str] = None) -> List[Dict]:
    """Retrieves finding records from the database."""
    query = "SELECT * FROM secret_findings"
    params = []

    if status:
        query += " WHERE status = ?"
        params.append(status)

    query += " ORDER BY id DESC"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
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
    """Generates a quantitative breakdown of secrets grouped by Severity and Status."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM secret_findings GROUP BY severity"
        )
        severity_data = cursor.fetchall()

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

    # Test raw string inputs to prove the model masks them internally
    print("\nInserting sample secrets (Passing raw data directly)...")
    new_id = insert_finding(
        file_path="src/auth.py",
        line_number=12,
        secret_type="AWS Access Key",
        severity="High",
        matched_text="AKIAIOSFODNN7EXAMPLE",  # Safe to pass raw string now!
    )

    print("\nListing findings to verify database state:")
    db_records = list_findings()
    print(json.dumps(db_records, indent=2, default=str))
