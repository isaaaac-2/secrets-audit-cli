import json
import pathlib
import re


def load_secret_patterns(filename="secret_patterns.json"):
    
    # Resolve absolute path to ensure it finds the file in the same directory
    file_path = pathlib.Path(__file__).parent / "secret-patterns.json"

    if not file_path.exists():
        raise FileNotFoundError(
            f"Required configuration file missing: {file_path}"
        )

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Pre-compile the regex strings into pattern objects for performance
    compiled_patterns = {}
    for secret_type, config in data.items():
        compiled_patterns[secret_type] = {
            "regex": re.compile(config["regex"]),
            "severity": config["severity"],
        }
    return compiled_patterns

def mask_secret(text):
    if len(text) <= 4:
        return "***"
    return text[:4] + "***"

def scan_text_block(text_to_scan, compiled_patterns, file_path="unknown"):
    findings = []

    # Enumerate line-by-line starting at line 1
    for line_number, line in enumerate(text_to_scan.splitlines(), start=1):
        for secret_type, config in compiled_patterns.items():

            # Search the individual line
            match = config["regex"].search(line)
            if match:
                findings.append(
                    {
                        "line_number": line_number,
                        "secret_type": secret_type,
                        "severity": config["severity"],
                        "matched_text": mask_secret(match.group(0).strip()),
                        "file_path": file_path,
                    }
                )

    return findings


# --- Example Execution ---
if __name__ == "__main__":
    # Sample multi-line code block simulating a file read
    code_sample = """import os

def connect_services():
    # Setup database connection string
    db_conn = "postgres://admin:superSecret123@localhost:5432/db"
    
    # Initialize AWS client
    aws_id = "AKIAIOSFODNN7EXAMPLE"
    
    # Setup legacy application tokens
    api_token = "1a2b3c4d5e6f7g8h9i0jK_example_token_value"
    
    print("Connecting...")
"""

    try:
        # Load patterns from JSON and compile them
        patterns = load_secret_patterns()

        # Run scanner
        detected_secrets = scan_text_block(code_sample, patterns)

        # Output results nicely formatted
        print(json.dumps(detected_secrets, indent=2))

    except FileNotFoundError as e:
        print(e)
