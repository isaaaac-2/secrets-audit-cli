import json
import re


def load_secret_patterns(filepath="secret_patterns.json"):
    with open(filepath, "file_r") as file:
        return json.load(file)


def scan_for_secrets(text_to_scan, patterns):
    findings = {}

    for secret_type, pattern_string in patterns.items():
        # Using re.MULTILINE to catch patterns spanning or starting on new lines
        matches = re.finditer(pattern_string, text_to_scan, re.MULTILINE)

        for match in matches:
            if secret_type not in findings:
                findings[secret_type] = []
            findings[secret_type].append(match.group(0))

    return findings


# Example Usage
patterns = load_secret_patterns()
code_sample = """
    conn = "postgres://admin:superSecret123@localhost:3000/db"
    api_token = "1a2b3c4d5e6f7g8h9i0jK"
"""

detected = scan_for_secrets(code_sample, patterns)
print(json.dumps(detected, indent=2))
