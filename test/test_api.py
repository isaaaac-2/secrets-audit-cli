import os

# Database configuration
DB_HOST = "localhost"
DB_PASSWORD = "superSecret123!"
CONNECTION_STRING = "postgres://admin:password@db.example.com:5432/production"

# AWS credentials (DO NOT use in production)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API tokens
STRIPE_API_KEY = "sk_live_abc123def456ghi789jkl012mno345"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

# Private key example
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4yplmMFRjHkRlWmSYfLkYxDPkVhNjSbYKGZ8HtFJMaVLGMoLfYHn
-----END RSA PRIVATE KEY-----"""

def connect_to_database():
    password = "hardcoded_password_123"
    api_key = os.getenv("API_KEY", "fallback_key_should_not_be_here")
    return f"Connected with {password}"
