"""Test file with additional vulnerabilities."""

import subprocess
import os
import json

# ============================================================
# More hardcoded secrets in test files
# ============================================================
TEST_API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
TEST_DATABASE_URL = "postgres://testuser:testpass@localhost:5432/testdb"
TEST_JWT_SECRET = "test_jwt_secret_12345"


def test_database_connection():
    """Test with hardcoded credentials."""
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        database="testdb",
        user="testuser",
        password="testpass123"  # Hardcoded password
    )
    return conn


def test_api_call():
    """Test API with hardcoded key."""
    import requests
    headers = {
        "Authorization": f"Bearer {TEST_API_KEY}",
        "Content-Type": "application/json"
    }
    # Disabling SSL verification in tests
    response = requests.get("https://api.example.com/test", headers=headers, verify=False)
    return response.json()


def test_command_execution():
    """Test with subprocess."""
    # Unsafe subprocess call
    result = subprocess.check_output("echo 'test'", shell=True)
    return result


def test_file_operations():
    """Test file operations."""
    # Writing test data to world-readable file
    test_data = {"key": "value", "secret": TEST_API_KEY}
    with open("/tmp/test_config.json", "w") as f:
        json.dump(test_data, f)
    os.chmod("/tmp/test_config.json", 0o777)  # World-readable
