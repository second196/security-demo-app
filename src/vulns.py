"""Additional source code with more security vulnerabilities."""

import os
import re
import subprocess
import tempfile
import sqlite3
import base64
import struct
import socket
import threading
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCServer

# ============================================================
# Regex Denial of Service (ReDoS)
# ============================================================
def redos_vulnerability(user_input):
    """Catastrophic backtracking in regex."""
    # Evil regex pattern vulnerable to ReDoS
    pattern = r"(a+)+b"
    match = re.match(pattern, user_input)
    return match


def email_validation_redos(email):
    """Another ReDoS pattern."""
    # Vulnerable regex for email validation
    pattern = r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z0-9]+)*$"
    return re.match(pattern, email)


# ============================================================
# XML-RPC vulnerabilities
# ============================================================
def xmlrpc_server():
    """XML-RPC server with no authentication."""
    server = SimpleXMLRPCServer(("0.0.0.0", 8000))
    # No authentication, no rate limiting
    server.register_function(os.system, "execute")
    server.register_function(eval, "evaluate")
    server.serve_forever()


def xmlrpc_client_call(url, command):
    """XML-RPC client - SSRF potential."""
    proxy = xmlrpc.client.ServerProxy(url)
    # SSRF: calling arbitrary XML-RPC endpoints
    return proxy.execute(command)


# ============================================================
# Integer overflow / buffer overflow simulation
# ============================================================
def process_data(data):
    """Simulated buffer overflow."""
    # No bounds checking
    buffer = bytearray(256)
    for i, byte in enumerate(data):
        buffer[i] = byte  # No length check - overflow possible
    return bytes(buffer)


def parse_header(header_bytes):
    """Unsafe struct unpacking."""
    # Unpacking without validating length
    # If header_bytes is shorter than expected, this crashes
    magic, version, length = struct.unpack("!IHH", header_bytes)
    return magic, version, length


# ============================================================
# Type confusion vulnerabilities
# ============================================================
def type_confusion(value):
    """Type confusion leading to unexpected behavior."""
    if isinstance(value, str):
        return int(value)  # No error handling
    elif isinstance(value, int):
        return str(value)
    # Potential None return on unexpected type


def unsafe_type_cast(data):
    """Unsafe type casting."""
    # Direct casting without validation
    result = bool(data)  # Empty string becomes False, non-empty True
    return result


# ============================================================
# TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
# ============================================================
def toctou_vulnerability(filename):
    """Race condition in file access."""
    # Check if file exists
    if os.path.exists(filename):
        # Another process could delete/replace the file here
        time.sleep(0.1)  # Simulated delay
        # Now open the file
        with open(filename, 'r') as f:
            return f.read()


def toctou_permission_check(username):
    """Race condition in permission check."""
    # Check permission
    if os.access(f"/home/{username}", os.R_OK):
        # Another user could change permissions here
        time.sleep(0.05)
        # Now read the file
        with open(f"/home/{username}/.ssh/authorized_keys", 'r') as f:
            return f.read()


# ============================================================
# Memory leak simulation
# ============================================================
class DataProcessor:
    """Simulated memory leak through global state."""
    _cache = {}

    def process(self, key, data):
        # Memory leak: cache grows unbounded
        self._cache[key] = data  # Never evicted
        return self._cache[key]

    def get_cache_size(self):
        return len(self._cache)


# ============================================================
# Insecure temporary file handling
# ============================================================
def create_temp_file(data):
    """Insecure temporary file creation."""
    # Predictable filename, no mkstemp
    temp_path = f"/tmp/temp_{os.getpid()}.dat"
    with open(temp_path, 'w') as f:
        f.write(data)
    # File permissions not restricted
    return temp_path


def process_upload(file_data):
    """Insecure file upload handling."""
    # No file type validation
    # No file size limit
    # No filename sanitization
    filename = file_data.filename  # Could contain path traversal
    save_path = f"/uploads/{filename}"
    with open(save_path, 'wb') as f:
        f.write(file_data.read())
    return save_path


# ============================================================
# Race condition in authentication
# ============================================================
login_attempts = {}
LOGIN_LOCK = threading.Lock()

def login(username, password):
    """Vulnerable to timing attacks and race conditions."""
    # Race condition: multiple threads can pass the check simultaneously
    if username in login_attempts and login_attempts[username] >= 5:
        return False, "Account locked"

    # No rate limiting in critical section
    if authenticate(username, password):
        login_attempts[username] = 0
        return True, "Success"
    else:
        login_attempts[username] = login_attempts.get(username, 0) + 1
        return False, "Invalid credentials"


def authenticate(username, password):
    """Weak authentication."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Timing attack vulnerability: string comparison
    cursor.execute(f"SELECT password FROM users WHERE username='{username}'")
    result = cursor.fetchone()
    conn.close()
    if result:
        # Constant-time comparison NOT used
        return password == result[0]
    return False


# ============================================================
# Insecure direct object reference (IDOR)
# ============================================================
def get_user_profile(requesting_user_id, target_user_id):
    """IDOR vulnerability - no authorization check."""
    # No check if requesting_user_id has permission to view target_user_id
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={target_user_id}")
    profile = cursor.fetchone()
    conn.close()
    return profile


def update_order(user_id, order_id, new_status):
    """IDOR - users can modify other users' orders."""
    # No check if order belongs to user_id
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE orders SET status='{new_status}' WHERE id={order_id}"
    )
    conn.commit()
    conn.close()


# ============================================================
# Insecure deserialization with jsonpickle
# ============================================================
def load_user_object(data):
    """Insecure deserialization with jsonpickle."""
    import jsonpickle
    # jsonpickle can execute arbitrary code
    obj = jsonpickle.decode(data)
    return obj


# ============================================================
# Prototype pollution simulation (Python equivalent)
# ============================================================
def merge_configs(default, user_input):
    """Unsafe dict merge - prototype pollution equivalent."""
    for key, value in user_input.items():
        if key.startswith('__'):
            # Should block dunder attributes but doesn't properly
            pass
        default[key] = value
    return default


# ============================================================
# LDAP injection
# ============================================================
def ldap_search(username):
    """LDAP injection vulnerability."""
    import ldap
    # No escaping of user input
    search_filter = f"(uid={username})"
    results = ldap.initialize("ldap://ldap.example.com").search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        search_filter
    )
    return results


# ============================================================
# XPath injection
# ============================================================
def xpath_query(user_input):
    """XPath injection vulnerability."""
    import xml.etree.ElementTree as ET
    tree = ET.parse("data.xml")
    root = tree.getroot()
    # XPath injection: user input in XPath expression
    query = f"//user[name='{user_input}']"
    return root.findall(query)


# ============================================================
# Expression Language injection
# ============================================================
def evaluate_expression(expression, user_data):
    """SSTI-like vulnerability."""
    # Dangerous: user-controlled expression evaluation
    from jinja2 import Environment
    env = Environment()
    tmpl = env.from_string(f"Result: {{{{{expression}}}}}")
    return tmpl.render(data=user_data)


# ============================================================
# Path traversal in zip extraction
# ============================================================
def extract_zip(zip_path, extract_to):
    """Zip slip vulnerability."""
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            # No validation of filename - path traversal possible
            target_path = os.path.join(extract_to, info.filename)
            zip_ref.extract(info, extract_to)


# ============================================================
# Server-Side Request Forgery (SSRF) via webhooks
# ============================================================
def register_webhook(webhook_url, user_id):
    """SSRF via webhook registration."""
    import requests
    # No validation of webhook URL - can hit internal services
    requests.post(webhook_url, json={"user_id": user_id})


def test_webhook(url):
    """SSRF via webhook testing."""
    import requests
    # User can specify any URL, including internal network
    response = requests.get(url, timeout=5)
    return response.status_code


# ============================================================
# Open redirect
# ============================================================
def redirect_user(return_url):
    """Open redirect vulnerability."""
    # No validation of return_url
    from flask import redirect
    return redirect(return_url)


# ============================================================
# Mass assignment vulnerability
# ============================================================
def update_user_profile(user_id, form_data):
    """Mass assignment - user can set any field."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # User can add fields like 'is_admin', 'role', etc.
    for key, value in form_data.items():
        cursor.execute(
            f"UPDATE users SET {key}=? WHERE id=?",
            (value, user_id)
        )
    conn.commit()
    conn.close()


# ============================================================
# Insecure randomness for security tokens
# ============================================================
def generate_session_token():
    """Using weak random for session tokens."""
    import random
    import string
    # Not cryptographically secure
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return token


def generate_otp():
    """Using weak random for OTP."""
    import random
    # Predictable OTP
    otp = random.randint(100000, 999999)
    return otp


# ============================================================
# Hardcoded backup credentials
# ============================================================
BACKUP_S3_BUCKET = "s3://backup-bucket-12345"
BACKUP_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
BACKUP_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
BACKUP_SSH_KEY = """
-----BEGIN RSA PRIVATE KEY-----
FAKE_BACKUP_KEY_FOR_DEMO
-----END RSA PRIVATE KEY-----
"""
BACKUP_DB_PASSWORD = "backup_db_pass_456!"
INTERNAL_API_KEY = "internal-api-key-abc123xyz789"
HARDcoded_HMAC_KEY = "hmac_secret_key_for_signing"


# ============================================================
# Insecure file permissions
# ============================================================
def setup_app():
    """Creating files with overly permissive permissions."""
    # World-readable config
    with open("/etc/app/config.yaml", "w") as f:
        f.write(f"db_password: {BACKUP_DB_PASSWORD}\n")

    os.chmod("/etc/app/config.yaml", 0o777)

    # World-writable directory
    os.makedirs("/var/app/uploads", mode=0o777, exist_ok=True)
    os.chmod("/var/app/uploads", 0o777)

    # Executable in shared location
    with open("/usr/local/bin/app-helper.sh", "w") as f:
        f.write("#!/bin/bash\necho 'helper'\n")
    os.chmod("/usr/local/bin/app-helper.sh", 0o777)
