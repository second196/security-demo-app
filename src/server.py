"""Server with additional vulnerabilities."""

import os
import subprocess
import json
import yaml
import xml.etree.ElementTree as ET
from xml.sax import make_parser

# ============================================================
# Additional hardcoded secrets
# ============================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
DATABASE_URL = "postgres://admin:Password123!@db.internal:5432/production"
JWT_SECRET = "super_secret_jwt_key_do_not_share"
ENCRYPTION_KEY = "aes-256-key-0123456789abcdef"
OAUTH_CLIENT_SECRET = "oauth_secret_abc123def456ghi789"

# ============================================================
# More SAST vulnerabilities
# ============================================================

def xml_parsing_vulnerability(xml_data):
    """XML External Entity (XXE) vulnerability."""
    # XXE: parsing XML without disabling external entities
    parser = make_parser()
    parser.parse(xml_data)


def yaml_load_vulnerability(yaml_data):
    """YAML deserialization vulnerability."""
    # Unsafe YAML loading (can execute arbitrary Python code)
    data = yaml.load(yaml_data)
    return data


def eval_vulnerability(user_input):
    """Arbitrary code execution via eval."""
    # Arbitrary code execution
    result = eval(user_input)
    return result


def exec_vulnerability(user_input):
    """Arbitrary code execution via exec."""
    # Arbitrary code execution
    exec(user_input)


def format_string_vulnerability(template, user_input):
    """Format string vulnerability."""
    # User input directly in format string
    return template.format(user_input)


def insecure_random():
    """Use of insecure random number generator."""
    import random
    # Using predictable random for security-sensitive operation
    token = random.randint(100000, 999999)
    return token


def hardcoded_ip():
    """Hardcoded internal IP address."""
    internal_db = "192.168.1.100"
    internal_cache = "10.0.0.50"
    return internal_db, internal_cache


# ============================================================
# Insecure HTTP requests
# ============================================================
def fetch_resource(url):
    """Make HTTP request without SSL verification."""
    import requests
    # Disabling SSL verification
    response = requests.get(url, verify=False)
    return response.json()


def send_webhook(data):
    """Send data to webhook."""
    import requests
    # Sending sensitive data over HTTP
    requests.post(SLACK_WEBHOOK, json=data)


# ============================================================
# Debug information leak
# ============================================================
DEBUG_MODE = True
VERBOSE_LOGGING = True
LOG_LEVEL = "DEBUG"
STACK_TRACE_ENABLED = True
