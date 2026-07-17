"""Simple Flask web application with intentional security vulnerabilities for demo purposes."""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)
app.secret_key = "super_secret_key_12345"  # Hardcoded secret

# ============================================================
# Hardcoded credentials (Secret Leak)
# ============================================================
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin:Password123!"
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456"
SENDGRID_API_KEY = "SG.abcd1234.efgh5678ijkl9012mnopqrstuvwx"


# ============================================================
# SQL Injection vulnerabilities (SAST - Source Code)
# ============================================================
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: string formatting in query
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route("/search")
def search():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: f-string in query
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    return str(results)


# ============================================================
# Command Injection vulnerability (SAST)
# ============================================================
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command Injection: unsanitized user input in subprocess
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    # Command Injection via os.system
    os.system(f"nslookup {domain}")
    return "Done"


# ============================================================
# Cross-Site Scripting (XSS) vulnerability (SAST)
# ============================================================
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # XSS: user input directly in template
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/profile")
def profile():
    user_input = request.args.get("bio")
    # Stored XSS potential
    return f"<div class='bio'>{user_input}</div>"


# ============================================================
# Insecure Deserialization (SAST)
# ============================================================
@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    # Insecure deserialization: pickle from user input
    obj = pickle.loads(data)
    return str(obj)


# ============================================================
# Weak Cryptography (SAST)
# ============================================================
@app.route("/hash_password", methods=["POST"])
def hash_password():
    password = request.form.get("password")
    # Weak hashing: MD5 without salt
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


@app.route("/verify")
def verify():
    token = request.args.get("token")
    # Weak comparison
    expected = hashlib.md5(b"secret").hexdigest()
    if token == expected:
        return "Verified"
    return "Invalid"


# ============================================================
# Path Traversal (SAST)
# ============================================================
@app.route("/read_file")
def read_file():
    filename = request.args.get("name")
    # Path Traversal: no sanitization
    with open(f"/app/data/{filename}", "r") as f:
        return f.read()


# ============================================================
# SSRF vulnerability (SAST)
# ============================================================
@app.route("/fetch")
def fetch_url():
    import requests
    url = request.args.get("url")
    # SSRF: fetch arbitrary URLs
    resp = requests.get(url)
    return resp.text


# ============================================================
# Debug mode enabled (Configuration Issue)
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
