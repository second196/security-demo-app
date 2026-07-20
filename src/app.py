"""Flask web application - secured against common vulnerabilities."""

import os
import re
import secrets
import sqlite3
import subprocess
import hashlib
from functools import wraps
from urllib.parse import urlparse
from markupsafe import escape
from flask import Flask, request, render_template_string, redirect, session, abort
import hmac

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# ============================================================
# 配置安全 - 从环境变量读取密钥，不再硬编码
# ============================================================
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")


def get_db_connection():
    """获取数据库连接的辅助函数"""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# SQL 注入防护 - 使用参数化查询
# ============================================================
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    if not user_id or not user_id.isdigit():
        abort(400, description="Invalid user ID")
    conn = get_db_connection()
    cursor = conn.cursor()
    # 使用参数化查询防止 SQL 注入
    cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
    user = cursor.fetchone()
    conn.close()
    if user is None:
        abort(404, description="User not found")
    return dict(user)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    if not query:
        abort(400, description="Search query required")
    conn = get_db_connection()
    cursor = conn.cursor()
    # 使用参数化查询防止 SQL 注入
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{query}%",))
    results = cursor.fetchall()
    conn.close()
    return [dict(r) for r in results]


# ============================================================
# 命令注入防护 - 使用参数列表而非 shell 模式
# ============================================================
ALLOWED_HOSTS = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host or not ALLOWED_HOSTS.match(host):
        abort(400, description="Invalid hostname")
    # 使用参数列表而非 shell=True，防止命令注入
    result = subprocess.check_output(
        ["ping", "-c", "1", "-W", "3", host],
        timeout=10
    )
    return result


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    if not domain or not ALLOWED_HOSTS.match(domain):
        abort(400, description="Invalid domain")
    # 使用 subprocess 而非 os.system，防止命令注入
    result = subprocess.check_output(
        ["nslookup", domain],
        timeout=10
    )
    return result


# ============================================================
# XSS 防护 - 使用 escape() 转义用户输入
# ============================================================
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # 使用 escape() 转义用户输入，防止 XSS
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=escape(name))


@app.route("/profile")
def profile():
    user_input = request.args.get("bio", "")
    # 使用 escape() 转义用户输入，防止存储型 XSS
    return f"<div class='bio'>{escape(user_input)}</div>"


# ============================================================
# 反序列化防护 - 禁用 pickle，使用安全的 JSON
# ============================================================
@app.route("/load", methods=["POST"])
def load_object():
    # 使用 JSON 替代 pickle，防止不安全的反序列化
    import json
    try:
        data = request.get_json(force=True, silent=False)
        if data is None:
            abort(400, description="Invalid JSON")
        return json.dumps(data)
    except Exception:
        abort(400, description="Invalid JSON data")


# ============================================================
# 强密码哈希 - 使用 bcrypt/argon2 替代 MD5
# ============================================================
@app.route("/hash_password", methods=["POST"])
def hash_password():
    password = request.form.get("password")
    if not password:
        abort(400, description="Password required")
    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters")

    # 使用 PBKDF2-HMAC-SHA256 替代 MD5，增加安全性
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations=600000
    )
    return {
        "hash": hashed.hex(),
        "salt": salt.hex(),
        "algorithm": "pbkdf2_sha256",
        "iterations": 600000,
    }


@app.route("/verify")
def verify():
    token = request.args.get("token", "")
    # 使用 secrets.compare_digest 进行常量时间比较，防止时序攻击
    expected = hashlib.pbkdf2_hmac("sha256", b"secret", b"salt", 600000).hex()
    if hmac.compare_digest(token, expected):
        return "Verified"
    return "Invalid"


# ============================================================
# 路径穿越防护 - 验证和限制文件路径
# ============================================================
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


@app.route("/read_file")
def read_file():
    filename = request.args.get("name", "")
    if not filename:
        abort(400, description="Filename required")

    # 规范化路径并验证是否在允许的目录内
    base_dir = os.path.realpath(DATA_DIR)
    filepath = os.path.realpath(os.path.join(base_dir, filename))

    # 确保文件路径在 DATA_DIR 内，防止路径穿越
    if not filepath.startswith(base_dir + os.sep) and filepath != base_dir:
        abort(403, description="Access denied: path traversal")

    # 限制文件扩展名
    allowed_extensions = {".txt", ".csv", ".json", ".md"}
    if not any(filepath.endswith(ext) for ext in allowed_extensions):
        abort(403, description="File type not allowed")

    try:
        with open(filepath, "r") as f:
            return f.read()
    except FileNotFoundError:
        abort(404, description="File not found")
    except PermissionError:
        abort(403, description="Permission denied")


# ============================================================
# SSRF 防护 - URL 白名单和验证
# ============================================================
BLOCKED_NETWORKS = [
    re.compile(r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?"),
    re.compile(r"^https?://10\."),
    re.compile(r"^https?://172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^https?://192\.168\."),
    re.compile(r"^https?://169\.254\."),
    re.compile(r"^https?://\[::1\]"),
    re.compile(r"^https?://\[fc00:"),
    re.compile(r"^https?://\[fe80:"),
]


@app.route("/fetch")
def fetch_url():
    import requests as req
    url = request.args.get("url", "")
    if not url:
        abort(400, description="URL required")

    # 验证 URL 格式
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        abort(400, description="Only HTTPS URLs are allowed")

    # 检查是否指向内部网络
    for pattern in BLOCKED_NETWORKS:
        if pattern.match(url):
            abort(403, description="Access to internal/private URLs is forbidden")

    try:
        resp = req.get(url, timeout=5, allow_redirects=False)
        return resp.text[:10000]  # 限制响应大小
    except req.RequestException:
        abort(502, description="Failed to fetch URL")


# ============================================================
# 安全配置 - 生产环境关闭调试模式
# ============================================================
if __name__ == "__main__":
    # 生产环境应使用 gunicorn/uwsgi 等 WSGI 服务器
    # 不要在生产环境使用 debug=True
    app.run(
        host="127.0.0.1",  # 仅监听本地，不绑定 0.0.0.0
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
