"""
安全漏洞演示代码 - 包含常见安全问题
⚠️ 此文件仅用于安全培训和测试，切勿在生产环境中使用！
"""

import os
import re
import pickle
import hashlib
import subprocess
import sqlite3
import random
import string
import json
import yaml
import base64
import xml.etree.ElementTree as ET
import threading
import tempfile
import struct
import socket
import time
import secrets
from functools import wraps
from flask import Flask, request, render_template_string, redirect, session, jsonify
import requests

app = Flask(__name__)
app.secret_key = "super_secret_key_12345"  # 🔴 硬编码密钥

# ============================================================
# 🔴 硬编码凭证 (Hardcoded Secrets)
# ============================================================
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin:Password123!"
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456"
SENDGRID_API_KEY = "SG.abcd1234.efgh5678ijkl9012mnopqrstuvwx"
JWT_SECRET = "super_secret_jwt_key_do_not_share"
OAUTH_CLIENT_SECRET = "oauth_secret_abc123def456ghi789"


# ============================================================
# 🔴 SQL 注入 (SQL Injection)
# ============================================================
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 🔴 字符串拼接导致 SQL 注入
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route("/search")
def search():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 🔴 f-string 导致 SQL 注入
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    return str(results)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 🔴 SQL 注入 - 认证绕过
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return "Login success"
    return "Login failed"


# ============================================================
# 🔴 命令注入 (Command Injection)
# ============================================================
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # 🔴 shell=True 允许命令注入: ; rm -rf /
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    # 🔴 os.system 命令注入
    os.system(f"nslookup {domain}")
    return "Done"


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # 🔴 直接执行用户输入的命令
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return output.stdout


# ============================================================
# 🔴 跨站脚本攻击 (XSS)
# ============================================================
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # 🔴 用户输入直接插入模板，可执行任意 JS
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/profile")
def profile():
    bio = request.args.get("bio")
    # 🔴 存储型 XSS
    return f"<div class='bio'>{bio}</div>"


@app.route("/comment")
def comment():
    text = request.args.get("text")
    # 🔴 反射型 XSS
    return f"<div>{text}</div>"


# ============================================================
# 🔴 不安全的反序列化 (Insecure Deserialization)
# ============================================================
@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    # 🔴 pickle 反序列化可执行任意代码
    obj = pickle.loads(data)
    return str(obj)


@app.route("/import", methods=["POST"])
def import_data():
    data = request.get_json()
    # 🔴 yaml.load 可执行任意 Python 代码
    config = yaml.load(json.dumps(data), Loader=yaml.FullLoader)
    return jsonify(config)


# ============================================================
# 🔴 弱密码哈希 (Weak Cryptography)
# ============================================================
@app.route("/hash_password", methods=["POST"])
def hash_password():
    password = request.form.get("password")
    # 🔴 MD5 无盐值，极易被彩虹表破解
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


@app.route("/hash_password_sha1", methods=["POST"])
def hash_password_sha1():
    password = request.form.get("password")
    # 🔴 SHA1 也不安全
    hashed = hashlib.sha1(password.encode()).hexdigest()
    return hashed


@app.route("/verify_token")
def verify_token():
    token = request.args.get("token")
    # 🔴 弱哈希验证
    expected = hashlib.md5(b"secret").hexdigest()
    if token == expected:
        return "Verified"
    return "Invalid"


# ============================================================
# 🔴 路径穿越 (Path Traversal)
# ============================================================
@app.route("/read_file")
def read_file():
    filename = request.args.get("name")
    # 🔴 无路径验证，可读取任意文件: ../../etc/passwd
    with open(f"/app/data/{filename}", "r") as f:
        return f.read()


@app.route("/download")
def download():
    filename = request.args.get("file")
    # 🔴 路径穿越
    filepath = os.path.join("/uploads", filename)
    with open(filepath, "rb") as f:
        return f.read()


# ============================================================
# 🔴 服务端请求伪造 (SSRF)
# ============================================================
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    # 🔴 可访问内部服务: http://169.254.169.254/latest/meta-data/
    resp = requests.get(url)
    return resp.text


@app.route("/preview")
def preview():
    url = request.args.get("url")
    # 🔴 SSRF - 获取内部元数据
    try:
        resp = requests.get(url, timeout=5)
        return resp.text[:1000]
    except:
        return "Error"


@app.route("/webhook")
def webhook_test():
    url = request.args.get("url")
    # 🔴 SSRF - 探测内部网络
    requests.post(url, json={"test": True})
    return "Sent"


# ============================================================
# 🔴 开放重定向 (Open Redirect)
# ============================================================
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url")
    # 🔴 无验证重定向目标
    return redirect(url)


@app.route("/login_redirect")
def login_redirect():
    next_url = request.args.get("next")
    # 🔴 登录后重定向到任意 URL
    if next_url:
        return redirect(next_url)
    return "Welcome"


# ============================================================
# 🔴 XML 外部实体注入 (XXE)
# ============================================================
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()
    # 🔴 解析 XML 时未禁用外部实体
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_data)
    return ET.tostring(root, encoding="unicode")


@app.route("/xml")
def xml_import():
    xml_file = request.args.get("file")
    # 🔴 XXE - 读取任意文件
    tree = ET.parse(xml_file)
    return ET.tostring(tree.getroot(), encoding="unicode")


# ============================================================
# 🔴 eval/exec 代码执行
# ============================================================
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    # 🔴 eval 可执行任意 Python 代码
    result = eval(expression)
    return str(result)


@app.route("/execute")
def execute():
    code = request.args.get("code")
    # 🔴 exec 可执行任意代码
    exec(code)
    return "Executed"


@app.route("/template")
def template_render():
    user_input = request.args.get("input")
    # 🔴 服务端模板注入 (SSTI)
    return render_template_string(user_input)


# ============================================================
# 🔴 不安全的随机数 (Insecure Random)
# ============================================================
@app.route("/generate_token")
def generate_token():
    # 🔴 使用伪随机数生成安全令牌
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return token


@app.route("/generate_otp")
def generate_otp():
    # 🔴 可预测的 OTP
    otp = random.randint(100000, 999999)
    return str(otp)


@app.route("/session_id")
def session_id():
    # 🔴 可预测的会话 ID
    session_id = ''.join(random.choices(string.hexdigits, k=64))
    return session_id


# ============================================================
# 🔴 竞态条件 (Race Condition)
# ============================================================
account_balance = {}
BALANCE_LOCK = threading.Lock()

@app.route("/transfer")
def transfer():
    from_user = request.args.get("from")
    to_user = request.args.get("to")
    amount = float(request.args.get("amount", 0))

    # 🔴 竞态条件 - 检查和更新不是原子操作
    if account_balance.get(from_user, 0) >= amount:
        time.sleep(0.1)  # 模拟处理延迟，放大竞态窗口
        account_balance[from_user] = account_balance.get(from_user, 0) - amount
        account_balance[to_user] = account_balance.get(to_user, 0) + amount
        return "Transfer success"
    return "Insufficient funds"


# ============================================================
# 🔴 IDOR (不安全的直接对象引用)
# ============================================================
@app.route("/api/user/<int:user_id>")
def get_user_profile(user_id):
    # 🔴 无授权检查，任何用户可访问其他用户数据
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route("/api/order/<int:order_id>")
def get_order(order_id):
    # 🔴 无归属检查
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    order = cursor.fetchone()
    conn.close()
    return str(order)


# ============================================================
# 🔴 敏感信息泄露 (Information Disclosure)
# ============================================================
@app.route("/debug")
def debug_info():
    # 🔴 泄露环境变量
    return jsonify({
        "env": dict(os.environ),
        "secret_key": app.secret_key,
        "aws_key": AWS_ACCESS_KEY,
    })


@app.route("/error")
def error_page():
    # 🔴 泄露堆栈跟踪
    try:
        1 / 0
    except Exception as e:
        import traceback
        return traceback.format_exc()


@app.route("/config")
def show_config():
    # 🔴 泄露配置信息
    return jsonify({
        "database": DATABASE_PASSWORD,
        "stripe": STRIPE_API_KEY,
        "github": GITHUB_TOKEN,
    })


# ============================================================
# 🔴 CSRF (跨站请求伪造)
# ============================================================
@app.route("/change_email", methods=["POST"])
def change_email():
    # 🔴 无 CSRF Token 验证
    new_email = request.form.get("email")
    # 更新邮箱...
    return f"Email changed to {new_email}"


@app.route("/delete_account", methods=["POST"])
def delete_account():
    # 🔴 无 CSRF 防护
    user_id = request.form.get("user_id")
    # 删除账户...
    return "Account deleted"


# ============================================================
# 🔴 不安全的密码重置
# ============================================================
@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    # 🔴 可枚举用户是否存在
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    user = cursor.fetchone()
    conn.close()

    if user:
        # 🔴 重置令牌无过期时间
        reset_token = ''.join(random.choices(string.ascii_letters, k=32))
        # 🔴 使用 HTTP 而非 HTTPS
        reset_link = f"http://app.example.com/reset?token={reset_token}"
        return f"Reset link: {reset_link}"
    return "Email not found"  # 🔴 泄露用户是否存在


# ============================================================
# 🔴 不安全的文件上传
# ============================================================
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if file:
        # 🔴 无文件类型验证
        # 🔴 无文件大小限制
        # 🔴 未清理文件名
        filename = file.filename
        # 🔴 可覆盖系统文件
        file.save(f"/uploads/{filename}")
        return "Uploaded"
    return "No file"


# ============================================================
# 🔴 LDAP 注入
# ============================================================
def ldap_search(username):
    import ldap
    # 🔴 用户输入直接拼接到 LDAP 查询
    search_filter = f"(uid={username})"
    results = ldap.initialize("ldap://ldap.example.com").search_s(
        "dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter
    )
    return results


# ============================================================
# 🔴 XPath 注入
# ============================================================
@app.route("/xpath")
def xpath_query():
    user_input = request.args.get("name")
    tree = ET.parse("users.xml")
    root = tree.getroot()
    # 🔴 XPath 注入
    query = f"//user[name='{user_input}']"
    results = root.findall(query)
    return str(results)


# ============================================================
# 🔴 正则表达式 DoS (ReDoS)
# ============================================================
@app.route("/validate_email")
def validate_email():
    email = request.args.get("email")
    # 🔴 恶意正则导致回溯爆炸
    pattern = r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z0-9]+)*$"
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# ============================================================
# 🔴 不安全的依赖和配置
# ============================================================
@app.route("/health")
def health_check():
    # 🔴 生产环境暴露调试端点
    return jsonify({
        "status": "ok",
        "debug": True,
        "version": "1.0.0",
        "database": DATABASE_PASSWORD,  # 🔴 泄露数据库密码
    })


# ============================================================
# 🔴 JWT 安全问题
# ============================================================
import jwt as pyjwt

@app.route("/jwt/create", methods=["POST"])
def create_jwt():
    data = request.get_json()
    # 🔴 无过期时间
    # 🔴 使用弱密钥
    token = pyjwt.encode(data, "secret", algorithm="HS256")
    return token


@app.route("/jwt/verify")
def verify_jwt():
    token = request.args.get("token")
    try:
        # 🔴 不验证签名
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        return jsonify(decoded)
    except:
        return "Invalid token"


# ============================================================
# 🔴 缓冲区溢出模拟
# ============================================================
def process_data(data):
    buffer = bytearray(256)
    # 🔴 无边界检查
    for i, byte in enumerate(data):
        buffer[i] = byte  # 可能溢出
    return bytes(buffer)


# ============================================================
# 🔴 不安全的临时文件
# ============================================================
def create_temp_file(data):
    # 🔴 可预测的临时文件名
    temp_path = f"/tmp/temp_{os.getpid()}.dat"
    with open(temp_path, 'w') as f:
        f.write(data)
    # 🔴 文件权限过于宽松
    os.chmod(temp_path, 0o777)
    return temp_path


# ============================================================
# 🔴 SSRF - 读取云元数据
# ============================================================
@app.route("/cloud_metadata")
def cloud_metadata():
    # 🔴 读取 AWS EC2 元数据
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    try:
        resp = requests.get(metadata_url, timeout=2)
        return resp.text
    except:
        return "Error"


# ============================================================
# 🔴 服务端模板注入 (SSTI) - Jinja2
# ============================================================
@app.route("/render")
def render():
    template = request.args.get("template")
    # 🔴 Jinja2 SSTI - 可执行任意代码
    from jinja2 import Environment
    env = Environment()
    tmpl = env.from_string(template)
    return tmpl.render()


# ============================================================
# 🔴 不安全的 CORS 配置
# ============================================================
@app.after_request
def add_cors_headers(response):
    # 🔴 允许所有来源
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    return response


# ============================================================
# 🔴 调试模式启用
# ============================================================
if __name__ == "__main__":
    # 🔴 生产环境使用 debug=True
    # 🔴 绑定到 0.0.0.0
    app.run(host="0.0.0.0", port=5000, debug=True)
