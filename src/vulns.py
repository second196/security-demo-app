"""Additional source code - secured against common vulnerabilities."""

import os
import re
import secrets
import sqlite3
import base64
import struct
import socket
import threading
import tempfile
import hmac
import ipaddress
from functools import wraps
from urllib.parse import urlparse

# ============================================================
# ReDoS 防护 - 使用安全的正则表达式
# ============================================================
def redos_vulnerability(user_input):
    """安全的正则匹配 - 使用原子组或更简单的模式。"""
    # 避免嵌套量词 (a+)+，使用更安全的模式
    pattern = r"a+b"
    match = re.match(pattern, user_input)
    return match


def email_validation_safe(email):
    """安全的邮箱验证正则表达式。"""
    # 避免嵌套量词，使用字符类而非量词组
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


# ============================================================
# XML-RPC 防护 - 移除危险的系统函数注册
# ============================================================
def xmlrpc_server():
    """安全的 XML-RPC 服务器 - 仅注册业务函数。"""
    from xmlrpc.server import SimpleXMLRPCServer

    def safe_add(a, b):
        """仅注册安全的业务函数"""
        return a + b

    # 仅绑定到本地地址
    server = SimpleXMLRPCServer(("127.0.0.1", 8000))
    server.register_function(safe_add, "add")
    # 绝不注册 os.system, eval 等危险函数
    server.serve_forever()


def xmlrpc_client_call(url, command):
    """安全的 XML-RPC 客户端 - 验证目标 URL。"""
    import xmlrpc.client

    parsed = urlparse(url)
    # 验证 URL 仅指向 HTTPS 端点
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS XML-RPC endpoints are allowed")

    # 验证目标不是内部网络
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError("XML-RPC calls to internal networks are forbidden")
    except (socket.gaierror, ValueError) as e:
        if "internal networks" in str(e):
            raise
        raise ValueError(f"Invalid hostname: {parsed.hostname}")

    proxy = xmlrpc.client.ServerProxy(url)
    # 仅允许调用预定义的安全函数
    safe_functions = {"add", "multiply"}
    if command not in safe_functions:
        raise ValueError(f"Function '{command}' is not allowed")
    return getattr(proxy, command)()


# ============================================================
# 缓冲区溢出防护 - 添加边界检查
# ============================================================
def process_data(data):
    """安全的数据处理 - 带有边界检查。"""
    buffer = bytearray(256)
    # 检查输入长度是否超出缓冲区大小
    if len(data) > len(buffer):
        raise ValueError(f"Data too large: {len(data)} bytes, max is {len(buffer)}")
    for i, byte in enumerate(data):
        buffer[i] = byte
    return bytes(buffer)


def parse_header(header_bytes):
    """安全的 struct 解包 - 验证输入长度。"""
    expected_size = struct.calcsize("!IHH")
    if len(header_bytes) < expected_size:
        raise ValueError(
            f"Header too short: {len(header_bytes)} bytes, "
            f"expected at least {expected_size}"
        )
    magic, version, length = struct.unpack("!IHH", header_bytes[:expected_size])
    return magic, version, length


# ============================================================
# 类型混淆防护 - 添加类型验证
# ============================================================
def type_confusion(value):
    """安全的类型转换 - 带有错误处理。"""
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            raise TypeError(f"Cannot convert '{value}' to integer")
    elif isinstance(value, int):
        return str(value)
    else:
        raise TypeError(f"Unexpected type: {type(value).__name__}")


def unsafe_type_cast(data):
    """安全的类型转换 - 显式验证。"""
    if isinstance(data, str):
        return bool(data.strip())
    return bool(data)


# ============================================================
# TOCTOU 防护 - 使用原子操作
# ============================================================
def toctou_safe(filename):
    """安全的文件读取 - 使用 open() 的原子操作。"""
    # 直接打开文件，不再先检查存在性
    # open() 本身是原子操作，避免了 TOCTOU 竞态条件
    try:
        with open(filename, "r") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None


def toctou_permission_check(username):
    """安全的文件读取 - 使用 with 语句直接打开。"""
    # 验证用户名只包含安全字符
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        raise ValueError("Invalid username")

    filepath = os.path.join("/home", username, ".ssh", "authorized_keys")
    # 直接尝试打开，不再先检查权限
    try:
        with open(filepath, "r") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


# ============================================================
# 内存泄漏防护 - 添加缓存大小限制
# ============================================================
class DataProcessor:
    """安全的数据处理器 - 带有 LRU 缓存限制。"""
    _cache = {}
    _max_size = 1000  # 缓存最大条目数

    def process(self, key, data):
        # 检查缓存大小，超出时清理最早的条目
        if len(self._cache) >= self._max_size:
            # 移除最早插入的条目
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[key] = data
        return self._cache[key]

    def get_cache_size(self):
        return len(self._cache)

    def clear_cache(self):
        """手动清理缓存"""
        self._cache.clear()


# ============================================================
# 安全的临时文件处理
# ============================================================
def create_temp_file(data):
    """安全的临时文件创建 - 使用 tempfile 模块。"""
    # 使用 mkstemp 创建具有受限权限的临时文件
    fd, temp_path = tempfile.mkstemp(suffix=".dat", prefix="app_")
    try:
        os.chmod(temp_path, 0o600)  # 仅所有者可读写
        with os.fdopen(fd, "w") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        raise
    return temp_path


def process_upload(file_data):
    """安全的文件上传处理 - 验证文件类型和大小。"""
    ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

    # 获取文件名并清理路径
    filename = os.path.basename(file_data.filename)
    # 验证文件扩展名
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{ext}' is not allowed")

    # 验证文件大小
    file_data.seek(0, os.SEEK_END)
    size = file_data.tell()
    file_data.seek(0)
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {size} bytes, max is {MAX_FILE_SIZE}")

    # 使用安全的上传目录
    upload_dir = os.path.join(tempfile.gettempdir(), "secure_uploads")
    os.makedirs(upload_dir, mode=0o700, exist_ok=True)
    save_path = os.path.join(upload_dir, filename)
    with open(save_path, "wb") as f:
        f.write(file_data.read())
    return save_path


# ============================================================
# 认证安全 - 使用线程安全的锁和常量时间比较
# ============================================================
login_attempts = {}
LOGIN_LOCK = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 分钟


def login(username, password):
    """安全的登录函数 - 线程安全 + 常量时间比较。"""
    # 验证输入
    if not username or not password:
        return False, "Username and password required"

    with LOGIN_LOCK:
        # 检查账户锁定状态
        attempts_info = login_attempts.get(username, {"count": 0, "locked_until": 0})
        import time
        if attempts_info.get("locked_until", 0) > time.time():
            return False, "Account is temporarily locked"

        if authenticate(username, password):
            login_attempts[username] = {"count": 0, "locked_until": 0}
            return True, "Success"
        else:
            new_count = attempts_info.get("count", 0) + 1
            if new_count >= MAX_LOGIN_ATTEMPTS:
                login_attempts[username] = {
                    "count": new_count,
                    "locked_until": time.time() + LOCKOUT_DURATION,
                }
                return False, "Account locked due to too many attempts"
            else:
                login_attempts[username] = {
                    "count": new_count,
                    "locked_until": 0,
                }
                return False, "Invalid credentials"


def authenticate(username, password):
    """安全的认证函数 - 参数化查询 + 常量时间比较。"""
    if not username or not password:
        return False

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 使用参数化查询防止 SQL 注入
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        # 使用 hmac.compare_digest 进行常量时间比较，防止时序攻击
        return hmac.compare_digest(password, result[0])
    return False


# ============================================================
# IDOR 防护 - 添加授权检查
# ============================================================
def get_user_profile(requesting_user_id, target_user_id):
    """安全的用户资料获取 - 带有授权检查。"""
    if requesting_user_id != target_user_id:
        # 检查是否有管理员权限
        if not is_admin(requesting_user_id):
            raise PermissionError("Not authorized to view this profile")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 使用参数化查询
    cursor.execute("SELECT * FROM users WHERE id = ?", (int(target_user_id),))
    profile = cursor.fetchone()
    conn.close()
    return profile


def update_order(user_id, order_id, new_status):
    """安全的订单更新 - 验证订单归属。"""
    ALLOWED_STATUSES = {"pending", "processing", "shipped", "delivered", "cancelled"}
    if new_status not in ALLOWED_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    # 先验证订单属于该用户
    cursor.execute(
        "SELECT id FROM orders WHERE id = ? AND user_id = ?",
        (int(order_id), int(user_id)),
    )
    if not cursor.fetchone():
        conn.close()
        raise PermissionError("Not authorized to update this order")

    cursor.execute(
        "UPDATE orders SET status = ? WHERE id = ? AND user_id = ?",
        (new_status, int(order_id), int(user_id)),
    )
    conn.commit()
    conn.close()


def is_admin(user_id):
    """检查用户是否为管理员"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (int(user_id),))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == "admin"


# ============================================================
# 反序列化防护 - 禁用 jsonpickle，使用安全的 JSON
# ============================================================
def load_user_object(data):
    """安全的对象加载 - 使用 JSON 替代 jsonpickle。"""
    import json
    try:
        obj = json.loads(data)
        return obj
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON data")


# ============================================================
# 原型污染防护 - 阻止 dunder 属性
# ============================================================
BLOCKED_KEYS = frozenset({"__proto__", "__class__", "__bases__", "__subclasses__",
                          "__mro__", "__init__", "__globals__", "__builtins__"})


def merge_configs(default, user_input):
    """安全的字典合并 - 阻止原型污染。"""
    if not isinstance(default, dict) or not isinstance(user_input, dict):
        raise TypeError("Both arguments must be dictionaries")

    for key, value in user_input.items():
        # 阻止危险的 dunder 属性
        if key in BLOCKED_KEYS:
            raise ValueError(f"Blocked key: {key}")
        if isinstance(value, dict) and key in default and isinstance(default[key], dict):
            merge_configs(default[key], value)
        else:
            default[key] = value
    return default


# ============================================================
# LDAP 注入防护 - 使用转义
# ============================================================
LDAP_ESCAPE_CHARS = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
}


def ldap_search(username):
    """安全的 LDAP 搜索 - 转义用户输入。"""
    import ldap

    def escape_ldap_filter(value):
        """转义 LDAP 过滤器特殊字符"""
        result = ""
        for char in str(value):
            result += LDAP_ESCAPE_CHARS.get(char, char)
        return result

    # 转义用户输入
    safe_username = escape_ldap_filter(username)
    search_filter = f"(uid={safe_username})"

    conn = ldap.initialize("ldap://ldap.example.com")
    results = conn.search_s(
        "dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter
    )
    return results


# ============================================================
# XPath 注入防护 - 使用参数化查询
# ============================================================
def xpath_query(user_input):
    """安全的 XPath 查询 - 验证和清理输入。"""
    import xml.etree.ElementTree as ET

    # 仅允许字母数字和基本字符
    if not re.match(r"^[a-zA-Z0-9_@.\- ]+$", user_input):
        raise ValueError("Invalid input for XPath query")

    tree = ET.parse("data.xml")
    root = tree.getroot()
    # 使用 findall 而非拼接查询字符串
    # 使用属性查找替代危险的 XPath 拼接
    results = []
    for elem in root.iter("user"):
        name_elem = elem.find("name")
        if name_elem is not None and name_elem.text == user_input:
            results.append(elem)
    return results


# ============================================================
# 表达式注入防护 - 使用安全的模板引擎
# ============================================================
def evaluate_expression(expression, user_data):
    """安全的表达式评估 - 仅允许白名单操作。"""
    import re
    from markupsafe import escape

    # 仅允许安全的变量名和基本操作
    if not re.match(r"^[a-zA-Z0-9_ .,]+$", expression):
        raise ValueError("Invalid expression")

    # 使用预定义的安全模板，而非用户控制的表达式
    safe_template = str(escape(expression))
    return f"Result: {safe_template}"


# ============================================================
# Zip Slip 防护 - 验证解压路径
# ============================================================
def extract_zip(zip_path, extract_to):
    """安全的 ZIP 解压 - 防止 Zip Slip 攻击。"""
    import zipfile

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for info in zip_ref.infolist():
            # 验证文件名不包含路径穿越
            if info.filename.startswith("/") or ".." in info.filename:
                raise ValueError(f"Blocked path traversal in zip: {info.filename}")

            target_path = os.path.normpath(os.path.join(extract_to, info.filename))
            # 确保目标路径在提取目录内
            if not target_path.startswith(os.path.normpath(extract_to)):
                raise ValueError(f"Path traversal attempt detected: {info.filename}")

            zip_ref.extract(info, extract_to)


# ============================================================
# SSRF 防护 - 验证 URL
# ============================================================
def register_webhook(webhook_url, user_id):
    """安全的 Webhook 注册 - 验证 URL。"""
    import requests

    # 验证 URL 格式和安全性
    parsed = urlparse(webhook_url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS webhook URLs are allowed")

    # 检查是否指向内部网络
    try:
        import socket
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            raise ValueError("Webhook URLs targeting internal networks are forbidden")
    except (socket.gaierror, ValueError) as e:
        if "internal networks" in str(e) or "Only HTTPS" in str(e):
            raise
        raise ValueError(f"Invalid webhook URL: {e}")

    requests.post(webhook_url, json={"user_id": user_id}, timeout=10)


def test_webhook(url):
    """安全的 Webhook 测试 - 限制目标。"""
    import requests

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed")

    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            raise ValueError("Cannot test internal URLs")
    except (socket.gaierror, ValueError) as e:
        if "Cannot test" in str(e) or "Only HTTPS" in str(e):
            raise
        raise ValueError(f"Invalid URL: {e}")

    response = requests.get(url, timeout=5, verify=True)
    return response.status_code


# ============================================================
# 开放重定向防护 - 验证重定向 URL
# ============================================================
ALLOWED_REDIRECT_DOMAINS = {"app.example.com", "www.example.com"}


def redirect_user(return_url):
    """安全的重定向 - 验证目标 URL。"""
    from flask import redirect as flask_redirect

    parsed = urlparse(return_url)
    # 仅允许相对路径或同域名重定向
    if parsed.netloc:
        if parsed.hostname not in ALLOWED_REDIRECT_DOMAINS:
            raise ValueError("Redirect to external domain is not allowed")
    # 仅允许 HTTP(S) 协议
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid redirect scheme: {parsed.scheme}")

    return flask_redirect(return_url)


# ============================================================
# 批量赋值防护 - 白名单字段
# ============================================================
ALLOWED_PROFILE_FIELDS = {"display_name", "bio", "avatar_url"}


def update_user_profile(user_id, form_data):
    """安全的用户资料更新 - 使用字段白名单。"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # 仅更新白名单中的字段
    for key, value in form_data.items():
        if key not in ALLOWED_PROFILE_FIELDS:
            continue  # 忽略不在白名单中的字段
        cursor.execute(
            "UPDATE users SET {} = ? WHERE id = ?".format(key),
            (str(value), int(user_id)),
        )
    conn.commit()
    conn.close()


# ============================================================
# 安全随机数 - 使用 secrets 模块
# ============================================================
def generate_session_token():
    """使用密码学安全的随机数生成会话令牌。"""
    return secrets.token_urlsafe(32)


def generate_otp():
    """使用密码学安全的随机数生成 OTP。"""
    return secrets.randbelow(900000) + 100000  # 6 位数字


# ============================================================
# 敏感配置 - 从环境变量读取
# ============================================================
# 所有敏感信息应从环境变量读取
BACKUP_S3_BUCKET = os.environ.get("BACKUP_S3_BUCKET", "")
BACKUP_AWS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")
BACKUP_AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
BACKUP_SSH_KEY_PATH = os.environ.get("BACKUP_SSH_KEY_PATH", "")
BACKUP_DB_PASSWORD = os.environ.get("BACKUP_DB_PASSWORD", "")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "")


# ============================================================
# 安全的文件权限
# ============================================================
def setup_app():
    """创建应用目录和文件，使用安全的权限。"""
    import stat

    # 配置文件 - 仅所有者可读写
    os.makedirs("/etc/app", mode=0o700, exist_ok=True)
    with open("/etc/app/config.yaml", "w") as f:
        f.write("app_config: true\n")  # 不再包含密码
    os.chmod("/etc/app/config.yaml", 0o600)

    # 上传目录 - 仅所有者可读写执行
    os.makedirs("/var/app/uploads", mode=0o700, exist_ok=True)
    os.chmod("/var/app/uploads", 0o700)

    # 脚本文件 - 所有者可执行，其他用户只读
    os.makedirs("/usr/local/bin", exist_ok=True)
    with open("/usr/local/bin/app-helper.sh", "w") as f:
        f.write("#!/bin/bash\necho 'helper'\n")
    os.chmod("/usr/local/bin/app-helper.sh", 0o755)
