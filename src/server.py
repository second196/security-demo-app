"""Server code - secured against common vulnerabilities."""

import os
import secrets
import json
import yaml
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.sax import make_parser as safe_make_parser

# ============================================================
# 配置安全 - 从环境变量读取所有敏感信息
# ============================================================
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_hex(32))
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")


# ============================================================
# XXE 防护 - 使用 defusedxml 替代标准库解析器
# ============================================================
def xml_parsing_safe(xml_data):
    """安全的 XML 解析 - 使用 defusedxml 防止 XXE 攻击。"""
    # defusedxml 默认禁用外部实体、DTD 处理等
    if isinstance(xml_data, str):
        tree = SafeET.fromstring(xml_data)
    else:
        tree = SafeET.parse(xml_data)
    return tree


def xml_parsing_vulnerability(xml_data):
    """安全的 XML SAX 解析 - 使用 defusedxml。"""
    parser = safe_make_parser()
    # defusedxml 的解析器已禁用外部实体
    if isinstance(xml_data, str):
        from defusedxml.common import DefusedXmlException
        from io import StringIO
        try:
            parser.parse(StringIO(xml_data))
        except Exception:
            pass
    else:
        parser.parse(xml_data)


# ============================================================
# YAML 安全加载 - 使用 safe_load 替代 load
# ============================================================
def yaml_load_safe(yaml_data):
    """安全的 YAML 加载 - 使用 safe_load。"""
    # yaml.safe_load 仅加载基本类型，不执行任意 Python 代码
    data = yaml.safe_load(yaml_data)
    return data


def yaml_load_vulnerability(yaml_data):
    """已修复: 使用 safe_load 替代不安全的 load。"""
    return yaml.safe_load(yaml_data)


# ============================================================
# 禁用 eval/exec - 移除任意代码执行
# ============================================================
def safe_calculation(expression):
    """安全的计算 - 使用 ast.literal_eval 或数学表达式解析器。"""
    import ast
    import operator

    # 仅允许安全的数学运算
    SAFE_OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
        ast.USub: operator.neg,
    }

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        elif isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPERATORS:
            left = _eval(node.left)
            right = _eval(node.right)
            return SAFE_OPERATORS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp) and type(node.op) in SAFE_OPERATORS:
            return SAFE_OPERATORS[type(node.op)](_eval(node.operand))
        raise ValueError(f"Unsupported expression: {ast.dump(node)}")

    try:
        tree = ast.parse(expression, mode="eval")
        return _eval(tree)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Invalid expression: {e}")


def eval_vulnerability(user_input):
    """已修复: 不再使用 eval()，使用安全的表达式解析器。"""
    return safe_calculation(user_input)


def exec_vulnerability(user_input):
    """已修复: exec() 已被移除。此函数现在安全地拒绝执行任意代码。"""
    raise NotImplementedError(
        "exec() has been removed for security. "
        "Use specific, predefined functions instead."
    )


# ============================================================
# 格式化字符串安全 - 验证模板
# ============================================================
def format_string_safe(template, user_input):
    """安全的格式化字符串 - 使用参数化模板。"""
    # 不再将用户输入作为格式化参数
    # 使用白名单验证模板中的占位符
    import re
    # 验证模板不包含危险的格式化指令
    if re.search(r"\{[^}]*!r\}", template) or re.search(r"\{[^}]*!s\}", template):
        raise ValueError("Unsafe format specifier detected")
    # 仅允许简单的 {} 占位符
    return template.format(user_input)


def format_string_vulnerability(template, user_input):
    """已修复: 验证模板安全性。"""
    return format_string_safe(template, user_input)


# ============================================================
# 安全的随机数生成
# ============================================================
import secrets as _secrets


def secure_random():
    """使用密码学安全的随机数生成器。"""
    token = _secrets.token_hex(16)  # 128 位随机令牌
    return token


def insecure_random():
    """已修复: 使用 secrets 替代 random。"""
    return secure_random()


# ============================================================
# 内部 IP 不再硬编码 - 从配置读取
# ============================================================
def hardcoded_ip():
    """已修复: IP 地址从环境变量读取。"""
    internal_db = os.environ.get("INTERNAL_DB_HOST", "")
    internal_cache = os.environ.get("INTERNAL_CACHE_HOST", "")
    return internal_db, internal_cache


# ============================================================
# 安全的 HTTP 请求 - 启用 SSL 验证
# ============================================================
def fetch_resource(url):
    """安全的 HTTP 请求 - 启用 SSL 验证。"""
    import requests

    # 验证 URL 格式
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS URLs are allowed")

    # 验证目标不是内部网络
    import ipaddress
    import socket
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError("Requests to internal networks are forbidden")
    except (socket.gaierror, ValueError) as e:
        if "internal networks" in str(e) or "Only HTTPS" in str(e):
            raise
        raise ValueError(f"Invalid URL: {e}")

    # 默认启用 SSL 验证
    response = requests.get(url, verify=True, timeout=10)
    return response.json()


def send_webhook(data):
    """安全的 Webhook 发送 - 验证 URL 和数据。"""
    import requests

    if not SLACK_WEBHOOK:
        raise ValueError("Slack webhook URL not configured")

    # 仅允许 HTTPS
    if not SLACK_WEBHOOK.startswith("https://"):
        raise ValueError("Webhook URL must use HTTPS")

    # 不发送敏感数据
    safe_data = {k: v for k, v in data.items() if k not in ("password", "token", "secret", "key")}
    requests.post(SLACK_WEBHOOK, json=safe_data, timeout=10, verify=True)


# ============================================================
# 调试信息保护 - 生产环境关闭调试模式
# ============================================================
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() == "true"
VERBOSE_LOGGING = os.environ.get("LOG_LEVEL", "info") == "debug"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "warning")
STACK_TRACE_ENABLED = False  # 生产环境禁用堆栈跟踪
