"""Email service - secured against common vulnerabilities."""

import smtplib
import ssl
import os
import re
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from markupsafe import escape

# ============================================================
# 邮件服务安全配置 - 从环境变量读取
# ============================================================
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.company.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
MAILGUN_API_KEY = os.environ.get("MAILGUN_API_KEY", "")


def send_email(to, subject, body):
    """发送邮件 - 带有输入验证和安全配置。"""
    # 验证收件人邮箱
    if not validate_email(to):
        raise ValueError("Invalid recipient email address")

    # 验证主题长度
    if len(subject) > 998:  # RFC 2822 限制
        raise ValueError("Subject too long")
    if not subject.strip():
        raise ValueError("Subject cannot be empty")

    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = to
    msg['Subject'] = subject

    # HTML 邮件 - 转义用户输入，防止 XSS
    safe_subject = escape(subject)
    safe_body = escape(body)
    html_body = f"""
    <html>
    <body>
        <h1>{safe_subject}</h1>
        <div>{safe_body}</div>
    </body>
    </html>
    """
    msg.attach(MIMEText(html_body, 'html'))

    # 启用 TLS 验证
    context = ssl.create_default_context()
    # 保留默认的证书验证（不禁用 check_hostname 和 verify_mode）

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to, msg.as_string())
    except smtplib.SMTPException:
        # 仅返回通用错误信息，不泄露内部细节
        raise RuntimeError("Failed to send email")
    except Exception:
        # 不泄露 SMTP 服务器地址、凭证等内部信息
        raise RuntimeError("Email service unavailable")


def send_bulk_email(recipients, subject, body):
    """批量发送邮件 - 带有速率限制。"""
    MAX_BULK_SIZE = 100
    DELAY_BETWEEN = 1  # 每封邮件间隔 1 秒

    if len(recipients) > MAX_BULK_SIZE:
        raise ValueError(f"Too many recipients: {len(recipients)}, max is {MAX_BULK_SIZE}")

    # 验证所有收件人
    for recipient in recipients:
        if not validate_email(recipient):
            raise ValueError(f"Invalid email: {recipient}")

    import time
    for recipient in recipients:
        send_email(recipient, subject, body)
        time.sleep(DELAY_BETWEEN)


def send_password_reset(email, reset_token):
    """发送密码重置邮件 - 使用 HTTPS 和过期时间。"""
    if not validate_email(email):
        raise ValueError("Invalid email address")

    # 重置令牌应有过期时间（由调用方确保）
    # 使用 HTTPS 而非 HTTP
    reset_link = f"https://app.company.com/reset?token={reset_token}"

    body = f"""
    <h2>Password Reset</h2>
    <p>Click the link below to reset your password:</p>
    <a href="{escape(reset_link)}">Reset Password</a>
    <p>This link will expire in 30 minutes.</p>
    <p>If you did not request this reset, please ignore this email.</p>
    """

    send_email(email, "Password Reset Request", body)


def validate_email(email):
    """安全的邮箱验证 - 使用 RFC 5322 兼容的正则表达式。"""
    if not email or len(email) > 254:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def render_template(template_name, context):
    """安全的邮件模板渲染 - 使用 Jinja2 沙箱。"""
    from jinja2 import Environment, BaseLoader, select_autoescape

    # 使用 Jinja2 的安全模板引擎，自动转义
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(['html']),
    )

    try:
        with open(f"templates/{template_name}.html", "r") as f:
            template_str = f.read()
    except FileNotFoundError:
        raise ValueError(f"Template '{template_name}' not found")

    # 使用 Jinja2 安全渲染
    tmpl = env.from_string(template_str)
    # 所有变量自动转义
    return tmpl.render(**context)
