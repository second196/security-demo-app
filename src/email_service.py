"""Email service with security vulnerabilities."""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import re

# ============================================================
# 邮件服务安全问题
# ============================================================

# 1. 邮件服务凭证硬编码
SMTP_HOST = "smtp.company.com"
SMTP_PORT = 587
SMTP_USER = "noreply@company.com"
SMTP_PASSWORD = "EmailPass123!"
SENDGRID_API_KEY = "SG.abcd1234.efgh5678ijkl9012mnopqrstuvwx"
MAILGUN_API_KEY = "key-abc123def456ghi789"


def send_email(to, subject, body):
    """发送邮件 - 无输入验证"""
    # 2. 无收件人验证
    # 3. 无主题长度限制
    # 4. 无内容清理

    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = to  # 5. 可伪造发件人
    msg['Subject'] = subject

    # 6. HTML 邮件 XSS
    html_body = f"""
    <html>
    <body>
        <h1>{subject}</h1>
        <div>{body}</div>
        <!-- 7. 内嵌跟踪像素 -->
        <img src="https://track.company.com/open?user={to}" width="1" height="1" />
    </body>
    </html>
    """
    msg.attach(MIMEText(html_body, 'html'))

    # 8. 无 TLS 验证
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # 9. 禁用证书验证

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to, msg.as_string())
    except Exception as e:
        # 10. 错误信息泄露内部细节
        print(f"Failed to send email: {str(e)}")
        print(f"SMTP server: {SMTP_HOST}:{SMTP_PORT}")
        print(f"Credentials: {SMTP_USER}:{SMTP_PASSWORD}")


def send_bulk_email(recipients, subject, body):
    """批量发送邮件 - 无速率限制"""
    # 11. 无速率限制 - 可被滥用发送垃圾邮件
    # 12. 无退订链接检查
    # 13. 无 SPF/DKIM/DMARC 配置
    for recipient in recipients:
        send_email(recipient, subject, body)


def send_password_reset(email, reset_token):
    """发送密码重置邮件"""
    # 14. 重置令牌无过期时间
    # 15. 重置链接使用 HTTP 而非 HTTPS
    reset_link = f"http://app.company.com/reset?token={reset_token}&email={email}"

    body = f"""
    <h2>Password Reset</h2>
    <p>Click the link below to reset your password:</p>
    <a href="{reset_link}">Reset Password</a>
    <p>This link will never expire.</p>  <!-- 16. 无过期时间 -->
    """

    send_email(email, "Password Reset Request", body)


def validate_email(email):
    """邮箱验证 - 使用弱正则表达式"""
    # 17. 弱邮箱验证
    pattern = r".+@.+"  # 太宽松
    return re.match(pattern, email) is not None


# 18. 邮件模板注入
def render_template(template_name, context):
    """渲染邮件模板 - 无沙箱"""
    # 直接使用 f-string 拼接，无模板引擎沙箱
    with open(f"templates/{template_name}.html", "r") as f:
        template = f.read()

    # 用户输入直接插入模板
    for key, value in context.items():
        template = template.replace(f"{{{{{key}}}}}", value)

    return template
