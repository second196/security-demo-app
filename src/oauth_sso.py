"""SSO/OAuth integration with security vulnerabilities."""

import jwt
import requests
import hashlib
import time
import json
import base64
import os

# ============================================================
# OAuth/SSO 安全问题
# ============================================================

# 1. OAuth 客户端密钥硬编码
OAUTH_CLIENT_ID = "client_id_abc123"
OAUTH_CLIENT_SECRET = "client_secret_xyz789"
OAUTH_REDIRECT_URI = "http://localhost:3000/callback"  # 2. HTTP 而非 HTTPS

# 2. JWT 密钥硬编码
JWT_SECRET = "super_secret_jwt_key_12345"
JWT_ALGORITHM = "HS256"  # 3. 使用对称算法而非非对称算法

# 4. SAML 配置问题
SAML_IDP_URL = "https://idp.company.com/saml/sso"
SAML_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+abc...  # 5. 证书未验证
-----END CERTIFICATE-----"""


def generate_jwt_token(user_id, role):
    """生成 JWT Token - 多个安全问题"""
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": time.time(),
        # 6. 无过期时间
        # "exp": time.time() + 3600,
    }

    # 7. 使用弱密钥
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token):
    """验证 JWT Token - 无签名验证"""
    try:
        # 8. 无签名验证，直接解码
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        # 9. 错误信息泄露
        return {"error": f"Token verification failed: {str(e)}"}


def oauth_authorization_url():
    """生成 OAuth 授权 URL - 无 state 参数"""
    # 10. 无 state 参数 - CSRF 攻击
    # 11. 无 PKCE (Proof Key for Code Exchange)
    url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={OAUTH_CLIENT_ID}"
        f"&redirect_uri={OAUTH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid email profile"
        # 缺少 state 参数
    )
    return url


def exchange_oauth_code(code):
    """交换 OAuth 代码 - 无验证"""
    # 12. 无重放攻击保护
    # 13. 无 token 类型验证
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }

    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data=data,
        verify=False  # 14. 禁用 SSL 验证
    )

    # 15. 无响应状态码检查
    token_data = response.json()

    # 16. 未验证 id_token 的签名
    if "id_token" in token_data:
        decoded = jwt.decode(
            token_data["id_token"],
            options={"verify_signature": False}  # 17. 不验证签名
        )
        return decoded

    return token_data


def refresh_access_token(refresh_token):
    """刷新访问令牌 - 无刷新令牌轮换"""
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }

    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data=data
    )

    # 18. 不轮换刷新令牌 - 旧令牌仍有效
    return response.json()


def saml_response_parser(saml_response):
    """SAML 响应解析 - 无签名验证"""
    # 19. 不验证 SAML 响应签名
    # 20. 不验证断言签名
    # 21. 不验证时间戳
    decoded = base64.b64decode(saml_response)
    # 直接解析 XML 无验证
    return decoded


def social_login(provider, access_token):
    """社交登录 - 无 provider 验证"""
    # 22. 不验证 access_token 的颁发者
    # 23. 允许任意 provider
    providers = {
        "google": "https://www.googleapis.com/oauth2/v3/userinfo",
        "github": "https://api.github.com/user",
        "facebook": "https://graph.facebook.com/me",
    }

    # 24. 无 token 绑定验证 (Token Binding)
    url = providers.get(provider)
    if url:
        response = requests.get(url, headers={
            "Authorization": f"Bearer {access_token}"
        })
        return response.json()

    return None
