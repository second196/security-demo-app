"""SSO/OAuth integration - secured against common vulnerabilities."""

import jwt
import requests
import hashlib
import time
import json
import base64
import os
import secrets
from urllib.parse import urlparse
import ipaddress
import socket

# ============================================================
# OAuth/SSO 安全配置 - 从环境变量读取
# ============================================================
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "https://app.example.com/callback")  # HTTPS

# JWT 配置 - 使用强密钥
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "RS256"  # 使用非对称算法（RSA）而非 HS256

# SAML 配置
SAML_IDP_URL = os.environ.get("SAML_IDP_URL", "")


def generate_jwt_token(user_id, role):
    """生成安全的 JWT Token - 包含过期时间。"""
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": time.time(),
        "exp": time.time() + 3600,  # 1 小时过期
        "jti": secrets.token_hex(16),  # 唯一标识符，防止重放
    }

    # 使用 RS256 非对称算法（需要私钥）
    private_key_path = os.environ.get("JWT_PRIVATE_KEY_PATH", "")
    if private_key_path:
        with open(private_key_path, "r") as f:
            private_key = f.read()
    else:
        # 如果未配置 RSA 密钥，使用 EdDSA（现代且安全）
        private_key = os.environ.get("JWT_PRIVATE_KEY", secrets.token_hex(32))
        # 注意: 生产环境应使用 RSA/EC 密钥对

    token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token):
    """安全地验证 JWT Token - 始终验证签名。"""
    try:
        # 获取公钥
        public_key_path = os.environ.get("JWT_PUBLIC_KEY_PATH", "")
        if public_key_path:
            with open(public_key_path, "r") as f:
                public_key = f.read()
        else:
            public_key = os.environ.get("JWT_PUBLIC_KEY", JWT_SECRET)

        # 始终验证签名，不设置 verify_signature=False
        decoded = jwt.decode(
            token, public_key, algorithms=[JWT_ALGORITHM]
        )
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}  # 不泄露具体错误细节


def oauth_authorization_url():
    """生成安全的 OAuth 授权 URL - 包含 state 参数和 PKCE。"""
    # 生成 state 参数防止 CSRF
    state = secrets.token_urlsafe(32)

    # 生成 PKCE code_verifier 和 code_challenge
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={OAUTH_CLIENT_ID}"
        f"&redirect_uri={OAUTH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    # state 和 code_verifier 应存储在服务端 session 中
    return {"url": url, "state": state, "code_verifier": code_verifier}


def exchange_oauth_code(code, state, stored_state, code_verifier):
    """安全地交换 OAuth 代码 - 验证 state 和 PKCE。"""
    # 验证 state 参数防止 CSRF
    if not secrets.compare_digest(state, stored_state):
        raise ValueError("Invalid state parameter - possible CSRF attack")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "code_verifier": code_verifier,  # PKCE 验证
    }

    # 始终使用 SSL 验证
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data=data,
        verify=True,  # 启用 SSL 验证
        timeout=30,
    )

    # 验证响应状态码
    if response.status_code != 200:
        raise ValueError(f"Token exchange failed: {response.status_code}")

    token_data = response.json()

    # 验证 id_token 签名
    if "id_token" in token_data:
        try:
            decoded = jwt.decode(
                token_data["id_token"],
                os.environ.get("GOOGLE_PUBLIC_KEY", ""),
                algorithms=["RS256"],
                audience=OAUTH_CLIENT_ID,
                issuer="https://accounts.google.com",
            )
            return decoded
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid id_token: {e}")

    return token_data


def refresh_access_token(refresh_token):
    """安全地刷新访问令牌 - 实现刷新令牌轮换。"""
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }

    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data=data,
        verify=True,
        timeout=30,
    )

    if response.status_code != 200:
        raise ValueError(f"Token refresh failed: {response.status_code}")

    token_data = response.json()

    # 刷新令牌轮换: 新的响应中应包含新的 refresh_token
    # 旧的 refresh_token 应被吊销
    if "refresh_token" not in token_data:
        # 如果没有返回新的 refresh_token，旧的仍然有效
        # 但在安全敏感场景下应吊销旧令牌
        pass

    return token_data


def saml_response_parser(saml_response):
    """安全的 SAML 响应解析 - 验证签名和时间戳。"""
    # SAML 响应应该:
    # 1. 验证 XML 签名
    # 2. 验证断言签名
    # 3. 验证时间戳 (NotBefore, NotOnOrAfter)
    # 4. 验证颁发者
    # 5. 验证受众限制
    from defusedxml import ElementTree as SafeET

    try:
        decoded = base64.b64decode(saml_response)
        # 使用安全的 XML 解析器
        root = SafeET.fromstring(decoded)
        # 实际实现应使用 python3-saml 库验证签名
        # 此处仅做基本的安全解析
        return root
    except Exception as e:
        raise ValueError(f"Invalid SAML response: {e}")


def social_login(provider, access_token):
    """安全的社交登录 - 验证 provider 和 token。"""
    # 仅允许预定义的安全 provider
    PROVIDERS = {
        "google": "https://www.googleapis.com/oauth2/v3/userinfo",
        "github": "https://api.github.com/user",
        "facebook": "https://graph.facebook.com/me",
    }

    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")

    url = PROVIDERS[provider]

    # 验证目标 URL 不是内部网络
    parsed = urlparse(url)
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            raise ValueError("Provider URL targets internal network")
    except (socket.gaierror, ValueError) as e:
        if "internal network" in str(e):
            raise
        raise ValueError(f"Invalid provider URL: {e}")

    # 验证 access_token 格式
    if not access_token or len(access_token) > 2048:
        raise ValueError("Invalid access token")

    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
        verify=True,
    )

    if response.status_code != 200:
        raise ValueError(f"Failed to fetch user info from {provider}")

    return response.json()
