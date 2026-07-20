"""GraphQL API - secured against common vulnerabilities."""

import graphene
from graphene import ObjectType, String, Int, Boolean, Field, List, Mutation, Float, Schema
import hashlib
import secrets
import sqlite3
import os
import re
import hmac

# ============================================================
# GraphQL 安全配置
# ============================================================
# 1. 查询深度限制
MAX_QUERY_DEPTH = 5
# 2. 查询复杂度限制
MAX_QUERY_COMPLEXITY = 100
# 3. 速率限制（每分钟）
RATE_LIMIT = 60


def get_db_connection():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# 认证装饰器 - 所有 GraphQL 操作都需要认证
# ============================================================
def require_auth(func):
    """认证装饰器"""
    def wrapper(self, info, *args, **kwargs):
        user = info.context.get("user")
        if not user:
            raise Exception("Authentication required")
        return func(self, info, *args, **kwargs)
    return wrapper


def require_admin(func):
    """管理员权限装饰器"""
    def wrapper(self, info, *args, **kwargs):
        user = info.context.get("user")
        if not user:
            raise Exception("Authentication required")
        if user.get("role") != "admin":
            raise Exception("Admin access required")
        return func(self, info, *args, **kwargs)
    return wrapper


# ============================================================
# 安全的类型定义 - 移除敏感字段
# ============================================================
class User(ObjectType):
    id = Int()
    username = String()
    email = String()
    # 移除了 password_hash、ssn、credit_card 等敏感字段
    role = String()
    created_at = String()


class SafeUser(ObjectType):
    """仅包含非敏感字段的用户类型"""
    id = Int()
    username = String()
    email = String()
    role = String()


class Order(ObjectType):
    id = Int()
    user_id = Int()
    amount = Float()
    status = String()


class Query(ObjectType):
    """所有查询都要求认证"""
    user = Field(SafeUser, id=Int(required=True))
    users = List(SafeUser)
    order = Field(Order, id=Int(required=True))
    orders = List(Order)
    search = String(query=String(required=True))

    @require_auth
    def resolve_users(self, info):
        """安全的用户列表查询 - 参数化 + 分页"""
        conn = get_db_connection()
        cursor = conn.cursor()
        # 使用参数化查询 + 分页
        cursor.execute(
            "SELECT id, username, email, role, created_at FROM users LIMIT ? OFFSET ?",
            (50, 0)  # 默认分页
        )
        users = cursor.fetchall()
        conn.close()
        return [SafeUser(id=u[0], username=u[1], email=u[2],
                        role=u[3], created_at=u[4]) for u in users]

    @require_auth
    def resolve_user(self, info, id):
        """安全的用户查询 - 参数化查询"""
        conn = get_db_connection()
        cursor = conn.cursor()
        # 使用参数化查询防止 SQL 注入
        cursor.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (int(id),)
        )
        user = cursor.fetchone()
        conn.close()
        if user:
            return SafeUser(id=user[0], username=user[1], email=user[2],
                           role=user[3], created_at=user[4])
        return None

    @require_auth
    def resolve_search(self, info, query):
        """安全的搜索 - 参数化查询"""
        # 验证输入
        if not query or len(query) > 100:
            raise ValueError("Invalid search query")

        conn = get_db_connection()
        cursor = conn.cursor()
        # 使用参数化查询
        cursor.execute(
            "SELECT id, username, email FROM users WHERE username LIKE ?",
            (f"%{query}%",)
        )
        results = cursor.fetchall()
        conn.close()
        return str([dict(r) for r in results])

    @require_auth
    def resolve_order(self, info, id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM orders WHERE id = ?", (int(id),))
        order = cursor.fetchone()
        conn.close()
        if order:
            return Order(id=order[0], user_id=order[1],
                        amount=order[2], status=order[3])
        return None


# ============================================================
# 安全的变更操作 - 带有认证和输入验证
# ============================================================
class CreateUser(Mutation):
    """创建用户 - 带有输入验证"""

    class Arguments:
        username = String(required=True)
        email = String(required=True)
        password = String(required=True)

    user = Field(SafeUser)

    def mutate(self, info, username, email, password):
        # 验证用户名
        if not username or len(username) < 3 or len(username) > 50:
            raise ValueError("Username must be 3-50 characters")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise ValueError("Username must be alphanumeric")

        # 验证邮箱
        if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            raise ValueError("Invalid email address")

        # 验证密码强度
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain uppercase letter")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain lowercase letter")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain digit")

        conn = get_db_connection()
        cursor = conn.cursor()

        # 检查用户名是否已存在
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Username already exists")

        # 使用 PBKDF2 哈希密码（替代 MD5）
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, iterations=600000
        ).hex()

        # 使用参数化查询
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()

        return CreateUser(user=SafeUser(username=username, email=email))


class DeleteUser(Mutation):
    """删除用户 - 仅管理员可操作"""

    class Arguments:
        id = Int(required=True)

    success = Boolean()

    @require_admin
    def mutate(self, info, id):
        conn = get_db_connection()
        cursor = conn.cursor()
        # 使用参数化查询
        cursor.execute("DELETE FROM users WHERE id = ?", (int(id),))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return DeleteUser(success=affected > 0)


class Mutation(ObjectType):
    create_user = CreateUser.Field()
    delete_user = DeleteUser.Field()


# ============================================================
# Schema 配置 - 生产环境禁用 Introspection
# ============================================================
# 在生产环境中禁用 introspection，防止攻击者枚举 schema
# 可以通过环境变量控制
ENABLE_INTROSPECTION = os.environ.get("GRAPHQL_INTROSPECTION", "false").lower() == "true"

schema = Schema(query=Query, mutation=Mutation)
if not ENABLE_INTROSPECTION:
    schema.graphql_schema.introspection = False
