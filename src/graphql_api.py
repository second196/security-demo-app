"""GraphQL API with security vulnerabilities."""

import graphene
from graphene import ObjectType, String, Int, Field, List, Mutation, Schema
import jwt
import hashlib
import sqlite3
import os

# ============================================================
# GraphQL 安全问题
# ============================================================

# 1. 无查询深度限制 (Query Depth Attack)
# 攻击者可以构造嵌套极深的查询导致 DoS

# 2. 无查询复杂度限制 (Query Complexity Attack)
# 攻击者可以用单个查询消耗大量资源

# 3. 无速率限制
# 无限次调用 API

# 4. Introspection 启用（生产环境应禁用）
# 攻击者可以枚举整个 schema

# 5. 无认证/授权检查
# 任何查询都可以访问所有数据


class User(ObjectType):
    id = Int()
    username = String()
    email = String()
    password_hash = String()  # 6. 密码哈希暴露在 GraphQL schema 中
    role = String()
    ssn = String()  # 7. 敏感字段暴露
    credit_card = String()  # 8. 支付信息暴露


class Order(ObjectType):
    id = Int()
    user_id = Int()
    amount = Float()
    status = String()


class Query(ObjectType):
    """所有查询都无认证检查"""
    user = Field(User, id=Int(required=True))
    users = List(User)
    order = Field(Order, id=Int(required=True))
    orders = List(Order)
    search = String(query=String(required=True))

    # 9. N+1 查询问题
    def resolve_users(self, info):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        # 无分页 - 可返回所有数据导致内存溢出
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        conn.close()
        return [User(id=u[0], username=u[1], email=u[2],
                     password_hash=u[3], role=u[4], ssn=u[5],
                     credit_card=u[6]) for u in users]

    def resolve_user(self, info, id):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        # 10. SQL 注入
        cursor.execute(f"SELECT * FROM users WHERE id = {id}")
        user = cursor.fetchone()
        conn.close()
        if user:
            return User(id=user[0], username=user[1], email=user[2],
                       password_hash=user[3], role=user[4], ssn=user[5],
                       credit_card=user[6])
        return None

    def resolve_search(self, info, query):
        # 11. GraphQL 注入
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%'")
        results = cursor.fetchall()
        conn.close()
        return str(results)


class CreateUser(Mutation):
    """创建用户 - 无输入验证"""
    class Arguments:
        username = String(required=True)
        email = String(required=True)
        password = String(required=True)

    user = Field(User)

    def mutate(self, info, username, email, password):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        # 12. 无密码强度验证
        # 13. 无邮箱格式验证
        # 14. SQL 注入
        password_hash = hashlib.md5(password.encode()).hexdigest()
        cursor.execute(
            f"INSERT INTO users (username, email, password_hash) "
            f"VALUES ('{username}', '{email}', '{password_hash}')"
        )
        conn.commit()
        conn.close()
        return CreateUser(user=User(username=username, email=email))


class DeleteUser(Mutation):
    """删除用户 - 无授权检查"""
    class Arguments:
        id = Int(required=True)

    success = Boolean()

    def mutate(self, info, id):
        # 15. 任何用户都可以删除任何其他用户
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM users WHERE id = {id}")
        conn.commit()
        conn.close()
        return DeleteUser(success=True)


class Mutation(ObjectType):
    create_user = CreateUser.Field()
    delete_user = DeleteUser.Field()


schema = Schema(query=Query, mutation=Mutation)

# 16. Schema 导出/打印暴露所有类型
# print_schema(schema)  # 不应在生产环境启用
