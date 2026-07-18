"""Database migration scripts with security vulnerabilities."""

import sqlite3
import os
import json

# ============================================================
# 数据库迁移安全问题
# ============================================================

# 1. 迁移脚本中硬编码凭证
DB_HOST = "db.internal.company.com"
DB_PORT = 5432
DB_USER = "migration_admin"
DB_PASSWORD = "MigrationPass123!"
DB_NAME = "production"

# 2. 使用 root 权限执行迁移
# 3. 无事务回滚机制
# 4. 无迁移版本控制


def migrate_v1():
    """第一次迁移 - 创建用户表"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # 5. 无 SQL 参数化
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            ssn TEXT,
            credit_card TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 6. 迁移脚本中插入测试数据包含真实密码
    test_users = [
        ("admin", "admin@company.com", "admin123", "admin", "123-45-6789", "4111111111111111"),
        ("test_user", "test@company.com", "password123", "user", "987-65-4321", "5500000000000004"),
    ]

    for user in test_users:
        # 7. 明文密码插入数据库
        cursor.execute(
            f"INSERT INTO users (username, email, password_hash, role, ssn, credit_card) "
            f"VALUES ('{user[0]}', '{user[1]}', '{user[2]}', '{user[3]}', '{user[4]}', '{user[5]}')"
        )

    conn.commit()
    conn.close()


def migrate_v2():
    """第二次迁移 - 添加订单表"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            status TEXT,
            payment_method TEXT,
            card_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 8. 硬编码的测试订单包含真实卡号
    test_orders = [
        (1, 99.99, "completed", "credit_card", "4111111111111111"),
        (2, 149.50, "pending", "credit_card", "5500000000000004"),
    ]

    for order in test_orders:
        cursor.execute(
            f"INSERT INTO orders (user_id, amount, status, payment_method, card_number) "
            f"VALUES ({order[0]}, {order[1]}, '{order[2]}', '{order[3]}', '{order[4]}')"
        )

    conn.commit()
    conn.close()


def migrate_v3():
    """第三次迁移 - 添加审计日志表"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # 9. 审计日志表存储敏感操作但无访问控制
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            api_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 10. 插入包含 API 密钥的审计日志
    audit_entries = [
        (1, "login", "Successful login", "192.168.1.100", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        (1, "api_call", "Called /api/users", "192.168.1.100", "ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456"),
    ]

    for entry in audit_entries:
        cursor.execute(
            f"INSERT INTO audit_log (user_id, action, details, ip_address, api_key) "
            f"VALUES ({entry[0]}, '{entry[1]}', '{entry[2]}', '{entry[3]}', '{entry[4]}')"
        )

    conn.commit()
    conn.close()


def rollback_v3():
    """回滚脚本 - 但无验证"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 11. 无确认机制，直接删除表
    cursor.execute("DROP TABLE IF EXISTS audit_log")
    conn.commit()
    conn.close()


def run_all_migrations():
    """运行所有迁移"""
    print("Running migrations...")
    migrate_v1()
    migrate_v2()
    migrate_v3()
    print("All migrations completed.")


if __name__ == "__main__":
    # 12. 无环境检查，可直接在生产环境运行
    run_all_migrations()
