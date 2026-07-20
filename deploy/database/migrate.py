"""Database migration scripts - secured against common vulnerabilities."""

import sqlite3
import os
import json
import secrets
import hashlib

# ============================================================
# 数据库迁移安全配置
# ============================================================
# 从环境变量读取数据库凭证
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "app")

# 迁移版本控制
MIGRATION_VERSION = 3


def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


def create_migration_table(conn):
    """创建迁移版本跟踪表"""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            checksum TEXT
        )
    """)
    conn.commit()


def check_migration_version(conn, target_version):
    """检查是否可以执行迁移"""
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(version) FROM schema_migrations")
    result = cursor.fetchone()
    current_version = result[0] or 0

    if current_version >= target_version:
        return False  # 已迁移
    return True


def record_migration(conn, version, checksum):
    """记录迁移版本"""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO schema_migrations (version, checksum) VALUES (?, ?)",
        (version, checksum)
    )
    conn.commit()


def migrate_v1():
    """第一次迁移 - 创建用户表"""
    conn = get_db_connection()
    create_migration_table(conn)

    if not check_migration_version(conn, 1):
        print("Migration v1 already applied, skipping")
        conn.close()
        return

    cursor = conn.cursor()

    # 使用参数化查询创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 安全地插入测试用户 - 使用强密码哈希
    test_users = [
        ("admin", "admin@example.com", "Admin@123456"),
        ("test_user", "test@example.com", "Test@123456"),
    ]

    for username, email, password in test_users:
        # 使用 PBKDF2 哈希密码
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, iterations=600000
        ).hex()

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, salt.hex())
        )

    # 记录迁移
    checksum = hashlib.sha256(b"v1-users-table").hexdigest()
    record_migration(conn, 1, checksum)

    conn.commit()
    conn.close()
    print("Migration v1 completed")


def migrate_v2():
    """第二次迁移 - 添加订单表"""
    conn = get_db_connection()
    create_migration_table(conn)

    if not check_migration_version(conn, 2):
        print("Migration v2 already applied, skipping")
        conn.close()
        return

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL CHECK(amount >= 0),
            status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
            payment_method TEXT NOT NULL,
            card_last_four TEXT,  # 仅存储卡号后四位
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # 安全地插入测试订单 - 不存储完整卡号
    test_orders = [
        (1, 99.99, "completed", "credit_card", "1111"),
        (2, 149.50, "pending", "credit_card", "0004"),
    ]

    for user_id, amount, status, payment_method, card_last_four in test_orders:
        cursor.execute(
            "INSERT INTO orders (user_id, amount, status, payment_method, card_last_four) VALUES (?, ?, ?, ?, ?)",
            (user_id, amount, status, payment_method, card_last_four)
        )

    checksum = hashlib.sha256(b"v2-orders-table").hexdigest()
    record_migration(conn, 2, checksum)

    conn.commit()
    conn.close()
    print("Migration v2 completed")


def migrate_v3():
    """第三次迁移 - 添加审计日志表"""
    conn = get_db_connection()
    create_migration_table(conn)

    if not check_migration_version(conn, 3):
        print("Migration v3 already applied, skipping")
        conn.close()
        return

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # 审计日志中不存储 API 密钥
    checksum = hashlib.sha256(b"v3-audit-log-table").hexdigest()
    record_migration(conn, 3, checksum)

    conn.commit()
    conn.close()
    print("Migration v3 completed")


def rollback_v3():
    """回滚脚本 - 带有确认机制"""
    # 安全检查: 确认当前环境
    environment = os.environ.get("APP_ENV", "development")
    if environment == "production":
        raise RuntimeError("Rollback is not allowed in production environment!")

    # 要求显式确认
    confirmation = input("Type 'CONFIRM ROLLBACK' to proceed: ")
    if confirmation != "CONFIRM ROLLBACK":
        print("Rollback cancelled")
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    # 使用事务回滚
    try:
        cursor.execute("DROP TABLE IF EXISTS audit_log")
        cursor.execute(
            "DELETE FROM schema_migrations WHERE version = ?",
            (3,)
        )
        conn.commit()
        print("Rollback v3 completed")
    except Exception as e:
        conn.rollback()
        print(f"Rollback failed: {e}")
    finally:
        conn.close()


def run_migrations():
    """运行所有迁移 - 带有环境检查"""
    environment = os.environ.get("APP_ENV", "development")

    # 生产环境需要显式确认
    if environment == "production":
        print("WARNING: Running migrations in PRODUCTION environment")
        confirmation = input("Type 'CONFIRM PRODUCTION' to proceed: ")
        if confirmation != "CONFIRM PRODUCTION":
            print("Migration cancelled")
            return

    print(f"Running migrations in {environment} environment...")
    migrate_v1()
    migrate_v2()
    migrate_v3()
    print("All migrations completed successfully")


if __name__ == "__main__":
    run_migrations()
