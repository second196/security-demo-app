# ============================================================
# 安全的 Dockerfile
# ============================================================

# 1. 使用特定版本的镜像，不使用 latest
FROM python:3.11-slim AS builder

# 2. 设置工作目录
WORKDIR /app

# 3. 安装系统依赖并清理缓存
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 4. 安装 Python 依赖（使用缓存层）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 使用多阶段构建，最终镜像更小
FROM python:3.11-slim

WORKDIR /app

# 6. 复制依赖
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 7. 复制应用代码
COPY src/ ./src/
COPY config/ ./config/

# 8. 创建非 root 用户
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# 9. 设置文件权限
RUN chown -R appuser:appuser /app

# 10. 切换到非 root 用户
USER appuser

# 11. 仅暴露必要端口
EXPOSE 5000

# 12. 添加健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# 13. 使用非 root 用户运行
CMD ["python", "src/app.py"]
