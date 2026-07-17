# ============================================================
# Dockerfile with multiple security issues
# ============================================================

# Issue 1: Using latest tag and running as root
FROM python:3.9

# Issue 2: Installing packages with no version pinning
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    netcat \
    telnet \
    && rm -rf /var/lib/apt/lists/*

# Issue 3: No WORKDIR set, using root /
COPY . /app

WORKDIR /app

# Issue 4: Requirements installed as root
RUN pip install -r requirements.txt

# Issue 5: Exposing unnecessary ports
EXPOSE 5000 8080 8443 3306 6379 27017

# Issue 6: No health check
# Issue 7: Running as root user
CMD ["python", "src/app.py"]
