# Security Demo Application

A demo application containing intentional security vulnerabilities for testing and educational purposes.

## ⚠️ WARNING

This application is intentionally insecure and should NEVER be deployed to any real environment.

## Security Issues Included

### 🔑 Secrets Leaked in Files
- AWS credentials in source code
- Database passwords in configuration
- API keys and tokens hardcoded
- Slack webhook URLs
- JWT secrets

### 🔍 Source Code Vulnerabilities (SAST)
- SQL Injection
- Command Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Path Traversal
- SSRF
- XML External Entity (XXE)
- Unsafe YAML loading
- Use of eval()/exec()
- Weak cryptography (MD5)
- Insecure random number generation

### 🐳 Dockerfile Issues
- Using `latest` tag
- Running as root
- No health checks
- Installing unnecessary packages (telnet, nmap)
- No multi-stage build
- Exposing unnecessary ports

### ☸️ Kubernetes Configuration Issues
- Secrets in plain text
- Privileged container
- No resource limits
- Using default namespace
- Docker socket mounted
- Overly permissive RBAC
- NodePort exposed

### 🏗️ Terraform / IaC Issues
- Hardcoded AWS credentials
- S3 bucket public access
- Security group open to all
- RDS publicly accessible
- No encryption on storage
- Overly permissive IAM policies

### 🔄 GitHub Actions Security Issues
- Hardcoded secrets in workflow
- Unpinned action versions
- Deploying on PR events
- Executing code from PRs
- No environment protection

### 📦 Package Manager Issues
- Outdated packages with known CVEs
- Supply chain vulnerabilities
- Weak dependencies

### ☁️ CloudFormation Issues
- Default password in parameters
- Public S3 bucket
- Public RDS
- No encryption
- Wildcard IAM permissions
- Sensitive values in outputs

### ⎈ Helm Chart Issues
- Hardcoded passwords in values
- NodePort exposed
- No TLS
- No resource limits
- No security context

### 📋 Ansible Issues
- Running as root
- Secrets in playbook
- World-readable secret files
- Installing security tools on prod
- No firewall rules
- Weak user passwords

## Directory Structure

```
security-demo-app/
├── src/                        # Source code with vulnerabilities
│   ├── app.py                  # Main Flask application
│   └── server.py               # Additional server code
├── deploy/
│   ├── kubernetes/             # K8s manifests with issues
│   ├── helm/                   # Helm chart with issues
│   ├── terraform/              # Terraform with issues
│   ├── cloudformation/         # CloudFormation with issues
│   └── ansible/                # Ansible playbook with issues
├── .github/workflows/          # GitHub Actions with issues
├── Dockerfile                  # Dockerfile with issues
├── requirements.txt            # Python dependencies (some vulnerable)
├── package.json                # Node.js dependencies (vulnerable)
└── README.md
```
