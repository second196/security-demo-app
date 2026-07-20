# ============================================================
# 安全的 Terraform 配置
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # 启用远程状态存储和加密
  backend "s3" {
    bucket         = "my-terraform-state-bucket"
    key            = "security-demo-app/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"  # 状态锁
  }
}

provider "aws" {
  region = var.aws_region
  # 不再硬编码凭证，使用 IAM 角色或环境变量
  # 通过 AWS_PROFILE 或 IAM Role 认证
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true  # 标记为敏感变量
}

# ============================================================
# S3 Bucket - 加密 + 版本控制 + 访问日志
# ============================================================
resource "aws_s3_bucket" "data_bucket" {
  bucket = "${var.environment}-app-data-bucket-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "s3-access-logs/"
}

# ============================================================
# 安全的 Security Group
# ============================================================
resource "aws_security_group" "web_sg" {
  name_prefix = "${var.environment}-web-"
  vpc_id      = aws_vpc.main.id

  # 仅允许必要的端口
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP (redirect to HTTPS)"
  }

  # 仅允许必要的出站流量
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Database access"
  }

  tags = {
    Name        = "${var.environment}-web-sg"
    Environment = var.environment
  }
}

# ============================================================
# 安全的 RDS 数据库
# ============================================================
resource "aws_db_instance" "database" {
  identifier     = "${var.environment}-app-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  # 从变量读取凭证
  username = "admin"
  password = var.db_password

  # 不公开访问
  publicly_accessible = false

  # 启用加密
  storage_encrypted = true
  kms_key_id        = aws_kms_key.db_key.arn

  # 启用备份
  backup_retention_period = 7
  backup_window          = "03:00-04:00"

  # 启用删除保护
  deletion_protection = true

  # 使用专用安全组
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # 启用 IAM 数据库认证
  iam_database_authentication_enabled = true

  # 启用自动小版本升级
  auto_minor_version_upgrade = true

  # 启用性能洞察
  performance_insights_enabled = true

  # 启用监控
  monitoring_interval = 60

  # 标签
  tags = {
    Name        = "${var.environment}-database"
    Environment = var.environment
  }
}

# ============================================================
# 安全的 EC2 实例
# ============================================================
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # 不分配公网 IP
  associate_public_ip_address = false

  # 使用 IAM 实例配置文件
  iam_instance_profile = aws_iam_instance_profile.web_profile.name

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # 不在用户数据中存储密钥
  user_data = <<-EOF
    #!/bin/bash
    yum install -y httpd
    systemctl start httpd
    # 从 SSM Parameter Store 获取配置
    # aws ssm get-parameter --name /app/config --with-decryption
  EOF

  root_block_device {
    encrypted = true
  }

  tags = {
    Name        = "${var.environment}-web-server"
    Environment = var.environment
  }
}

# ============================================================
# 最小权限的 IAM 策略
# ============================================================
resource "aws_iam_policy" "app_policy" {
  name        = "${var.environment}-app-policy"
  description = "Application minimum required permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.data_bucket.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
        ]
        Resource = "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/app/*"
      },
    ]
  })
}

data "aws_caller_identity" "current" {}
