# ============================================================
# Terraform configuration with security issues
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  # Issue 1: No backend encryption / no state locking
  # backend "s3" {}
}

provider "aws" {
  region = "us-east-1"
  # Issue 2: Hardcoded credentials
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ============================================================
# S3 Bucket with public access
# ============================================================
resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-public-data-bucket-12345"

  # Issue 3: No server-side encryption
  # Issue 4: No versioning
  # Issue 5: No logging
}

resource "aws_s3_bucket_public_access_block" "data_bucket" {
  bucket = aws_s3_bucket.data_bucket.id

  # Issue 6: Public access allowed
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "data_bucket_policy" {
  bucket = aws_s3_bucket.data_bucket.id

  # Issue 7: Overly permissive bucket policy
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data_bucket.arn}/*"
      }
    ]
  })
}

# ============================================================
# Security Group with overly permissive rules
# ============================================================
resource "aws_security_group" "web_sg" {
  name = "web-security-group"

  # Issue 8: Open to the world on all ports
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Issue 9: All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ============================================================
# RDS with security issues
# ============================================================
resource "aws_db_instance" "database" {
  identifier     = "app-database"
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t2.micro"

  # Issue 10: Hardcoded credentials
  username = "admin"
  password = "Password123!"

  # Issue 11: Publicly accessible
  publicly_accessible = true

  # Issue 12: No encryption
  storage_encrypted = false

  # Issue 13: No backup
  backup_retention_period = 0

  # Issue 14: Using default security group
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # Issue 15: No deletion protection
  deletion_protection = false

  # Issue 16: Auto minor version upgrade disabled
  auto_minor_version_upgrade = false

  # Issue 17: No IAM authentication
  iam_database_authentication_enabled = false
}

# ============================================================
# EC2 with security issues
# ============================================================
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Issue 18: No key pair specified (SSM)
  # Issue 19: Public IP
  associate_public_ip_address = true

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # Issue 20: User data with secrets
  user_data = <<-EOF
    #!/bin/bash
    echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" >> /etc/environment
    echo "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /etc/environment
    yum install -y httpd
    systemctl start httpd
  EOF

  root_block_device {
    # Issue 21: No encryption
    encrypted = false
  }
}

# ============================================================
# IAM Policy with overly permissive access
# ============================================================
resource "aws_iam_policy" "admin_policy" {
  name        = "AdminAccess"
  description = "Full admin access"

  # Issue 22: Overly permissive policy
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
