# ============================================================
# Terraform modules with additional security issues
# ============================================================

# Issue: Module using old provider versions
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"  # Issue: Old version
    }
  }
}

# ============================================================
# Lambda function with security issues
# ============================================================
resource "aws_lambda_function" "api_handler" {
  filename      = "lambda.zip"
  function_name = "api-handler"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.8"  # Issue: Old runtime

  environment {
    variables = {
      # Issue: Secrets in environment variables
      DATABASE_URL = "postgres://admin:Password123!@db:5432/app"
      API_KEY      = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
      SECRET_KEY   = "super_secret_key_12345"
    }
  }

  # Issue: No VPC configuration
  # Issue: No encryption
  # Issue: No tracing
  # Issue: No reserved concurrency
}

# ============================================================
# IAM role with overly permissive policy
# ============================================================
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          # Issue: Allowing any service to assume this role
          Service = "*"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-permissions"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Issue: Wildcard permissions
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# ============================================================
# CloudWatch Log Group with no retention
# ============================================================
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/api-handler"
  # Issue: No retention policy (logs retained forever)
  # retention_in_days = 30
}

# ============================================================
# API Gateway with no auth
# ============================================================
resource "aws_apigatewayv2_api" "api" {
  name          = "api-gateway"
  protocol_type = "HTTP"
  # Issue: No authorization configured
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true
  # Issue: No access logs
  # Issue: No throttling
  # Issue: No WAF
}

# ============================================================
# SNS Topic with public access
# ============================================================
resource "aws_sns_topic" "alerts" {
  name = "alerts"
}

resource "aws_sns_topic_policy" "alerts_policy" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicPublish"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# ============================================================
# SQS Queue with public access
# ============================================================
resource "aws_sqs_queue" "tasks" {
  name = "task-queue"
}

resource "aws_sqs_queue_policy" "tasks_policy" {
  queue_url = aws_sqs_queue.tasks.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.tasks.arn
      }
    ]
  })
}
