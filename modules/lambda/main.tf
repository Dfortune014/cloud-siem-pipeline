data "archive_file" "s3_exposure_zip" {
  type        = "zip"
  source_file = "${path.root}/lambda_functions/s3_exposure/handler.py"
  output_path = "${path.root}/lambda_functions/s3_exposure/handler.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name = "siem-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_sns_policy" {
  name = "lambda-sns-publish"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish", "logs:CreateLogGroup",
                  "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "*"
    },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:us-east-1:091855123856:table/siem-*"
      },
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = "arn:aws:es:us-east-1:091855123856:domain/siem-events/*"
      }
    ]
  })
}

resource "aws_lambda_function" "s3_exposure_detector" {
  filename         = data.archive_file.s3_exposure_zip.output_path
  function_name    = "siem-s3-exposure-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.s3_exposure_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN       = var.sns_topic_arn
      OPENSEARCH_ENDPOINT = var.opensearch_endpoint
    }
  }
}

resource "aws_cloudwatch_event_rule" "s3_public_exposure" {
  name        = "siem-s3-public-exposure"
  description = "Detects S3 bucket ACL or policy changes that could make bucket public"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketAcl", "PutBucketPolicy"]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_exposure_target" {
  rule = aws_cloudwatch_event_rule.s3_public_exposure.name
  arn  = aws_lambda_function.s3_exposure_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_exposure_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_exposure.arn
}

resource "aws_dynamodb_table" "failed_auth" {
  name         = "siem-failed-auth"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "source_ip"

  attribute {
    name = "source_ip"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Project = "cloud-siem-pipeline"
  }
}

# Zip the failed auth Lambda
data "archive_file" "failed_auth_zip" {
  type        = "zip"
  source_file = "${path.root}/lambda_functions/failed_auth/handler.py"
  output_path = "${path.root}/lambda_functions/failed_auth/handler.zip"
}

# Lambda function
resource "aws_lambda_function" "failed_auth_detector" {
  filename         = data.archive_file.failed_auth_zip.output_path
  function_name    = "siem-failed-auth-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.failed_auth_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN      = var.sns_topic_arn
      DYNAMODB_TABLE     = aws_dynamodb_table.failed_auth.name
      FAILURE_THRESHOLD  = "5"
      WINDOW_SECONDS     = "600"
      OPENSEARCH_ENDPOINT = var.opensearch_endpoint
    }
  }
}

# EventBridge rule — watches for ANY ConsoleLogin
# Lambda filters for failed ones internally
resource "aws_cloudwatch_event_rule" "failed_auth" {
  name        = "siem-failed-auth-detection"
  description = "Catches all console login attempts for brute force analysis"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
  })
}

# Wire EventBridge to Lambda
resource "aws_cloudwatch_event_target" "failed_auth_target" {
  rule = aws_cloudwatch_event_rule.failed_auth.name
  arn  = aws_lambda_function.failed_auth_detector.arn
}

# Allow EventBridge to invoke the Lambda
resource "aws_lambda_permission" "allow_eventbridge_failed_auth" {
  statement_id  = "AllowEventBridgeFailedAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.failed_auth_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.failed_auth.arn
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda_exec.arn
}

# Zip the root usage Lambda
data "archive_file" "root_usage_zip" {
  type        = "zip"
  source_file = "${path.root}/lambda_functions/root_usage/handler.py"
  output_path = "${path.root}/lambda_functions/root_usage/handler.zip"
}

# Lambda function
resource "aws_lambda_function" "root_usage_detector" {
  filename         = data.archive_file.root_usage_zip.output_path
  function_name    = "siem-root-usage-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.root_usage_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN       = var.sns_topic_arn
      OPENSEARCH_ENDPOINT = var.opensearch_endpoint
    }
  }
}

# EventBridge rule — catches ALL CloudTrail events
# Lambda filters for root identity internally
resource "aws_cloudwatch_event_rule" "root_usage" {
  name        = "siem-root-account-usage"
  description = "Detects any AWS API call made by the root account"

  event_pattern = jsonencode({
    source      = ["aws.signin", "aws.iam", "aws.s3",
                   "aws.ec2", "aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail",
                   "AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

# Wire EventBridge to Lambda
resource "aws_cloudwatch_event_target" "root_usage_target" {
  rule = aws_cloudwatch_event_rule.root_usage.name
  arn  = aws_lambda_function.root_usage_detector.arn
}

# Allow EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge_root_usage" {
  statement_id  = "AllowEventBridgeRootUsage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.root_usage_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.root_usage.arn
}