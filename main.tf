provider "aws" {
  region = "us-east-1"
}

module "sns" {
  source      = "./modules/sns"
  alert_email = var.alert_email
}

module "lambda" {
  source        = "./modules/lambda"
  sns_topic_arn = module.sns.topic_arn
  opensearch_endpoint = module.opensearch.opensearch_endpoint
  opensearch_user = var.opensearch_master_user
  opensearch_pass = var.opensearch_master_password
}

module "opensearch" {
  source                     = "./modules/opensearch"
  opensearch_master_user     = var.opensearch_master_user
  opensearch_master_password = var.opensearch_master_password
  lambda_role_arn            = module.lambda.lambda_role_arn
}