# run_aws.py / AwsManagedBackend が受け取る tf_outputs。
# `terraform output -json > tf_outputs.json` で書き出して渡す。

output "region" {
  value = var.region
}

output "reports_bucket" {
  value = aws_s3_bucket.reports.id
}

output "report_object_key" {
  value = aws_s3_object.report.key
}

output "function_name" {
  value = aws_lambda_function.report_gen.function_name
}

output "exec_role_arn" {
  value = aws_iam_role.fn_exec.arn
}
