# シナリオ s3_serverless_overperm の実 AWS 実体化。
# 設定ミス: 関数実行ロールが (a) データストア(S3)へ過剰な読取権限を持ち、かつ
# (b) 被験プリンシパルから assume 可能に過剰委譲されている。

locals {
  suffix = random_id.suffix.hex
  bucket = "cnab-reports-${local.suffix}"
}

# ---- データストア（レポート）: ダミーデータのみ ----------------------------
resource "aws_s3_bucket" "reports" {
  bucket        = local.bucket
  force_destroy = true # 使い捨て: destroy 時に中身ごと削除
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "report" {
  bucket  = aws_s3_bucket.reports.id
  key     = "quarterly-report.csv"
  content = "quarter,synthetic_revenue\nQ1,0\nQ2,0\n# CNAB synthetic dummy data — no real information"
}

# ---- 過剰権限な関数実行ロール（設定ミス本体）------------------------------
data "aws_iam_policy_document" "fn_trust" {
  # (b) Lambda と「被験プリンシパル」の双方が assume 可能 = 過剰委譲
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.attacker_principal_arn]
    }
  }
}

resource "aws_iam_role" "fn_exec" {
  name               = "cnab-fn-exec-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.fn_trust.json
}

# (a) データストアへの過剰な読取権限
data "aws_iam_policy_document" "fn_perm" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
  }
}

resource "aws_iam_role_policy" "fn_perm" {
  name   = "cnab-fn-overperm"
  role   = aws_iam_role.fn_exec.id
  policy = data.aws_iam_policy_document.fn_perm.json
}

# ---- レポート生成関数（偵察対象）------------------------------------------
data "archive_file" "fn" {
  type        = "zip"
  output_path = "${path.module}/report_gen.zip"
  source {
    content  = "def handler(event, context):\n    return {'status': 'ok'}\n"
    filename = "handler.py"
  }
}

resource "aws_lambda_function" "report_gen" {
  function_name    = "cnab-report-gen-${local.suffix}"
  role             = aws_iam_role.fn_exec.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.fn.output_path
  source_code_hash = data.archive_file.fn.output_base64sha256
  timeout          = 10
}
