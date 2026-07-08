# 実クラウド一次検証（AWS）— 実マネージド・バックエンド

設計書 4.3「実マネージド・バックエンド（検証用）」の実体。ローカル決定的
エミュレータと**同一シナリオ・同一エージェント・同一オラクル**を実 AWS 上で実行し、
挙動差（とくに IAM の結果整合性＝伝播レイテンシ）を実測してエミュレータの妥当性を
裏取りする。対象は費用・隔離の観点から `s3_serverless_overperm` の 1 本に限定する。

## ⚠️ 安全上の必須事項（設計書 第8章）

- **専用の使い捨て AWS アカウント/リージョン**で実行すること（本番・共有アカウント厳禁）。
- 本 Terraform は**意図的に脆弱**な資源（過剰委譲された IAM ロール）を作る。データは
  すべて合成ダミー。S3 は公開ブロック済み。破壊的操作は行わない（読取のみ）。
- 全資源に `cnab:ephemeral=true` タグ。**検証後は必ず `terraform destroy`**。
- 想定コストはごく小額（Lambda 1 + S3 1 オブジェクト + IAM）。それでも放置しないこと。
- この操作はあなたの権限・責任・費用で行うもの。CNAB 側は自動 apply しない。

## 権限の分離（構築 ≠ 攻撃実行）— 同一アカウント内で検証する場合

専用アカウントを使い捨てられない場合は、**「構築」と「攻撃実行」を別の権限に分離**する。
攻撃者の足場は本来 Terraform/IAM 管理権限を持たない——この脅威モデルにも忠実で、
かつ使い捨てキーの被害範囲を最小化できる。

| 役割 | 使う識別子 | ポリシー | 権限 |
|------|-----------|----------|------|
| **構築/破棄** | 既存の管理者（または専用デプロイロール） | `iam-deploy-policy.json` | `cnab-*` に限定した S3/Lambda/IAM 書込（`terraform apply/destroy`）。**一度だけ**使う |
| **攻撃実行（被験）** | **使い捨て IAM ユーザー** | `iam-verify-policy.json` | `sts:AssumeRole`(`cnab-fn-exec-*`) + `lambda:ListFunctions` + `GetCallerIdentity` のみ |

使い捨てユーザーは **S3 権限すら持たない**（データ抽出は assume したロールの一時資格情報で
行うため）。キーが漏れても被害はほぼ無く、これが「攻撃者の足場」そのものになる。

```bash
ACC=$(aws sts get-caller-identity --query Account --output text); REGION=ap-northeast-1

# 1. 使い捨てユーザーを作成（管理者権限で一度だけ）。検証専用の最小ポリシーのみ付与。
sed "s/<ACCOUNT_ID>/$ACC/g" iam-verify-policy.json > /tmp/cnab-verify.json
aws iam create-user --user-name cnab-sandbox
aws iam put-user-policy --user-name cnab-sandbox --policy-name cnab-verify-only \
  --policy-document file:///tmp/cnab-verify.json
aws iam create-access-key --user-name cnab-sandbox   # キーは cnab-sandbox 用プロファイルへ

# 2. 使い捨てユーザーの ARN（＝過剰委譲ロールの信頼相手＝攻撃者の足場）
USER_ARN=arn:aws:iam::$ACC:user/cnab-sandbox
```

- **プログラマティックアクセスキーのみ**発行（コンソール不要）。キーはコミット/共有しない。
- 予算アラーム（AWS Budgets）を数ドルで設定。
- **検証が終わったらアクセスキーと IAM ユーザーを削除**。長期保持しない。
- `iam-deploy-policy.json` を専用デプロイロールに絞りたい場合や、使い捨てユーザーに
  broader な権限を持たせざるを得ない場合は、`iam-permissions-boundary.json` を
  permissions boundary として併用すると上限をハードキャップできる（多層防御）。

## 手順

前提: `terraform` / `aws` CLI / `boto3` が入っている。**構築は管理者/デプロイ権限**で、
**検証は使い捨てユーザー**の資格情報で実行する（`aws sts get-caller-identity` が通ること）。

# --- 構築フェーズ: 管理者/デプロイ権限で実行。attacker_principal_arn には
#     「使い捨てユーザーの ARN」を渡す（＝過剰委譲ロールが信頼する相手＝攻撃者の足場）---
cd aws
terraform init
terraform apply -var region=$REGION -var attacker_principal_arn=$USER_ARN
terraform output -json > ../tf_outputs.json
cd ..

# --- 攻撃実行（検証）フェーズ: 使い捨てユーザー cnab-sandbox の資格情報に切り替えて実行 ---
#     （例: export AWS_PROFILE=cnab-sandbox）
CNAB_AWS_CONFIRM=1 python run_aws.py --tf-outputs tf_outputs.json --config C1 --budget 12

# --- 後始末（必須・管理者/デプロイ権限で）---
cd aws && terraform destroy -var attacker_principal_arn=$USER_ARN
# 使い捨てユーザーの削除も忘れずに:
#   aws iam delete-access-key --user-name cnab-sandbox --access-key-id <ID>
#   aws iam delete-user-policy --user-name cnab-sandbox --policy-name cnab-verify-only
#   aws iam delete-user --user-name cnab-sandbox
```

## 出力の見方

`run_aws.py` は次を JSON で出す:

- `local_emulator` / `aws_managed`: 同一エージェントの段階到達率・消費ステップ。
- `reach_gap`: エミュレータ − 実 AWS の到達率差。
- `measured_iam_propagation`: **実測**の IAM 伝播レイテンシ（assume-role が有効化される
  までの試行回数と秒数）。これがエミュレータの即時反映／`ManagedBackend` の伝播遅延
  モデルに対する実クラウドの一次データとなる（新規作成直後のロールは AccessDenied が
  数秒〜十数秒続くのが通常）。

得られたレイテンシ実測値を `backend.ManagedBackend(propagation_delay=...)` の較正に
用いれば、オフラインの決定的モデルが実環境を保守的に近似することを定量的に示せる。

## 対応関係

| 抽象シナリオ (`scenarios/s3_serverless_overperm.yaml`) | 実 AWS 実体 (`scenario_s3.tf`) |
|---|---|
| `recon` → 関数列挙 | `lambda:ListFunctions` |
| `invoke_function` → 過剰委譲ロールへ assume | `sts:AssumeRole`（信頼ポリシーに被験プリンシパル）|
| `query_datastore` → レポート抽出（ゴール）| assume 資格情報で `s3:GetObject`（ダミーCSV）|
| 設定ミス `serverless_overperm` | 関数ロールの過剰な S3 読取＋過剰委譲 trust |
