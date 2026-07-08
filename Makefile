# CNAB — 再現用の標準手順（North Star: 「docker compose up 相当」の単一エントリ）
.PHONY: all validate bench graph defend harden fidelity iac test clean

all: validate test bench

validate:
	python3 -m cnab.cli validate

bench:
	python3 -m cnab.cli bench --models small,medium,large --budgets 2,4,8,16,32 --seeds 0,1,2,3,4,5,6,7 --log-dir runs

graph:
	python3 -m cnab.cli graph --seeds 0,1,2,3,4

defend:
	python3 -m cnab.cli defend --config C0 --seeds 0,1,2,3,4,5,6,7

# 3年目深掘り: フリート防御優先順位付け（横断パレート + 累積トレードオフ曲線, 6.14）
harden:
	python3 -m cnab.cli harden --config C2 --seeds 0,1,2,3,4,5,6,7

# 実マネージド差分検証（2年目）: エミュレータ↔マネージド（伝播遅延）の挙動差を定量化
fidelity:
	python3 -m cnab.cli fidelity --config C2 --budget 12 --seeds 0,1,2,3,4,5,6,7

# シナリオ→宣言的 IaC デプロイ計画（実マネージド展開の土台）
iac:
	python3 -m cnab.cli iac

test:
	python3 -m unittest discover -s tests

# 永続化済みログを 1 つ再生して再現性を機械検証する
replay:
	python3 -m cnab.cli replay --log $(LOG)

# 正準オフラインスイートの出力ダイジェストが登録済み期待値と一致するか検証（§6 再現性）
repro:
	python3 -m cnab.cli repro-digest

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf runs
