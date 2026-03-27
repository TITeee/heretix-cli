# heretix-cli

[English README](README.md)

Linux サーバや Docker コンテナイメージの OS パッケージ（RPM, DPKG）および OSS エコシステム（PyPI, npm/yarn/pnpm）をスキャンし、脆弱性 API に問い合わせて既知の脆弱性を検出する Go 製 CLI ツール。

## 対応エコシステム

| エコシステム | スキャン対象 |
|---|---|
| AlmaLinux / RHEL 系 (RPM) | `rpm -qa` / コンテナは `rpm --root <rootfs>` |
| Debian / Ubuntu 系 (DPKG) | `var/lib/dpkg/status` を直接解析 |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock` / フォールバック: `pip list` |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / フォールバック: `npm list -g`, `pnpm list -g` |

## インストール

### ビルド

```bash
# Linux 向け静的バイナリ
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .
```

生成されたバイナリを対象サーバにコピーするだけでデプロイ完了。

### 依存パッケージ

```bash
go mod tidy
```

## 使い方

### パッケージ収集 (`collect`)

システムをスキャンし、インストール済みパッケージを JSON に出力する。オフラインで実行可能。

```bash
heretix-cli collect
heretix-cli collect --output packages.json --scan-path /srv
heretix-cli collect --skip npm,pypi --verbose

# Docker イメージをスキャン
heretix-cli collect --image nginx:latest --output nginx-inventory.json
heretix-cli collect --image registry.example.com/myapp:v1.2 --output myapp-inventory.json

# Dockerfile の FROM ベースイメージも含めてスキャン
heretix-cli collect --image myapp:latest --dockerfile ./Dockerfile --output full-inventory.json
```

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--output` | `inventory.json` | 出力ファイルパス |
| `--scan-path` | `/` | ファイルシステムの探索ルートパス |
| `--skip` | (なし) | スキップするソース (例: `--skip npm`) |
| `--verbose` | `false` | 詳細ログ出力 |
| `--image` | (なし) | スキャンする Docker イメージ参照 (例: `nginx:latest`) |
| `--dockerfile` | (なし) | Dockerfile パス: FROM のベースイメージも連鎖スキャン |

### 脆弱性チェック (`check`)

collect で出力した JSON を読み込み、脆弱性 API に問い合わせる。

```bash
heretix-cli check inventory.json
heretix-cli check inventory.json --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
heretix-cli check inventory.json --format json > results.json
```

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--api-url` | `http://localhost:3001` | heretix-api の URL |
| `--api-key` | (なし) | API 認証キー（環境変数 `HERETIX_API_KEY` でも設定可） |
| `--format` | `table` | 出力形式: `table` / `json` |
| `--severity` | `0.0` | CVSS スコアの最小閾値 |
| `--concurrency` | `10` | 並行 API リクエスト数 |
| `--timeout` | `30s` | リクエストごとのタイムアウト |
| `--verbose` | `false` | 詳細ログ出力 |

### 一気通貫スキャン (`scan`)

collect と check をワンコマンドで実行する。中間ファイル不要。

```bash
# ライブシステムスキャン
heretix-cli scan
heretix-cli scan --scan-path /srv --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0

# Docker イメージスキャン
heretix-cli scan --image nginx:latest --api-url http://heretix-api:5000 --api-key your-secret-key
heretix-cli scan --image 123456789.dkr.ecr.ap-northeast-1.amazonaws.com/myapp:v1.2 --severity 7.0

# Dockerfile の FROM ベースイメージも含めて一括スキャン
heretix-cli scan --image myapp:latest --dockerfile ./Dockerfile --api-url http://heretix-api:5000

# 環境変数で API キーを指定
HERETIX_API_KEY=your-secret-key heretix-cli scan --api-url http://heretix-api:5000
```

`--image` フラグ指定時は Docker デーモンをまず参照し、見つからない場合はレジストリから直接 pull します。レジストリ認証は `~/.docker/config.json` から自動読み込みされます（ECR, GCR, Docker Hub 対応）。

`--image` 指定時、生成される inventory.json の `hostname` はマシンのホスト名ではなく**イメージ参照**（例: `nginx:latest`）に設定されます。これにより、複数のイメージを heretix-management にインポートした際に各イメージが独立したアセットとして管理されます。

上記コマンドは `collect` と `check` の全フラグを継承する。

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--image` | (なし) | スキャンする Docker イメージ参照 |
| `--dockerfile` | (なし) | Dockerfile パス: FROM のベースイメージも連鎖スキャン |

## 出力例

### テーブル出力 (デフォルト)

```
Vulnerability Check Report
==========================
Source:     inventory.json
Host:       server01
Packages:   1523 checked (rpm: 1200, dpkg: 320, pip: 280, npm: 43)

  ECOSYSTEM   PACKAGE          VERSION    SOURCE                DB    VULN ID               CVSS   EPSS  SUMMARY
  ──────────  ───────────────  ─────────  ────────────────────  ───   ───────────────────   ────   ─────  ──────────────
! AlmaLinux   curl             7.88.1     rpm                   nvd   CVE-2024-1234          9.8   0.950  Remote code exec
  AlmaLinux   openssl          3.0.11     rpm                   osv   ALSA-2024:5678         7.5   0.123  Buffer overflow
  Debian      libssl3          3.0.11     dpkg                  nvd   CVE-2024-5678          7.5   0.098  Buffer overflow
  PyPI        requests         2.31.0     /srv/myapp/req...     osv   GHSA-xxxx-yyyy         6.1   0.045  SSRF via proxy
~ PyPI        somepkg          v2024.1    pip                   osv   GHSA-zzzz-zzzz         6.0       -  Some vulnerability

! = in CISA Known Exploited Vulnerabilities (KEV) catalog
~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)
DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)
EPSS = Exploit Prediction Scoring System probability (0.000–1.000)

Summary: 13 packages with 19 vulnerabilities (1 KEV)
  Critical (>=9.0): 1
  High (>=7.0):     4
  Medium (>=4.0):   8
  Low (<4.0):       5
```

### JSON 出力 (`--format json`)

stdout に JSON のみ出力。進捗ログは stderr に出力されるため、パイプ処理が可能。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 脆弱性なし（collect の場合は成功） |
| `1` | 脆弱性あり（CI/CD 連携用） |
| `2` | 実行失敗 |

## CI/CD での利用例

### ライブシステムスキャン

```bash
export HERETIX_API_KEY=your-secret-key
heretix-cli scan --api-url http://heretix-api:5000 --severity 7.0 --format json > /dev/null
if [ $? -eq 1 ]; then
  echo "High severity vulnerabilities found!"
  exit 1
fi
```

### Docker イメージスキャン (ビルド後チェック)

```bash
docker build -t myapp:latest .
heretix-cli scan --image myapp:latest --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0
```

### Dockerfile ベースイメージも含めた完全スキャン

```bash
heretix-cli scan --image myapp:latest --dockerfile ./Dockerfile \
  --api-url http://heretix-api:5000 --api-key your-secret-key --severity 7.0 --format json > vuln-report.json
```

## プロジェクト構成

```
heretix-cli/
├── main.go                 # エントリポイント
├── cmd/                    # CLI コマンド定義 (cobra)
├── collector/              # パッケージ収集 (Collector インターフェース)
├── container/              # Docker イメージ取得・展開
├── inventory/              # 検出リスト JSON スキーマ・I/O
├── checker/                # 脆弱性 API クライアント
└── report/                 # テーブル・JSON 出力
```

## 拡張

新しいエコシステムを追加するには:

1. `collector/` に `Collector` インターフェースの実装を追加
2. `collector/collect.go` の `CollectAll` 内のリストに登録
