# heretix-cli

heretix-cli は、**[heretix](https://titeee.github.io/heretix-web/)** のスキャナーです。heretix は、サーバー・コンテナ・ネットワーク機器（ファイアウォール、VPN など）の CVE を 1 つのインベントリで管理する、セルフホスト型のツール群です（Apache-2.0）。

[English README](README.md)

## 概要

サーバー上で実行するか、ディレクトリやコンテナイメージを指定して実行します。インストールされているパッケージを洗い出し、そのうちどれに脆弱性があるかを [heretix-api](https://github.com/TITeee/heretix-api) に問い合わせます。

```
$ heretix-cli scan --image myapp:latest --api-url http://localhost:5000
   ECOSYSTEM   PACKAGE               VERSION    SOURCE               DB    VULN ID               CVSS   EPSS  SUMMARY
!  AlmaLinux   curl                  7.88.1     rpm                  nvd   CVE-2024-1234          9.8  0.950  Remote code exec
   PyPI        requests              2.31.0     /srv/myapp/requir... osv   GHSA-xxxx-yyyy         6.1  0.045  SSRF via proxy
 B Debian      binutils(2 pkgs)      2.44-3     dpkg                 osv   CVE-2024-9999          5.5  0.002  Heap overflow in BFD
...
Summary: 14 packages with 21 findings (1 malware, 1 KEV)
```

OS パッケージ（RPM、DPKG、APK）はパッケージデータベースから直接読み取ります。言語パッケージ（PyPI、npm、Go、Composer、Maven、Gradle、Java アーカイブ）は、ロックファイル、インストール済みパッケージのメタデータ、コンパイル済みバイナリから読み取ります。

heretix 全体の構成は次のとおりです。

```
 サーバー / ディレクトリ / コンテナイメージ
            │
            ▼
       heretix-cli ── collect ──► CycloneDX SBOM ──► heretix-management（インポート）
            │
            └── check / scan ── 検索 ──► heretix-api
            │
            ▼
 脆弱性レポート（表形式または JSON、CI 用の終了コード）
```

- **heretix-cli**（このリポジトリ）: パッケージを洗い出し、SBOM として書き出すか、その場で脆弱性を照合します。
- **[heretix-api](https://github.com/TITeee/heretix-api)**: パッケージのバージョンごとに、脆弱性があるかどうかを返します。
- **[heretix-management](https://github.com/TITeee/heretix-management)**: SBOM を取り込み、インベントリと検出結果を継続的に管理します。

`collect` と `detect` は API を使わずオフラインで動くため、SBOM の生成やサプライチェーン攻撃の検知だけを目的に、heretix-cli 単体で使うこともできます。

## 特徴

- **ホスト、ディレクトリ、コンテナイメージに対応**: イメージは、ローカルの Docker デーモンにあればそこから読み、なければレジストリから直接取得します。Docker 自体は必須ではありません。
- **CycloneDX 1.6 形式の SBOM**: PURL、依存関係グラフ、ライセンス、ハッシュ、直接依存か間接依存かを出力します。
- **イメージスキャンのノイズを抑制**: 同じソースパッケージから作られた複数のバイナリパッケージに共通する脆弱性は、1 件にまとめて報告します。カーネルヘッダーやビルドツールチェーンは「実行時に使われないパッケージ」として区別します。また、ディストリビューションのパッケージがインストールした言語パッケージ（例: `python3-urllib3` が置いたファイル）は、上流のバージョンではなく OS パッケージとして照合します。
- **オフラインで動くサプライチェーン攻撃の検知**: GlassWorm（不可視文字）、Dependency Confusion、悪意のあるインストールスクリプト（Shai-Hulud、RedC2）、CI/CD パイプラインの汚染、ロックファイルの整合性を検査します。
- **CI での利用を想定**: 検出があれば終了コード 1 を返し、JSON 形式でも出力できます。GitHub の依存関係グラフに送信して Dependabot に通知させることもできます。

## 対応エコシステム

| エコシステム | 読み取り元 |
|---|---|
| RPM（RHEL、AlmaLinux、Rocky Linux、Oracle Linux、CentOS） | RPM データベース（BDB、NDB、SQLite） |
| DPKG（Debian、Ubuntu） | `/var/lib/dpkg/status` |
| APK（Alpine） | `/lib/apk/db/installed` |
| PyPI | `site-packages`、`requirements.txt`、`Pipfile.lock`、`poetry.lock`、`uv.lock` |
| npm / yarn / pnpm | `package-lock.json`、`yarn.lock`、`pnpm-lock.yaml` |
| Go | `go.mod`、Go バイナリに埋め込まれたモジュール情報（イメージスキャン時） |
| Composer（PHP） | `composer.lock` |
| Maven / Gradle | `pom.xml`、`gradle.lockfile`、`build.gradle(.kts)` |
| Java アーカイブ | `*.jar`、`*.war`、`*.ear` |

OS パッケージのデータベースは、Linux ホストで読み取れるほか、イメージスキャンであればどの OS からでも読み取れます。フォールバックの動作、読み取り元ごとの詳細、実行時に使われないパッケージや OS 管理のパッケージの扱いは、[docs/package-detection.md](docs/package-detection.md)（英語）を参照してください。

## インストール

単一の静的バイナリをビルドし（Go 1.25 以上）、対象のマシンにコピーするだけで使えます。実行時に必要なものはありません。

```bash
# Linux 向け
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o heretix-cli .

# Windows 向け
GOOS=windows GOARCH=amd64 go build -o heretix-cli.exe .
```

## クイックスタート

`check` と `scan` を使うには、heretix-api が動いている必要があります。heretix-api の[クイックスタート](https://github.com/TITeee/heretix-api/blob/main/README.ja.md)を参照してください。API キーは `--api-key` オプションか、環境変数 `HERETIX_API_KEY` で渡します。

```bash
export HERETIX_API_KEY=<API キー>

# このホストをスキャンして脆弱性を表示する
heretix-cli scan --api-url http://localhost:5000

# コンテナイメージをスキャンする
heretix-cli scan --image nginx:latest --api-url http://localhost:5000

# 2 段階に分ける場合: SBOM を書き出し（オフライン）、あとで照合する
heretix-cli collect --output sbom.json
heretix-cli check sbom.json --api-url http://localhost:5000

# ローカルのセキュリティ検査だけを行う（オフライン）
heretix-cli detect --scan-path /srv/myapp
```

`sbom.json` を heretix-management にインポートすると、検出結果を継続的に追跡できます。

## コマンド

| コマンド | 用途 | heretix-api |
|---|---|---|
| `collect` | ホスト、ディレクトリ、イメージをスキャンし、パッケージ一覧を CycloneDX SBOM として書き出す | 不要 |
| `check` | SBOM を heretix-api で照合する | 必要 |
| `scan` | `collect`、`check`、ローカル検査を 1 回で実行する | 必要 |
| `detect` | ローカルのセキュリティ検査だけを行う | 不要 |
| `submit` | SBOM を GitHub の Dependency Submission API に送信する（Dependabot 用） | 不要 |

すべてのオプション、出力形式、そのほかの使用例は [docs/commands.md](docs/commands.md)（英語）を参照してください。

## CI での利用

`check`、`scan`、`detect` は、何か検出すると終了コード `1` を返します。そのため、パイプラインのステップはそれだけで失敗扱いになります。

```bash
docker build -t myapp:latest .
heretix-cli scan --image myapp:latest --api-url http://heretix-api:5000 --severity 7.0
```

| 終了コード | 意味 |
|---|---|
| `0` | 何も検出されなかった（`collect`、`submit` は正常終了） |
| `1` | 脆弱性、マルウェア、またはローカル検査での検出があった |
| `2` | コマンドの実行に失敗した |

`--severity` で CVSS スコアの下限を指定でき、`--runtime-only` を付けるとカーネルヘッダーとビルドツールチェーンの検出を除外します。`--format json` を指定すると、プログラムで扱いやすい JSON で出力します。GitHub Actions を含むそのほかの例は、[docs/commands.md](docs/commands.md#cicd-examples)（英語）を参照してください。

## ドキュメント

ドキュメントは英語のみです。

| ドキュメント | 内容 |
|---|---|
| [docs/commands.md](docs/commands.md) | 全コマンドとオプション、出力形式、終了コード、CI/CD の例 |
| [docs/package-detection.md](docs/package-detection.md) | 各コレクターが読み取るもの、実行時に使われないパッケージと OS 管理のパッケージ |
| [docs/sbom.md](docs/sbom.md) | SBOM の内容と、ロックファイルごとに埋められる項目 |
| [docs/local-checks.md](docs/local-checks.md) | ローカルのセキュリティ検査と、その判定ルール |
| [docs/development.md](docs/development.md) | プロジェクト構成、コレクターや検査の追加方法 |

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) を参照してください。
