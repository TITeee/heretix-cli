# Development

## Build and test

```bash
go mod tidy          # fetch dependencies
go build -o heretix-cli .
go test ./...
```

Some tests build a fixture binary or run `go list`, and are skipped when the `go` command is not in `PATH`.

## Project Structure

```
heretix-cli/
├── main.go                 # Entry point
├── cmd/                    # CLI command definitions (cobra)
├── collector/              # Package collection (Collector interface)
├── container/              # Docker image fetch & extraction
├── inventory/              # Package list JSON schema & I/O
├── checker/                # Vulnerability API client
├── detector/               # Local security checks (Detector interface)
├── report/                 # Table & JSON output
├── sbom/                   # CycloneDX SBOM generation
├── depgraph/               # GitHub Dependency Submission API client
└── docs/                   # Documentation (linked from README)
```

## Extending

### New ecosystem collector

1. Add a `Collector` interface implementation under `collector/`
2. Register it in the list inside `CollectAll` in `collector/collect.go`

### New local security check

1. Add a `Detector` interface implementation under `detector/`
2. Register it in the list inside `RunAll` in `detector/detector.go`
