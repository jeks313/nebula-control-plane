# What CI runs, locally. Run before pushing. `make check` is vet + lint + test.
check:
    make check GOLANGCI_LINT=golangci-lint-pinned
    go run golang.org/x/vuln/cmd/govulncheck@latest ./...
    go run github.com/zricethezav/gitleaks/v8@latest git --redact .
