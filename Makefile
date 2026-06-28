SHELL := /bin/bash
M0 := spike/m0

.PHONY: help
help:
	@echo "build targets:"
	@echo "  build        build pilot + harbor + gateway into bin/"
	@echo "  ui           build the web console SPA (ui/ -> internal/adminui/dist)"
	@echo "  harbor-ui    build harbor with the web console embedded (bin/harbor, -tags ui)"
	@echo "  test         go test ./..."
	@echo "  fmt          gofmt + goimports (golangci-lint formatters) — writes fixes"
	@echo "  vet          go vet ./cmd/... ./internal/..."
	@echo "  lint         golangci-lint run (pinned $(GOLANGCI_VERSION); spike/ excluded)"
	@echo "  check        vet + lint + test (the full pre-push gate)"
	@echo "  demo         full walkthrough: enrollment spine (m3) + control plane (M5/M6)"
	@echo "  m1-smoke     run the M1 acceptance (needs nebula + nebula-cert)"
	@echo "  m3-demo      run the M3 end-to-end enrollment harness (genesis->join)"
	@echo "  m4-chaos     run the M4.9 P3 chaos drill (Harbor down -> data plane up)"
	@echo "  systemd-verify  offline-validate packaging/systemd/pilot.service"
	@echo "  tidy         go mod tidy"
	@echo
	@echo "M0 spike targets:"
	@echo "  m0-prereqs   check tooling + print install command"
	@echo "  m0-build     build pkcs11-enabled nebula-cert into $(M0)/tools"
	@echo "  m0-certs     generate local-CA certs (Ed25519) for the netns lab"
	@echo "  m0-up        bring up the netns overlay              [sudo]"
	@echo "  m0-test      ping + blocklist + group tests          [sudo]"
	@echo "  m0-down      tear down netns + bridge + nebula       [sudo]"
	@echo "  m0-hsm       SoftHSM P256 CA -> sign -> certs (the feasibility test)"

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Harbor console build identity (CalVer date + short commit + build time), embedded so
# GET /admin/v1/version reports exactly what's deployed. Used by harbor-ui (below) + the deploy.
VPKG       := github.com/jeks313/nebula-control-plane/internal/version
CALVER     := $(shell date -u +%Y.%m.%d)
GITSHA     := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILDTIME  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
HARBOR_LDFLAGS := $(LDFLAGS) -X $(VPKG).Version=$(CALVER) -X $(VPKG).Commit=$(GITSHA) -X $(VPKG).BuildTime=$(BUILDTIME)

# Lint/format. Pinned so devs + CI run the SAME version; override
# GOLANGCI_LINT=golangci-lint to use a PATH-installed binary instead of go run.
GOLANGCI_VERSION ?= v2.12.2
GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
# Quality gates run over our code only; spike/ is experimental + holds a vendored
# nebula source copy (lint/format/vet would be noise there).
GO_PKGS := ./cmd/... ./internal/...

.PHONY: build
build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pilot ./cmd/pilot
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/harbor ./cmd/harbor
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gateway ./cmd/gateway

# ADR 0003 Phase 2: embed a known-good nebula in the pilot for offline first-boot.
# embed-nebula fetches the pinned nebula for the target GOOS/GOARCH (via fetch-nebula.sh,
# which knows slackhq's per-OS archive shapes) and gzips it into the (gitignored) embed
# asset; pilot-embedded then builds with -tags embed_nebula. On Windows it ALSO gzips the
# bundled Wintun driver into assets/wintun.gz, so the embedded pilot.exe can materialize
# wintun.dll beside nebula.exe and bring up the overlay with no pre-installed driver.
# Default `make build` embeds nothing and needs no asset.
NEBULA_VERSION ?= 1.10.3
NEBULA_OS      ?= $(shell go env GOOS)
NEBULA_ARCH    ?= $(shell go env GOARCH)

.PHONY: embed-nebula
embed-nebula:
	@mkdir -p internal/nebulaboot/assets
	@set -euo pipefail; \
	  tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	  bash deploy/prod/artifacts/fetch-nebula.sh "$(NEBULA_VERSION)" "$(NEBULA_OS)" "$(NEBULA_ARCH)" "$$tmp"; \
	  gzip -9 -c "$$tmp/nebula" > internal/nebulaboot/assets/nebula.gz; \
	  [ -s internal/nebulaboot/assets/nebula.gz ]; \
	  if [ "$(NEBULA_OS)" = "windows" ]; then \
	    gzip -9 -c "$$tmp/wintun.dll" > internal/nebulaboot/assets/wintun.gz; \
	    [ -s internal/nebulaboot/assets/wintun.gz ]; \
	  else \
	    rm -f internal/nebulaboot/assets/wintun.gz; \
	  fi
	@ls -lh internal/nebulaboot/assets/

.PHONY: pilot-embedded
pilot-embedded: embed-nebula
	@mkdir -p bin
	GOOS=$(NEBULA_OS) GOARCH=$(NEBULA_ARCH) go build -trimpath -tags embed_nebula -ldflags "$(LDFLAGS)" -o bin/pilot$(if $(filter windows,$(NEBULA_OS)),.exe,) ./cmd/pilot

.PHONY: ui
ui:
	npm --prefix ui install
	npm --prefix ui run build

.PHONY: harbor-ui
harbor-ui: ui
	@mkdir -p bin
	go build -trimpath -tags ui -ldflags "$(HARBOR_LDFLAGS)" -o bin/harbor ./cmd/harbor

# Regenerate the embedded console changelog from git log (commit before a deploy so the new
# binary embeds it). harbor-ui intentionally does NOT auto-run this — it uses the committed file.
.PHONY: changelog
changelog:
	bash deploy/scripts/gen-changelog.sh

.PHONY: test
test:
	go test ./...

.PHONY: fmt
fmt:
	$(GOLANGCI_LINT) fmt $(GO_PKGS)

.PHONY: vet
vet:
	go vet $(GO_PKGS)

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run $(GO_PKGS)

# The pre-push gate: format check (via lint's formatters) + vet + lint + tests.
.PHONY: check
check: vet lint test
	@echo "check: vet + lint + tests all clean"

.PHONY: m1-smoke
m1-smoke:
	go test -v -run TestPilotInitProducesConfigNebulaAccepts ./internal/integration

.PHONY: signer-softhsm
signer-softhsm:
	CGO_ENABLED=1 go test -tags pkcs11 -run TestPKCS11SoftHSMEndToEnd -v ./internal/signer

.PHONY: demo
demo: m3-demo
	@bash spike/demo/walkthrough.sh

.PHONY: demo-cp
demo-cp:
	@bash spike/demo/walkthrough.sh

.PHONY: m3-demo
m3-demo:
	@bash spike/m3/demo.sh

.PHONY: m4-chaos
m4-chaos:
	@bash spike/m4/chaos.sh

.PHONY: systemd-verify
systemd-verify:
	systemd-analyze verify packaging/systemd/pilot.service
	@echo "--- security profile (offline) ---"
	@systemd-analyze security --offline=true packaging/systemd/pilot.service || true

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: m0-prereqs
m0-prereqs:
	@bash $(M0)/00-prereqs.sh

.PHONY: m0-build
m0-build:
	@bash $(M0)/10-build-nebula-cert-pkcs11.sh

.PHONY: m0-certs
m0-certs:
	@bash $(M0)/30-gen-certs.sh

.PHONY: m0-up
m0-up: m0-certs
	@sudo bash $(M0)/40-netns-up.sh

.PHONY: m0-test
m0-test:
	@sudo bash $(M0)/50-test.sh

.PHONY: m0-down
m0-down:
	@sudo bash $(M0)/90-down.sh

.PHONY: m0-hsm
m0-hsm:
	@bash $(M0)/20-softhsm-ca.sh
	@bash $(M0)/31-gen-certs-hsm.sh
	@echo "Now run: make m0-up && make m0-test  (uses the HSM-signed certs in run/)"
