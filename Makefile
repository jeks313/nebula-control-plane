SHELL := /bin/bash
M0 := spike/m0

.PHONY: help
help:
	@echo "build targets:"
	@echo "  build        build pilot + harbor + gateway into bin/"
	@echo "  test         go test ./..."
	@echo "  m1-smoke     run the M1 acceptance (needs nebula + nebula-cert)"
	@echo "  m3-demo      run the M3 end-to-end enrollment harness (genesis->join)"
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

.PHONY: build
build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pilot ./cmd/pilot
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/harbor ./cmd/harbor
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gateway ./cmd/gateway

.PHONY: test
test:
	go test ./...

.PHONY: m1-smoke
m1-smoke:
	go test -v -run TestPilotInitProducesConfigNebulaAccepts ./internal/integration

.PHONY: signer-softhsm
signer-softhsm:
	CGO_ENABLED=1 go test -tags pkcs11 -run TestPKCS11SoftHSMEndToEnd -v ./internal/signer

.PHONY: m3-demo
m3-demo:
	@bash spike/m3/demo.sh

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
