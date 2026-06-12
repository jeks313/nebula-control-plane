SHELL := /bin/bash
M0 := spike/m0

.PHONY: help
help:
	@echo "M0 spike targets:"
	@echo "  m0-prereqs   check tooling + print install command"
	@echo "  m0-build     build pkcs11-enabled nebula-cert into $(M0)/tools"
	@echo "  m0-certs     generate local-CA certs (Ed25519) for the netns lab"
	@echo "  m0-up        bring up the netns overlay              [sudo]"
	@echo "  m0-test      ping + blocklist + group tests          [sudo]"
	@echo "  m0-down      tear down netns + bridge + nebula       [sudo]"
	@echo "  m0-hsm       SoftHSM P256 CA -> sign -> certs (the feasibility test)"

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
