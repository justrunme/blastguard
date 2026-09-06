SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: help build demo rehearse prove ci test tidy

help:
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build blastguard CLI
	go build -o bin/blastguard ./cmd/blastguard

demo: build ## Trace demo CVE blast radius + decision
	./bin/blastguard demo CVE-2026-1234

rehearse: build ## What-if rehearse for a CVE
	./bin/blastguard rehearse CVE-2026-1234

prove: build ## Before/after remediation prove
	./bin/blastguard prove

test: ## Go tests
	go test ./...

tidy: ## go mod tidy
	go mod tidy

ci: ## Offline checks + demo decision must BLOCK
	chmod +x scripts/*.sh
	./scripts/ci-check.sh
