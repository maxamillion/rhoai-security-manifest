# RHOAI Security Manifest Makefile
# Provides convenient targets for security analysis tools

# Default configuration
RHOAI_VERSION ?= 2.22.0
RHOAI_RELEASE ?= v2.21
OUTPUT_DIR ?= ./output
PYTHON ?= python3

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

.PHONY: help all clean check-deps install-deps
.PHONY: manifest manifest-verbose pyxis pyxis-json pyxis-csv pyxis-all
.PHONY: check-tools setup

# Default target
all: check-deps manifest pyxis

##@ Help
help: ## Display this help message
	@echo "$(BLUE)RHOAI Security Manifest Tools$(RESET)"
	@echo "================================"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make $(YELLOW)<target>$(RESET)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(YELLOW)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BLUE)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Dependency Management
check-deps: ## Check all dependencies for tools
	@echo "$(BLUE)Checking dependencies...$(RESET)"
	@./rhoai_security_manifest.sh --check-deps
	@echo "$(GREEN)✓ Dependencies checked$(RESET)"

check-deps-verbose: ## Check dependencies with verbose output
	@echo "$(BLUE)Checking dependencies (verbose)...$(RESET)"
	@./rhoai_security_manifest.sh --check-deps --verbose
	@echo "$(GREEN)✓ Dependencies checked$(RESET)"

install-deps: ## Install Python dependencies
	@echo "$(BLUE)Installing Python dependencies...$(RESET)"
	@$(PYTHON) -m pip install --user requests
	@echo "$(GREEN)✓ Python dependencies installed$(RESET)"

check-tools: ## Verify all required tools are available
	@echo "$(BLUE)Checking required tools...$(RESET)"
	@command -v podman >/dev/null 2>&1 || { echo "$(RED)✗ podman not found$(RESET)"; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "$(RED)✗ jq not found$(RESET)"; exit 1; }
	@command -v curl >/dev/null 2>&1 || { echo "$(RED)✗ curl not found$(RESET)"; exit 1; }
	@command -v $(PYTHON) >/dev/null 2>&1 || { echo "$(RED)✗ $(PYTHON) not found$(RESET)"; exit 1; }
	@echo "$(GREEN)✓ All required tools available$(RESET)"

##@ Security Analysis
manifest: check-deps ## Generate container image manifest (default version)
	@echo "$(BLUE)Generating RHOAI $(RHOAI_VERSION) manifest...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)
	@./rhoai_security_manifest.sh --version $(RHOAI_VERSION) --output-dir $(OUTPUT_DIR)
	@echo "$(GREEN)✓ Manifest generated in $(OUTPUT_DIR)/$(RESET)"

manifest-verbose: check-deps ## Generate manifest with verbose output
	@echo "$(BLUE)Generating RHOAI $(RHOAI_VERSION) manifest (verbose)...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)
	@./rhoai_security_manifest.sh --version $(RHOAI_VERSION) --output-dir $(OUTPUT_DIR) --verbose
	@echo "$(GREEN)✓ Manifest generated in $(OUTPUT_DIR)/$(RESET)"

manifest-custom: check-deps ## Generate manifest for custom version (make manifest-custom RHOAI_VERSION=2.23.0)
	@echo "$(BLUE)Generating RHOAI $(RHOAI_VERSION) manifest...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)
	@./rhoai_security_manifest.sh --version $(RHOAI_VERSION) --output-dir $(OUTPUT_DIR)
	@echo "$(GREEN)✓ Manifest generated in $(OUTPUT_DIR)/$(RESET)"

pyxis: ## Generate Pyxis security report (text format)
	@echo "$(BLUE)Generating Pyxis security report for $(RHOAI_RELEASE)...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --verbose

pyxis-json: ## Generate Pyxis security report (JSON format)
	@echo "$(BLUE)Generating Pyxis JSON report for $(RHOAI_RELEASE)...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format json --output $(OUTPUT_DIR)/rhoai_security_$(RHOAI_RELEASE).json
	@echo "$(GREEN)✓ JSON report generated: $(OUTPUT_DIR)/rhoai_security_$(RHOAI_RELEASE).json$(RESET)"

pyxis-csv: ## Generate Pyxis security report (CSV format)
	@echo "$(BLUE)Generating Pyxis CSV report for $(RHOAI_RELEASE)...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format csv --output $(OUTPUT_DIR)/rhoai_security_$(RHOAI_RELEASE).csv
	@echo "$(GREEN)✓ CSV report generated: $(OUTPUT_DIR)/rhoai_security_$(RHOAI_RELEASE).csv$(RESET)"

pyxis-all: pyxis-json pyxis-csv ## Generate Pyxis reports in all formats
	@echo "$(GREEN)✓ All Pyxis reports generated$(RESET)"

pyxis-all-cves: ## Generate Pyxis report showing all CVEs (not truncated)
	@echo "$(BLUE)Generating complete Pyxis security report for $(RHOAI_RELEASE)...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --show-all-cves --verbose

##@ Data Integration
sample-data: pyxis-json ## Generate sample data for development
	@echo "$(BLUE)Generating sample data...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format json --output sample_data.json
	@echo "$(GREEN)✓ Sample data generated$(RESET)"

##@ Development Workflows
full-analysis: manifest pyxis-all ## Complete security analysis (manifest + all Pyxis reports)
	@echo "$(GREEN)✓ Full security analysis complete$(RESET)"
	@echo "$(BLUE)Generated files:$(RESET)"
	@ls -la $(OUTPUT_DIR)/

dev-setup: check-tools install-deps sample-data ## Complete development environment setup
	@echo "$(GREEN)✓ Development environment ready$(RESET)"
	@echo "$(BLUE)Next steps:$(RESET)"
	@echo "  - Run './run_dashboard.sh' to start the Streamlit dashboard"
	@echo "  - Run 'make manifest' to generate image manifests"
	@echo "  - Run 'make pyxis' to analyze vulnerabilities"

quick-start: dev-setup ## Quick start: setup environment

##@ Release Workflows
release-reports: ## Generate all reports for release documentation
	@echo "$(BLUE)Generating release reports for RHOAI $(RHOAI_VERSION) / $(RHOAI_RELEASE)...$(RESET)"
	@mkdir -p $(OUTPUT_DIR)/release-$(RHOAI_VERSION)
	@./rhoai_security_manifest.sh --version $(RHOAI_VERSION) --output-dir $(OUTPUT_DIR)/release-$(RHOAI_VERSION)
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format json --output $(OUTPUT_DIR)/release-$(RHOAI_VERSION)/security-analysis.json
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format csv --output $(OUTPUT_DIR)/release-$(RHOAI_VERSION)/security-analysis.csv
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format text --output $(OUTPUT_DIR)/release-$(RHOAI_VERSION)/security-analysis.txt
	@echo "$(GREEN)✓ Release reports generated in $(OUTPUT_DIR)/release-$(RHOAI_VERSION)/$(RESET)"

##@ Maintenance
clean: ## Clean all build artifacts and temporary files
	@echo "$(BLUE)Cleaning all artifacts...$(RESET)"
	@rm -rf $(OUTPUT_DIR)
	@rm -f *.json
	@rm -f rhoai-*
	@rm -f rhoai_images.json
	@echo "$(GREEN)✓ All artifacts cleaned$(RESET)"

update-deps: ## Update Python dependencies
	@echo "$(BLUE)Updating Python dependencies...$(RESET)"
	@$(PYTHON) -m pip install --user --upgrade requests
	@echo "$(GREEN)✓ Dependencies updated$(RESET)"

##@ Testing
test-manifest: ## Test manifest generation without writing files
	@echo "$(BLUE)Testing manifest generation...$(RESET)"
	@./rhoai_security_manifest.sh --version $(RHOAI_VERSION) --check-deps
	@echo "$(GREEN)✓ Manifest generation test passed$(RESET)"

test-pyxis: ## Test Pyxis API connectivity
	@echo "$(BLUE)Testing Pyxis API connectivity...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --quiet --format json --output /dev/null
	@echo "$(GREEN)✓ Pyxis API test passed$(RESET)"

test-all: test-manifest test-pyxis ## Run all tests
	@echo "$(GREEN)✓ All tests passed$(RESET)"

##@ Information
show-config: ## Show current configuration
	@echo "$(BLUE)Current Configuration:$(RESET)"
	@echo "  RHOAI_VERSION: $(RHOAI_VERSION)"
	@echo "  RHOAI_RELEASE: $(RHOAI_RELEASE)"
	@echo "  OUTPUT_DIR: $(OUTPUT_DIR)"
	@echo "  PYTHON: $(PYTHON)"

show-status: ## Show repository status
	@echo "$(BLUE)Repository Status:$(RESET)"
	@echo "Tools:"
	@ls -la *.sh *.py 2>/dev/null || echo "  No executable tools found"
	@echo ""
	@echo "Output directory:"
	@if [ -d $(OUTPUT_DIR) ]; then ls -la $(OUTPUT_DIR)/; else echo "  $(OUTPUT_DIR) does not exist"; fi