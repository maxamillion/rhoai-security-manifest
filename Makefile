# RHOAI Security Manifest Makefile
# Provides convenient targets for security analysis tools and dashboard

# Default configuration
RHOAI_VERSION ?= 2.22.0
RHOAI_RELEASE ?= v2.21
OUTPUT_DIR ?= ./output
DASHBOARD_DIR ?= rhoai-security-dashboard
PYTHON ?= python3
NODE ?= node
NPM ?= npm

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

.PHONY: help all clean check-deps install-deps
.PHONY: manifest manifest-verbose pyxis pyxis-json pyxis-csv pyxis-all
.PHONY: dashboard dashboard-dev dashboard-build dashboard-install dashboard-clean
.PHONY: sample-data dashboard-data
.PHONY: check-tools setup

# Default target
all: check-deps manifest pyxis dashboard-build

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
	@command -v $(NODE) >/dev/null 2>&1 || { echo "$(RED)✗ $(NODE) not found$(RESET)"; exit 1; }
	@command -v $(NPM) >/dev/null 2>&1 || { echo "$(RED)✗ $(NPM) not found$(RESET)"; exit 1; }
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

##@ Dashboard
dashboard-install: ## Install dashboard dependencies
	@echo "$(BLUE)Installing dashboard dependencies...$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) install
	@echo "$(GREEN)✓ Dashboard dependencies installed$(RESET)"

dashboard-dev: dashboard-install ## Start dashboard development server
	@echo "$(BLUE)Starting dashboard development server...$(RESET)"
	@echo "$(YELLOW)Dashboard will be available at: http://localhost:5173$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) run dev

dashboard-build: dashboard-install ## Build dashboard for production
	@echo "$(BLUE)Building dashboard for production...$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) run build
	@echo "$(GREEN)✓ Dashboard built in $(DASHBOARD_DIR)/dist/$(RESET)"

dashboard-preview: dashboard-build ## Preview production dashboard build
	@echo "$(BLUE)Starting dashboard preview server...$(RESET)"
	@echo "$(YELLOW)Preview will be available at: http://localhost:4173$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) run preview

dashboard-lint: ## Lint dashboard code
	@echo "$(BLUE)Linting dashboard code...$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) run lint
	@echo "$(GREEN)✓ Dashboard linting complete$(RESET)"

dashboard-clean: ## Clean dashboard build artifacts
	@echo "$(BLUE)Cleaning dashboard build artifacts...$(RESET)"
	@rm -rf $(DASHBOARD_DIR)/dist
	@rm -rf $(DASHBOARD_DIR)/node_modules
	@echo "$(GREEN)✓ Dashboard cleaned$(RESET)"

##@ Data Integration
sample-data: pyxis-json ## Generate sample data for dashboard development
	@echo "$(BLUE)Generating sample data for dashboard...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format json --output sample_data.json
	@cp sample_data.json $(DASHBOARD_DIR)/public/
	@echo "$(GREEN)✓ Sample data generated and copied to dashboard$(RESET)"

dashboard-data: ## Generate fresh data for dashboard (custom release: make dashboard-data RHOAI_RELEASE=v2.22)
	@echo "$(BLUE)Generating dashboard data for $(RHOAI_RELEASE)...$(RESET)"
	@$(PYTHON) rhoai_security_pyxis.py --release $(RHOAI_RELEASE) --format json --output $(DASHBOARD_DIR)/public/sample_data.json
	@echo "$(GREEN)✓ Dashboard data updated for $(RHOAI_RELEASE)$(RESET)"

##@ Development Workflows
full-analysis: manifest pyxis-all ## Complete security analysis (manifest + all Pyxis reports)
	@echo "$(GREEN)✓ Full security analysis complete$(RESET)"
	@echo "$(BLUE)Generated files:$(RESET)"
	@ls -la $(OUTPUT_DIR)/

dev-setup: check-tools install-deps dashboard-install sample-data ## Complete development environment setup
	@echo "$(GREEN)✓ Development environment ready$(RESET)"
	@echo "$(BLUE)Next steps:$(RESET)"
	@echo "  - Run 'make dashboard-dev' to start the dashboard"
	@echo "  - Run 'make manifest' to generate image manifests"
	@echo "  - Run 'make pyxis' to analyze vulnerabilities"

quick-start: dev-setup dashboard-dev ## Quick start: setup environment and run dashboard

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
clean: dashboard-clean ## Clean all build artifacts and temporary files
	@echo "$(BLUE)Cleaning all artifacts...$(RESET)"
	@rm -rf $(OUTPUT_DIR)
	@rm -f *.json
	@rm -f rhoai-*
	@rm -f rhoai_images.json
	@echo "$(GREEN)✓ All artifacts cleaned$(RESET)"

update-deps: ## Update dashboard dependencies
	@echo "$(BLUE)Updating dashboard dependencies...$(RESET)"
	@cd $(DASHBOARD_DIR) && $(NPM) update
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

test-dashboard: dashboard-lint dashboard-build ## Test dashboard build and linting
	@echo "$(GREEN)✓ Dashboard tests passed$(RESET)"

test-all: test-manifest test-pyxis test-dashboard ## Run all tests
	@echo "$(GREEN)✓ All tests passed$(RESET)"

##@ Information
show-config: ## Show current configuration
	@echo "$(BLUE)Current Configuration:$(RESET)"
	@echo "  RHOAI_VERSION: $(RHOAI_VERSION)"
	@echo "  RHOAI_RELEASE: $(RHOAI_RELEASE)"
	@echo "  OUTPUT_DIR: $(OUTPUT_DIR)"
	@echo "  DASHBOARD_DIR: $(DASHBOARD_DIR)"
	@echo "  PYTHON: $(PYTHON)"
	@echo "  NODE: $(NODE)"
	@echo "  NPM: $(NPM)"

show-status: ## Show repository status
	@echo "$(BLUE)Repository Status:$(RESET)"
	@echo "Tools:"
	@ls -la *.sh *.py 2>/dev/null || echo "  No executable tools found"
	@echo ""
	@echo "Output directory:"
	@if [ -d $(OUTPUT_DIR) ]; then ls -la $(OUTPUT_DIR)/; else echo "  $(OUTPUT_DIR) does not exist"; fi
	@echo ""
	@echo "Dashboard:"
	@if [ -d $(DASHBOARD_DIR) ]; then echo "  Dashboard directory exists"; else echo "  Dashboard directory missing"; fi
	@if [ -f $(DASHBOARD_DIR)/package.json ]; then echo "  Package.json found"; else echo "  Package.json missing"; fi
	@if [ -d $(DASHBOARD_DIR)/node_modules ]; then echo "  Dependencies installed"; else echo "  Dependencies not installed"; fi