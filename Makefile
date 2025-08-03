.PHONY: help install install-dev test test-cov lint format type-check security clean build
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
UV := uv
PACKAGE_NAME := rhoai_security_manifest

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in development mode
	$(UV) pip install -e .

install-dev: ## Install development dependencies
	$(UV) pip install -e ".[dev]"

test: ## Run tests
	pytest -v

test-cov: ## Run tests with coverage
	pytest -v --cov=$(PACKAGE_NAME) --cov-report=term-missing --cov-report=html

test-unit: ## Run unit tests only
	pytest -v -m "unit" tests/

test-integration: ## Run integration tests only
	pytest -v -m "integration" tests/

lint: ## Run linting tools
	ruff check $(PACKAGE_NAME) tests/
	black --check $(PACKAGE_NAME) tests/
	isort --check-only $(PACKAGE_NAME) tests/

format: ## Format code
	black $(PACKAGE_NAME) tests/
	isort $(PACKAGE_NAME) tests/
	ruff check --fix $(PACKAGE_NAME) tests/

type-check: ## Run type checking
	mypy $(PACKAGE_NAME)

security: ## Run security checks
	bandit -r $(PACKAGE_NAME)
	safety check

quality: lint type-check security ## Run all quality checks

pre-commit: format quality test ## Run pre-commit checks

build: clean ## Build the package
	$(UV) build

clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

setup-dev: install-dev ## Setup development environment
	pre-commit install
	@echo "Development environment setup complete!"

validate: ## Validate project setup
	$(UV) pip check
	pytest --collect-only -q
	@echo "Project validation complete!"

run-cli: ## Run the CLI tool (example)
	$(PYTHON) -m $(PACKAGE_NAME).cli.main --help

docker-build: ## Build Docker image
	docker build -t rhoai-security-manifest:latest .

docker-run: ## Run Docker container
	docker run --rm -it rhoai-security-manifest:latest --help