# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a comprehensive suite of security analysis tools for Red Hat OpenShift AI (RHOAI) that provides multiple approaches to security assessment and vulnerability analysis:

### Core Tools

1. **Security Manifest Generator** (`rhoai_security_manifest.sh`) - Primary bash script for container image collection from registries and GitHub manifests
2. **Security Data Analyzer** (`rhoai_security_pyxis.py`) - Python tool for comprehensive vulnerability analysis via Red Hat Pyxis API
3. **Interactive Security Dashboard** (`rhoai_security_dashboard.py`) - Streamlit web application for visual security data analysis
4. **Shell Wrappers** - Additional utilities for direct API access and specialized workflows

### Supported Workflows

- **Registry-based Analysis**: Extract container images from Red Hat operator catalogs
- **API-based Security Analysis**: Query Red Hat Pyxis for CVE data, freshness grades, and security advisories
- **Multi-source Integration**: Combine registry data with GitHub disconnected install manifests
- **Interactive Visualization**: Web-based dashboards with Red Hat-inspired design
- **Security Scanning**: SBOM generation and vulnerability analysis using Syft/Grype
- **Automation Integration**: Make-based workflows for CI/CD and development environments

## Architecture

### Core Components

**Security Manifest Generator** (`rhoai_security_manifest.sh`):
- **Multi-source Collection**: Queries both Red Hat registry and GitHub manifests for comprehensive image lists
- **Advanced Security Scanning**: Optional SBOM generation and vulnerability analysis using Anchore tools
- **Parallel Processing**: Configurable parallel scanning for performance optimization
- **Comprehensive Validation**: Multi-tier dependency validation and intelligent error handling
- **Flexible Output**: Supports multiple output formats and directory structures

**Security Data Analyzer** (`rhoai_security_pyxis.py`):
- **API Integration**: Direct queries to Red Hat Pyxis container security database
- **Comprehensive Analysis**: CVE analysis, freshness grade assessment, advisory link generation
- **Multiple Output Formats**: JSON, CSV, and formatted text output with color coding
- **Complete Coverage**: Includes both repository images and operator bundle images
- **Performance Optimization**: Intelligent caching and rate limiting for API calls

**Interactive Security Dashboard** (`rhoai_security_dashboard.py`):
- **Multi-tab Interface**: Security Overview, Image Details, and CVE Analysis tabs
- **Interactive Visualizations**: Freshness grade distribution, CVE frequency analysis, vulnerability trends
- **Real-time Data Integration**: Can load existing JSON files or execute scripts dynamically
- **Professional UI**: Red Hat-inspired design with responsive layout
- **Advanced Filtering**: Search, filter, and drill-down capabilities for detailed analysis

**Automation Infrastructure**:
- **Makefile**: 40+ targets for comprehensive workflow automation
- **Dependency Management**: Intelligent package manager detection with uv and npm support
- **Development Setup**: One-command environment setup with `make dev-setup`
- **Release Workflows**: Automated report generation for documentation

### Enhanced Architecture Features

**Function-Based Design** (`rhoai_security_manifest.sh`):
- **Modular Structure**: 25+ functions with `fn_` prefix for clear organization
- **Error Handling**: Comprehensive error tracking with cleanup handlers
- **Security Integration**: Native support for Syft/Grype security scanning
- **Parallel Processing**: Configurable parallel execution for improved performance
- **Configuration Management**: Three-tier configuration (defaults → env vars → CLI args)

**API Architecture** (`rhoai_security_pyxis.py`):
- **Robust HTTP Handling**: Intelligent retry logic, timeout management, rate limiting
- **Data Processing Pipeline**: JSON parsing → CVE analysis → Advisory linking → Output formatting
- **Extensible Design**: Plugin-style architecture for additional data sources
- **Logging Framework**: Configurable logging with multiple verbosity levels

### Security Context Integration

**Multi-tier Security Analysis**:
1. **Image Collection**: Registry queries + GitHub manifest parsing
2. **Vulnerability Assessment**: Pyxis API CVE data + Grype scanning
3. **Package Analysis**: Syft SBOM generation + dependency tracking
4. **Risk Assessment**: Freshness grades + severity classifications
5. **Trend Analysis**: Historical vulnerability patterns + advisory tracking

**Data Flow Architecture**:
```
Input Sources → Collection Layer → Analysis Layer → Visualization Layer → Output Formats
     ↓              ↓               ↓               ↓                ↓
Registry API    Image Lists     CVE Data        Dashboard        JSON/CSV/Text
GitHub API      Manifests       SBOM Data       Charts           Reports
Manual Input    Deduplication   Vuln Scans      Tables           Exports
```

## Common Commands and Workflows

### 🚀 Quick Start (Recommended)
```bash
# Complete development setup with sample data
make dev-setup

# Launch interactive dashboard
./run_dashboard.sh

# Dashboard available at: http://localhost:8501
```

### 📊 Interactive Security Dashboard
```bash
# Quick start with automatic dependency management
./run_dashboard.sh

# Manual start (requires dependencies installed)
streamlit run rhoai_security_dashboard.py --server.port 8501

# Install dashboard dependencies with uv
uv venv && source .venv/bin/activate && uv pip install -r requirements.txt

# Or with pip
pip install -r requirements.txt
```

### ⚡ Make-based Automation (Recommended)
```bash
# Show all available commands
make help

# Generate comprehensive analysis (manifest + all security reports)
make full-analysis

# Generate reports for specific RHOAI version
make manifest RHOAI_VERSION=2.23.0
make pyxis-all RHOAI_RELEASE=v2.23

# Development workflows
make dev-setup              # Complete environment setup
make check-deps            # Validate all dependencies
make clean                 # Clean all generated files

# Release preparation
make release-reports RHOAI_VERSION=2.24.0 RHOAI_RELEASE=v2.24
```

### 🔍 Security Data Analysis (Command Line)
```bash
# Generate comprehensive security report (JSON format)
python3 ./rhoai_security_pyxis.py --release v2.22 --format json

# Generate human-readable security report with all CVEs
python3 ./rhoai_security_pyxis.py --release v2.21 --format text --show-all-cves

# Generate CSV for spreadsheet analysis
python3 ./rhoai_security_pyxis.py --release v2.23 --format csv --output security_report.csv

# Verbose analysis with progress information
python3 ./rhoai_security_pyxis.py --release v2.22 --verbose --log-level DEBUG
```

### 🛡️ Security Manifest Generation
```bash
# Basic manifest generation (default: RHOAI 2.22.0)
./rhoai_security_manifest.sh

# Advanced security scanning with SBOM and vulnerability analysis
./rhoai_security_manifest.sh --version 2.23.0 --security-scan --output-dir ./reports

# Generate only SBOMs for package analysis
./rhoai_security_manifest.sh --version 2.23.0 --sbom-only

# Vulnerability scanning only (requires existing SBOMs)
./rhoai_security_manifest.sh --version 2.23.0 --vuln-only

# Parallel scanning with custom format
./rhoai_security_manifest.sh --security-scan --parallel-scan 5 --scan-format sarif

# Fail build on critical vulnerabilities
./rhoai_security_manifest.sh --security-scan --fail-on critical
```

### 🔧 Development and Testing
```bash
# Check all dependencies without running
./rhoai_security_manifest.sh --check-deps --verbose

# Test specific RHOAI version with verbose output
./rhoai_security_manifest.sh --version 2.23.0 --verbose

# Test with custom registry and OpenShift version
./rhoai_security_manifest.sh --registry custom-registry.com/operator-index --openshift v4.17

# Environment variable configuration
RHOAI_VERSION=2.24.0 VERBOSE=true ./rhoai_security_manifest.sh

# Test API connectivity
make test-pyxis

# Run all tests
make test-all
```

### 🐛 Troubleshooting and Diagnostics
```bash
# Validate script functionality and show help
./rhoai_security_manifest.sh --help

# Show current configuration
make show-config

# Show repository status
make show-status

# Test with different OpenShift versions
./rhoai_security_manifest.sh --openshift v4.17 --version 2.21.0

# Verbose dependency check with version information
./rhoai_security_manifest.sh --check-deps --verbose
```

### 🔗 Integration and Automation Examples
```bash
# CI/CD pipeline integration
make check-deps && make manifest && make pyxis-json

# Generate data for dashboard consumption
python3 ./rhoai_security_pyxis.py --release v2.22 --format json --output dashboard_data.json

# Custom GitHub repository source
GITHUB_BASE_URL=https://raw.githubusercontent.com/my-org/my-repo/main ./rhoai_security_manifest.sh

# Batch processing multiple versions
for version in v2.21 v2.22 v2.23; do
    make pyxis-json RHOAI_RELEASE=$version
done
```

## Configuration System

### Three-tier Configuration Hierarchy
1. **Default values** (hardcoded in scripts)
2. **Environment variables** (RHOAI_VERSION, REGISTRY_URL, etc.)
3. **Command-line arguments** (highest priority)

### Core Configuration Variables

**Manifest Generator Variables**:
- `RHOAI_VERSION`: Target RHOAI version (semantic versioning: X.Y.Z, default: 2.22.0)
- `REGISTRY_URL`: Container registry base URL (default: registry.redhat.io/redhat/redhat-operator-index)
- `OPENSHIFT_VERSION`: OpenShift version for operator index (format: vX.Y, default: v4.18)
- `OPERATOR_NAME`: Operator name to query (default: rhods-operator)
- `OUTPUT_FILE`: Custom output filename (auto-generated if not specified)
- `OUTPUT_DIR`: Output directory for reports (default: ./output)
- `GITHUB_BASE_URL`: GitHub repository base URL for manifests

**Security Scanning Variables**:
- `SECURITY_SCAN`: Enable comprehensive security scanning (true/false)
- `SBOM_ONLY`: Generate SBOMs only (true/false)
- `VULN_ONLY`: Vulnerability scanning only (true/false)
- `SCAN_FORMAT`: Output format for security reports (json|sarif|table)
- `FAIL_ON_SEVERITY`: Exit with error on severity threshold (critical|high|medium|low)
- `PARALLEL_SCAN`: Number of parallel scanning processes (default: 3)

**Python Analyzer Variables**:
- `RHOAI_RELEASE`: RHOAI release version (format: vX.Y, default: v2.21)
- Logging and output format controls
- API rate limiting and retry configurations

### Make Configuration
**Makefile Variables**:
- `RHOAI_VERSION`: Default 2.22.0
- `RHOAI_RELEASE`: Default v2.21
- `OUTPUT_DIR`: Default ./output
- `PYTHON`: Python executable (default: python3)

## Dependency Management

### Intelligent Dependency Validation
- **Multi-tier Validation**: Critical vs basic tools with automatic categorization
- **Package Manager Detection**: Supports dnf, yum, apt, brew, pacman with automatic detection
- **Installation Guidance**: OS-specific installation commands for missing dependencies
- **Version Checking**: Optional tool version reporting in verbose mode

### Core Dependencies

**Critical Dependencies** (script fails without these):
- **podman**: Container runtime for registry access
- **jq**: JSON processing for catalog parsing and data manipulation
- **curl**: HTTP client for fetching GitHub manifests and API calls
- **awk, tr, wc**: Text processing utilities for data formatting

**Security Scanning Dependencies** (required when security scanning enabled):
- **syft**: Container SBOM generation tool (Anchore)
- **grype**: Vulnerability scanning tool (Anchore)

**Python Dependencies** (for Pyxis analyzer and dashboard):
- **requests**: HTTP library for API calls
- **streamlit**: Web framework for dashboard
- **pandas**: Data manipulation for dashboard
- **plotly**: Interactive charts for dashboard

**Optional Dependencies**:
- **uv**: Fast Python package manager (recommended over pip)
- **make**: Build automation (recommended for workflows)

### Dependency Installation

**Automatic Installation Guidance**:
```bash
# Check dependencies with installation guidance
./rhoai_security_manifest.sh --check-deps

# Install Python dependencies with uv (recommended)
./run_dashboard.sh  # Automatically handles virtual environment and dependencies

# Or manually with uv
uv venv && source .venv/bin/activate && uv pip install -r requirements.txt

# Or with pip
pip install -r requirements.txt

# Install security scanning tools
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
```

## Security Context and Compliance

### Defensive Security Tool Classification
This repository contains **defensive security tools** designed for:
- **Vulnerability Assessment**: CVE identification and severity analysis
- **Compliance Reporting**: Security posture documentation for RHOAI deployments
- **Risk Assessment**: Freshness grades and security trend analysis
- **Supply Chain Security**: SBOM generation and dependency tracking

### Security Design Principles

**Read-only Operations**:
- All registry interactions operate in read-only mode
- No modification of container images or registries
- API calls are strictly GET requests for data retrieval

**Data Handling**:
- No sensitive information (credentials, internal URLs) logged or exposed
- Temporary files cleaned up automatically
- Error handling prevents information disclosure

**Access Requirements**:
- Requires authenticated access to Red Hat's container registry (registry.redhat.io)
- Uses public APIs (Red Hat Pyxis) for vulnerability data
- GitHub manifest fetching uses public repositories

**Output Security**:
- Generated reports contain only public vulnerability information
- No internal system details exposed in output files
- Suitable for integration with security toolchains and CI/CD pipelines

### Compliance and Integration

**Enterprise Integration**:
- JSON/CSV output formats compatible with security information systems
- Make-based automation for CI/CD pipeline integration
- Configurable output directories for compliance workflows
- Parallel processing for enterprise-scale analysis

**Security Toolchain Compatibility**:
- SARIF output format for security scanners
- SBOM generation in standard formats
- Compatible with vulnerability management platforms
- Integration with Red Hat security advisory system

## Repository Structure and File Guide

### Primary Scripts
```
rhoai-security-manifest/
├── rhoai_security_manifest.sh          # Main manifest generator (1300+ lines)
├── rhoai_security_pyxis.py             # Pyxis API analyzer (600+ lines)
├── rhoai_security_dashboard.py         # Streamlit dashboard (500+ lines)
└── run_dashboard.sh                     # Quick dashboard launcher
```

### Additional Tools
```
├── rhoai_security_pyxis.sh             # Direct Pyxis API shell wrapper
├── rhoai_security_manifest_pyxis.sh    # Combined manifest + Pyxis script
└── Makefile                            # Automation with 40+ targets
```

### Configuration and Documentation
```
├── requirements.txt                     # Python dependencies
├── README.md                           # Comprehensive user documentation
├── DASHBOARD_README.md                 # Dashboard-specific documentation
├── CLAUDE.md                          # This file - Claude Code integration guide
└── LICENSE                            # Project license
```

### Generated Output Structure
```
├── output/                             # Generated reports directory
│   ├── rhoai-{version}-manifest.txt   # Container image lists
│   ├── sboms/                         # SBOM files (if security scanning enabled)
│   ├── vulnerabilities/               # Vulnerability reports
│   └── rhoai-{version}-security-report.json
├── rhoai_security_v{version}_{date}.json  # Pyxis API reports
└── rhoai_images.json                   # Temporary file (gitignored)
```

## Development Guidelines for Claude Code

### Code Analysis Patterns
When analyzing this codebase, focus on these key areas:

1. **Function Architecture**: Look for `fn_` prefixed functions in bash scripts for modular analysis
2. **Configuration Management**: Three-tier system (defaults → env vars → CLI args)
3. **Error Handling**: Comprehensive error tracking with cleanup handlers
4. **Security Integration**: SBOM/vulnerability scanning capabilities
5. **API Integration**: Red Hat Pyxis API patterns and rate limiting

### Common Development Tasks

**Adding New RHOAI Versions**:
- Update default version in scripts (RHOAI_VERSION)
- Test with new version format patterns
- Verify GitHub manifest availability
- Update documentation examples

**Extending Security Analysis**:
- Add new output formats in `SCAN_FORMAT` validation
- Extend vulnerability severity checking
- Add new API endpoints in Pyxis script
- Update dashboard visualizations

**Performance Optimization**:
- Adjust `PARALLEL_SCAN` limits
- Optimize API rate limiting
- Improve caching strategies
- Enhance batch processing

### Integration Points

**Make System Integration**:
- Use `make help` to see all available targets
- Extend Makefile for new workflows
- Follow existing target naming conventions
- Add new variables to configuration section

**Dashboard Integration**:
- JSON format is primary data exchange format
- Follow Red Hat design patterns for UI elements
- Use Streamlit caching decorators for performance
- Implement proper error handling for script execution

**CI/CD Integration**:
- Use dependency checking targets for validation
- Implement fail-fast patterns with `--fail-on` options
- Use JSON output for programmatic processing
- Follow exit code conventions for automation

### Best Practices for Modifications

1. **Maintain Defensive Security Posture**: All tools must remain read-only
2. **Follow Function Naming**: Use `fn_` prefix for bash functions
3. **Preserve Configuration System**: Maintain three-tier configuration hierarchy
4. **Add Comprehensive Testing**: Use existing test targets as examples
5. **Update Documentation**: Keep README.md and CLAUDE.md synchronized
6. **Maintain Compatibility**: Support existing environment variables and CLI arguments

### Security Considerations

**When modifying scripts, ensure**:
- Registry interactions remain read-only
- No sensitive information (credentials, internal URLs) logged or exposed
- Temporary files are properly cleaned up
- Error messages don't reveal sensitive system information
- Output files contain only public vulnerability information
- All API calls use appropriate rate limiting and retry logic