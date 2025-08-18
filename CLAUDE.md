# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains security analysis tools for Red Hat OpenShift AI (RHOAI):

1. **Security Manifest Generator** (`rhoai_security_manifest.sh`) - Queries container registries to extract and list container images
2. **Security Data Analyzer** (`rhoai_security_pyxis.py`) - Fetches detailed security information including CVEs and freshness grades from Red Hat Pyxis API
3. **Security Dashboard** (`rhoai_security_dashboard.py`) - Interactive Streamlit web application for visualizing security data

## Architecture

### Core Components

**Security Manifest Generator**: `rhoai_security_manifest.sh` - A comprehensive bash script that follows a modular function-based architecture:

**Security Data Analyzer**: `rhoai_security_pyxis.py` - Python script that queries Red Hat Pyxis API for detailed security information:
- **API Integration**: Direct queries to Red Hat Pyxis container security database
- **Data Processing**: CVE analysis, freshness grade assessment, advisory link generation
- **Output Formats**: JSON, CSV, and formatted text output with color coding
- **Comprehensive Coverage**: Includes both repository images and operator bundle images

**Security Dashboard**: `rhoai_security_dashboard.py` - Streamlit web application for interactive security data visualization:
- **Multi-tab Interface**: Security Overview, Image Details, and CVE Analysis tabs
- **Interactive Charts**: Freshness grade distribution, CVE frequency analysis, vulnerability trends
- **Data Integration**: Loads JSON output from Pyxis analyzer or executes script dynamically
- **Red Hat Styling**: Professional interface matching Red Hat design patterns

**Bash Script Architecture** (`rhoai_security_manifest.sh`):

- **Configuration Layer**: Environment variables with sensible defaults for RHOAI version, registry URLs, and output options
- **Validation Layer**: Comprehensive dependency checking and input validation with intelligent error reporting
- **Execution Layer**: Container registry interaction using podman to extract image manifests
- **Output Layer**: JSON processing pipeline (podman → jq → awk → text file) that formats results

### Function Architecture

The script uses a `fn_` prefix naming convention for all functions and follows a clear execution flow:

1. `fn_parse_arguments()` - Command-line argument processing with comprehensive option support
2. `fn_validate_dependencies()` - Multi-tier dependency validation (critical vs basic tools)
3. `fn_validate_inputs()` - Input format validation with regex patterns
4. `fn_generate_output_filename()` - Dynamic filename generation based on version
5. `fn_generate_manifest()` - Core registry interaction and data processing
6. `fn_main()` - Orchestration function with conditional execution paths

### Data Flow

```
User Input → Argument Parsing → Dependency Validation → Input Validation → Registry Query (podman) → JSON Processing (jq) → Text Formatting (awk) → File Output
```

The script queries Red Hat's operator index container, extracts catalog.json, filters for specific RHOAI bundle versions, and extracts related container images.

## Common Commands

### Security Dashboard (Interactive Web Interface)
```bash
# Launch the security dashboard (recommended for most users)
./run_dashboard.sh

# Or manually with Streamlit
streamlit run rhoai_security_dashboard.py

# Install dashboard dependencies (with uv - recommended)
./run_dashboard.sh

# Or manually with uv
uv venv && source .venv/bin/activate && uv pip install -r requirements.txt

# Or with pip
pip install -r requirements.txt
```

### Security Data Analysis (Command Line)
```bash
# Generate comprehensive security report (JSON format)
python3 ./rhoai_security_pyxis.py --release v2.22 --format json

# Generate human-readable security report
python3 ./rhoai_security_pyxis.py --release v2.21 --format text --show-all-cves

# Generate CSV for spreadsheet analysis
python3 ./rhoai_security_pyxis.py --release v2.23 --format csv --output security_report.csv
```

### Basic Manifest Generation
```bash
# Generate manifest with defaults (RHOAI 2.22.0)
./rhoai_security_manifest.sh

# Check all dependencies without running
./rhoai_security_manifest.sh --check-deps

# Verbose dependency check with version information
./rhoai_security_manifest.sh --check-deps --verbose
```

### Development and Testing
```bash
# Test specific RHOAI version
./rhoai_security_manifest.sh --version 2.23.0

# Test with custom registry
./rhoai_security_manifest.sh --registry custom-registry.com/operator-index

# Verbose execution for debugging
./rhoai_security_manifest.sh --verbose --version 2.21.0

# Environment variable configuration
RHOAI_VERSION=2.24.0 VERBOSE=true ./rhoai_security_manifest.sh
```

### Troubleshooting
```bash
# Validate script functionality
./rhoai_security_manifest.sh --help

# Test with different OpenShift versions
./rhoai_security_manifest.sh --openshift v4.17 --version 2.21.0
```

## Configuration System

The script implements a three-tier configuration hierarchy:
1. **Default values** (hardcoded in script)
2. **Environment variables** (RHOAI_VERSION, REGISTRY_URL, etc.)
3. **Command-line arguments** (highest priority)

Key configuration variables:
- `RHOAI_VERSION`: Target RHOAI version (semantic versioning: X.Y.Z)
- `REGISTRY_URL`: Container registry base URL
- `OPENSHIFT_VERSION`: OpenShift version for operator index (format: vX.Y)
- `OPERATOR_NAME`: Operator name to query (default: rhods-operator)
- `OUTPUT_FILE`: Custom output filename (auto-generated if not specified)

## Dependency Management

The script includes intelligent dependency validation with automatic package manager detection and installation guidance. Critical dependencies include:
- **podman**: Container runtime for registry access
- **jq**: JSON processing for catalog parsing
- **awk, tr, wc**: Text processing utilities

The validation system categorizes tools as "critical" (script fails without them) or "basic" (warnings only), and provides OS-specific installation commands for missing dependencies.

## Security Context

This is a defensive security tool designed for vulnerability assessment and compliance reporting. The script:
- Requires authenticated access to Red Hat's container registry
- Generates lists of container images for security scanning
- Operates in read-only mode against registries
- Produces text output suitable for security toolchain integration

When modifying the script, ensure that registry interactions remain read-only and that no sensitive information (credentials, internal URLs) is logged or exposed in output files.