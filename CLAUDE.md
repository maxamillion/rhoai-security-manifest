# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a single-purpose security manifest generator for Red Hat OpenShift AI (RHOAI). The script queries container registries to extract and list all container images associated with a specific RHOAI version for security scanning and compliance purposes.

## Architecture

### Core Components

**Main Script**: `rhoai_security_manifest.sh` - A comprehensive bash script that follows a modular function-based architecture:

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

### Basic Usage
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