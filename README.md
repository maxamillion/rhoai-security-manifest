RHOAI Security Manifest
=======================

A collection of security analysis tools for [Red Hat OpenShift AI](https://www.redhat.com/en/products/ai/openshift-ai) that generate container image manifests and provide vulnerability information through multiple approaches.

## Prerequisites

You will need to [login to Red Hat's Container Registry](https://access.redhat.com/articles/RegistryAuthentication) where the Product Images are stored.

## Available Tools

This repository contains multiple complementary tools for RHOAI security analysis:

### 1. Main Registry-Based Tool (`rhoai_security_manifest.sh`)
Fetches container images from Red Hat's operator catalog and GitHub manifests.

**Dependencies**:
- [podman](https://podman.io/) - Container runtime for registry access
- [jq](https://jqlang.github.io/jq/) - JSON processor for catalog parsing
- [curl](https://curl.se/) - HTTP client for fetching GitHub manifests
- [awk](https://www.gnu.org/software/gawk/) - Text processing tool
- Core utilities: `tr`, `wc`, `cat`, `echo`

### 2. Pyxis API Tool (`rhoai_security_pyxis.py`)
Python script that queries Red Hat's Pyxis API for comprehensive vulnerability information.

**Dependencies**:
- Python 3.x with `requests` library

### 3. Pyxis Shell Wrapper (`rhoai_security_pyxis.sh`)
Bash wrapper for direct Pyxis API queries using curl.

**Dependencies**:
- [curl](https://curl.se/) - HTTP client
- [jq](https://jqlang.github.io/jq/) - JSON processor

All tools include intelligent dependency validation with automatic package manager detection and installation guidance.

## Usage

### 1. Main Registry Tool (`rhoai_security_manifest.sh`)

**Generate image manifest** (default RHOAI version 2.22.0):
```bash
./rhoai_security_manifest.sh
```

**Generate manifest for specific version**:
```bash
./rhoai_security_manifest.sh --version 2.23.0
```

#### Main Registry Tool Options

```bash
./rhoai_security_manifest.sh [OPTIONS]

OPTIONS:
    -v, --version VERSION       RHOAI version (default: 2.22.0)
    -r, --registry URL          Registry URL (default: registry.redhat.io/redhat/redhat-operator-index)
    -o, --openshift VERSION     OpenShift version (default: v4.18)
    -p, --operator NAME         Operator name (default: rhods-operator)
    -f, --output FILE           Output filename (default: rhoai-{version})
    -d, --output-dir DIR        Output directory for reports (default: ./output)
    --check-deps                Check dependencies only and exit
    --verbose                   Enable verbose output with tool version information
    -h, --help                  Show help message
```

### 2. Pyxis API Tool (`rhoai_security_pyxis.py`)

**Query vulnerability information**:
```bash
./rhoai_security_pyxis.py --release v2.22
```

**Generate JSON report**:
```bash
./rhoai_security_pyxis.py --release v2.23 --format json --output rhoai_security_v2.23.json
```

**Show all CVEs (not truncated)**:
```bash
./rhoai_security_pyxis.py --release v2.21 --show-all-cves
```

#### Pyxis API Tool Options

```bash
./rhoai_security_pyxis.py [OPTIONS]

OPTIONS:
    -r, --release RELEASE       RHOAI release version (default: v2.21)
    -f, --format FORMAT         Output format: text, json, or csv (default: text)
    -o, --output OUTPUT         Output file path (default: stdout for text, auto-generated for json/csv)
    --no-color                  Disable colored output for text format
    -v, --verbose               Enable verbose logging and progress information
    --quiet                     Suppress status messages (except errors)
    --show-all-cves            Show all CVEs for each image without truncation (default: show first 3)
    -h, --help                  Show help message
```

### 3. Pyxis Shell Wrapper (`rhoai_security_pyxis.sh`)

Simple curl-based wrapper for direct Pyxis API access. See script source for usage details.

## Dependency Checking

All scripts automatically validate that required tools are installed before execution.

**Check dependencies for main tool**:
```bash
# Validate dependencies without running the script
./rhoai_security_manifest.sh --check-deps

# Check dependencies with verbose output (shows tool versions)
./rhoai_security_manifest.sh --check-deps --verbose
```

If dependencies are missing, the scripts will provide specific installation instructions based on your system's package manager.

## Environment Variables

You can configure the main registry tool using environment variables:

- `RHOAI_VERSION` - RHOAI version to generate manifest for
- `REGISTRY_URL` - Container registry base URL
- `OPENSHIFT_VERSION` - OpenShift version for operator index
- `OPERATOR_NAME` - Name of the operator to query
- `OUTPUT_FILE` - Output filename for the manifest
- `OUTPUT_DIR` - Output directory for reports
- `VERBOSE` - Enable verbose output (true/false)
- `GITHUB_BASE_URL` - GitHub repository base URL for manifests

## Examples

### Main Registry Tool Examples

Generate manifest for different RHOAI version:
```bash
./rhoai_security_manifest.sh --version 2.23.0
```

Use environment variables:
```bash
RHOAI_VERSION=2.21.0 OUTPUT_FILE=custom.txt ./rhoai_security_manifest.sh
```

Generate manifest for OpenShift 4.17:
```bash
./rhoai_security_manifest.sh --openshift v4.17 --version 2.21.0
```

Use custom registry and output directory:
```bash
./rhoai_security_manifest.sh --registry my-registry.com/operator-index --output-dir /tmp/reports
```

### Pyxis API Tool Examples

Generate text report for specific version:
```bash
./rhoai_security_pyxis.py --release v2.22 --verbose
```

Export CSV format with all CVEs:
```bash
./rhoai_security_pyxis.py --release v2.23 --format csv --show-all-cves --output security_report.csv
```

JSON format for integration with other tools:
```bash
./rhoai_security_pyxis.py --release v2.21 --format json --output rhoai_v2.21_security.json
```

## Output

### Registry Tool Output

The main script generates a text file containing container image URLs from multiple sources:
- **Red Hat Registry**: Images from the operator catalog
- **GitHub Manifests**: Additional images from the disconnected install helper repository

The default output filename follows the pattern `rhoai-{version}` (e.g., `rhoai-2220` for version 2.22.0).

### Pyxis API Tool Output

The Python Pyxis tool provides comprehensive vulnerability information:

**Text Format** (default):
- Human-readable report with colored output
- CVE summaries with severity levels
- Package counts and vulnerability statistics

**JSON Format**:
- Structured data suitable for integration with security tools
- Complete vulnerability details and metadata
- Machine-readable format for automation

**CSV Format**:
- Spreadsheet-compatible output
- Tabular data for analysis and reporting
- Easy import into data analysis tools

## Key Features

### Multi-Source Data Collection
- **Registry Integration**: Queries Red Hat's operator catalog for official images
- **GitHub Integration**: Fetches additional images from disconnected install manifests
- **Intelligent Deduplication**: Merges and deduplicates images from multiple sources
- **API Access**: Direct access to Red Hat Pyxis API for vulnerability data

### Comprehensive Security Analysis
- **Multiple Approaches**: Registry-based image collection and API-based vulnerability analysis
- **Vulnerability Details**: Detailed CVE information with severity classifications
- **Multiple Output Formats**: Text, JSON, and CSV formats for different use cases
- **Package Analysis**: Complete package inventories and vulnerability mappings

### Robust Error Handling
- **Comprehensive Validation**: Validates dependencies, inputs, and configurations
- **Graceful Degradation**: Continues operation when non-critical components fail
- **Detailed Logging**: Comprehensive error tracking and warning systems
- **Installation Guidance**: Automatic detection of missing tools with installation instructions

### Enhanced Usability
- **Intelligent Defaults**: Sensible default configurations for common use cases
- **Flexible Configuration**: Support for environment variables and command-line arguments
- **Verbose Mode**: Detailed progress reporting and diagnostic information
- **Version Compatibility**: Automatic handling of different RHOAI version formats
- **Cross-Platform**: Works on Linux, macOS, and Windows (with WSL)

## Configuration Priority

Settings are applied in the following order (later values override earlier ones):
1. Default values
2. Environment variables  
3. Command line arguments

## Performance Considerations

- **Efficient Processing**: Optimized for fast container registry queries
- **Network Optimization**: Intelligent retry logic and timeout handling
- **Memory Management**: Efficient processing of large image sets
- **API Rate Limiting**: Respectful API usage with built-in rate limiting

## Tool Comparison

| Feature | Registry Tool | Pyxis API Tool | Pyxis Shell Wrapper |
|---------|---------------|----------------|----------------------|
| **Data Source** | Container registries + GitHub | Red Hat Pyxis API | Red Hat Pyxis API |
| **Output** | Image list | Vulnerability details | Raw API data |
| **Formats** | Text | Text, JSON, CSV | JSON |
| **Dependencies** | podman, jq, curl | Python, requests | curl, jq |
| **Use Case** | Image collection | Security analysis | Quick API queries |
