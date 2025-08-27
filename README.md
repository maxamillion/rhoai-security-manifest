RHOAI Security Manifest
=======================

A comprehensive collection of security analysis tools for [Red Hat OpenShift AI](https://www.redhat.com/en/products/ai/openshift-ai) that generate container image manifests and provide vulnerability information through multiple complementary approaches including interactive dashboards.

## Available Tools

This repository contains multiple integrated tools for comprehensive RHOAI security analysis:

### 1. Registry-Based Manifest Generator (`rhoai_security_manifest.sh`)
Bash script that fetches container images from Red Hat's operator catalog and GitHub manifests and provides a simple evaluation of their security status using [syft](https://github.com/anchore/syft) and [grype](https://github.com/anchore/grype).

**Dependencies**:
- [podman](https://podman.io/) - Container runtime for registry access
- [jq](https://jqlang.github.io/jq/) - JSON processor for catalog parsing
- [curl](https://curl.se/) - HTTP client for fetching GitHub manifests
- [awk](https://www.gnu.org/software/gawk/) - Text processing tool
- [syft](https://github.com/anchore/syft) - Container SBOM tool
- [grype](https://github.com/anchore/grype) - Container security analysis tool
- Core utilities: `tr`, `wc`, `cat`, `echo`

### 2. Security Data Analyzer (`rhoai_security_pyxis.py`)
Python script that queries Red Hat's Pyxis API for comprehensive vulnerability information including CVEs, freshness grades, and security advisories.

**Dependencies**:
- Python 3.7+ with `requests` library

### 3. Interactive Security Dashboard (Streamlit)
Web-based dashboard (`rhoai_security_dashboard.py`) for visualizing security data with Red Hat-inspired design.

**Dependencies**:
- Python 3.7+ with `streamlit`, `pandas`, `plotly`

## Quick Start

### 🚀 Interactive Security Dashboard (Recommended)
**Launch the Streamlit dashboard** (easiest way to get started):
```bash
# Quick start with automatic dependency management
./run_dashboard.sh

# Manual start (requires pip install -r requirements.txt or similar with uv)
streamlit run rhoai_security_dashboard.py
```
Dashboard available at: `http://localhost:8501`

### ⚡ Using Make (Recommended for automation)
**Complete workflow automation** using the included Makefile:
```bash
# Show all available commands
make help

# Quick development setup
make dev-setup

# Generate all security reports
make full-analysis

# Generate reports for specific version
make pyxis-json RHOAI_RELEASE=v2.23
```

## Detailed Usage

### 1. Registry-Based Manifest Generator (`rhoai_security_manifest.sh`)

**Generate image manifest** (default RHOAI version 2.22.0):
```bash
./rhoai_security_manifest.sh
```

**Generate manifest for specific version**:
```bash
./rhoai_security_manifest.sh --version 2.23.0
```

#### Registry Tool Options

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

### 2. Security Data Analyzer (`rhoai_security_pyxis.py`)

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

#### Security Analyzer Options

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

### 3. Streamlit Dashboard (`rhoai_security_dashboard.py`)
Interactive web application with security overview, image details, and CVE analysis:

**Features**:
- 🔍 Security Overview with summary metrics
- 📋 Filterable image details with expandable CVE information
- 🚨 Comprehensive CVE analysis with Red Hat advisory links
- 📊 Interactive charts and visualizations

### 4. Shell Wrappers

Direct API access tools for automation and scripting:
- `rhoai_security_pyxis.sh` - Direct Pyxis API queries
- `rhoai_security_manifest_pyxis.sh` - Combined operations

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

### Make-based Workflows (Recommended)

**Complete development setup**:
```bash
# Set up everything: dependencies, sample data, dashboard ready
make dev-setup

# Show current configuration
make show-config
```

**Generate comprehensive security analysis**:
```bash
# Full analysis with manifest + all Pyxis reports
make full-analysis

# Generate reports for specific RHOAI version
make manifest RHOAI_VERSION=2.23.0
make pyxis-all RHOAI_RELEASE=v2.23
```

**Dashboard workflows**:
```bash
# Generate fresh data and start Streamlit dashboard
make dashboard-data RHOAI_RELEASE=v2.22
./run_dashboard.sh
```

**Release preparation**:
```bash
# Generate all reports for release documentation
make release-reports RHOAI_VERSION=2.24.0 RHOAI_RELEASE=v2.24
```

### Direct Tool Examples

**Registry Tool Examples**:

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

**Security Analyzer Examples**:

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

**Dashboard Integration Examples**:

Generate data for dashboard consumption:
```bash
# For Streamlit dashboard
./rhoai_security_pyxis.py --release v2.22 --format json --output dashboard_data.json
```

## Output

### Registry Tool Output

The main script generates a text file containing container image URLs from multiple sources:
- **Red Hat Registry**: Images from the operator catalog
- **GitHub Manifests**: Additional images from the disconnected install helper repository

The default output filename follows the pattern `rhoai-{version}` (e.g., `rhoai-2220` for version 2.22.0).

### Security Analyzer Output

The Python Pyxis tool provides comprehensive vulnerability information in multiple formats:

**Text Format** (default):
- Human-readable report with colored output
- CVE summaries with severity levels
- Package counts and vulnerability statistics
- Freshness grades and advisory links

**JSON Format**:
- Structured data suitable for integration with security tools
- Complete vulnerability details and metadata
- Machine-readable format for automation and dashboard consumption
- Includes image metadata, CVE lists, and advisory URLs

**CSV Format**:
- Spreadsheet-compatible output
- Tabular data for analysis and reporting
- Easy import into data analysis tools

### Dashboard Output

The repository includes multiple dashboard interfaces for interactive security analysis:

**Streamlit Dashboard**:
- **Security Overview**: Summary metrics and distribution charts
- **Image Details**: Filterable table with expandable CVE details
- **CVE Analysis**: Comprehensive vulnerability tracking with Red Hat advisory links
- Real-time data generation and file loading capabilities


## Key Features

### Multi-Source Data Collection
- **Registry Integration**: Queries Red Hat's operator catalog for official images
- **GitHub Integration**: Fetches additional images from disconnected install manifests
- **Intelligent Deduplication**: Merges and deduplicates images from multiple sources
- **API Access**: Direct access to Red Hat Pyxis API for vulnerability data

### Interactive Dashboards
- **Streamlit Dashboard**: Web-based interface with Red Hat-inspired design
- **Real-time Data Integration**: Generate fresh security data from within dashboard interfaces
- **Multi-format Data Support**: JSON, CSV, and text format integration
- **Responsive Design**: Mobile-friendly interfaces for on-the-go security analysis

### Comprehensive Security Analysis
- **Multiple Approaches**: Registry-based image collection and API-based vulnerability analysis
- **Vulnerability Details**: Detailed CVE information with severity classifications and advisory links
- **Freshness Grades**: Security assessment grades from A (best) to F (worst)
- **Package Analysis**: Complete package inventories and vulnerability mappings
- **Trend Analysis**: Visual charts showing security posture distribution

### Automation & Workflow Integration
- **Make-based Automation**: Comprehensive Makefile with 40+ targets for workflow automation
- **Dependency Management**: Intelligent package manager detection with uv and npm support
- **Release Workflows**: Automated report generation for release documentation
- **Development Setup**: One-command environment setup with `make dev-setup`
- **Continuous Integration**: Testing targets for CI/CD pipeline integration

### Robust Error Handling
- **Comprehensive Validation**: Validates dependencies, inputs, and configurations
- **Graceful Degradation**: Continues operation when non-critical components fail
- **Detailed Logging**: Comprehensive error tracking and warning systems
- **Installation Guidance**: Automatic detection of missing tools with installation instructions

### Enhanced Usability
- **Intelligent Defaults**: Sensible default configurations for common use cases
- **Flexible Configuration**: Support for environment variables and command-line arguments
- **Quick Start Scripts**: One-click dashboard launch with `./run_dashboard.sh`
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

| Feature | Registry Tool | Security Analyzer | Streamlit Dashboard | Shell Wrappers |
|---------|---------------|-------------------|-------------------|----------------|
| **Data Source** | Registries + GitHub | Red Hat Pyxis API | Pyxis + JSON files | Pyxis API |
| **Output** | Image list | Vulnerability details | Interactive web UI | Raw API data |
| **Formats** | Text | Text, JSON, CSV | Web interface | JSON |
| **Dependencies** | podman, jq, curl | Python, requests | Streamlit, pandas, plotly | curl, jq |
| **Use Case** | Image collection | Security analysis | Interactive analysis | Quick API queries |
| **Interface** | Command-line | Command-line | Web browser | Command-line |
| **Visualization** | None | Text/colored output | Charts and tables | None |
| **Real-time Data** | No | Yes | Yes (with script execution) | Yes |

## Repository Structure

```
rhoai-security-manifest/
├── rhoai_security_manifest.sh          # Registry-based manifest generator
├── rhoai_security_pyxis.py             # Security data analyzer (main tool)
├── rhoai_security_dashboard.py         # Streamlit web dashboard
├── run_dashboard.sh                     # Quick dashboard launcher
├── Makefile                            # Workflow automation targets
├── requirements.txt                     # Python dependencies
├── rhoai_security_*.sh                 # Additional shell wrappers
├── output/                             # Generated reports and manifests
├── README.md                           # This documentation
├── DASHBOARD_README.md                 # Streamlit dashboard documentation
└── CLAUDE.md                          # Claude Code integration guidance
```
