RHOAI Security Manifest
=======================

A comprehensive security analysis tool for [Red Hat OpenShift AI](https://www.redhat.com/en/products/ai/openshift-ai) that generates container image manifests and performs optional security scanning with SBOM generation and vulnerability analysis.

## Prerequisites

You will need to [login to Red Hat's Container Registry](https://access.redhat.com/articles/RegistryAuthentication) where the Product Images are stored.

This script requires the following tools to be installed:

**Core Dependencies (Required)**:
- [podman](https://podman.io/) - Container runtime for registry access
- [jq](https://jqlang.github.io/jq/) - JSON processor for catalog parsing
- [curl](https://curl.se/) - HTTP client for fetching GitHub manifests
- [awk](https://www.gnu.org/software/gawk/) - Text processing tool
- Core utilities: `tr`, `wc`, `cat`, `echo`

**Security Scanning Dependencies (Optional)**:
- [syft](https://github.com/anchore/syft) - SBOM (Software Bill of Materials) generation
- [grype](https://github.com/anchore/grype) - Vulnerability scanner

The script includes intelligent dependency validation with automatic package manager detection and installation guidance for missing tools.

## Usage

### Basic Usage

**Simple manifest generation** (RHOAI version 2.22.0, fetches from both Red Hat registry and GitHub):
```bash
./rhoai_security_manifest.sh
```

**With comprehensive security scanning**:
```bash
./rhoai_security_manifest.sh --security-scan
```

### Command Line Options

```bash
./rhoai_security_manifest.sh [OPTIONS]

CORE OPTIONS:
    -v, --version VERSION       RHOAI version (default: 2.22.0)
    -r, --registry URL          Registry URL (default: registry.redhat.io/redhat/redhat-operator-index)
    -o, --openshift VERSION     OpenShift version (default: v4.18)
    -p, --operator NAME         Operator name (default: rhods-operator)
    -f, --output FILE           Output filename (default: rhoai-{version})
    -d, --output-dir DIR        Output directory for reports (default: ./output)
    --check-deps                Check dependencies only and exit
    --verbose                   Enable verbose output with tool version information
    -h, --help                  Show help message

SECURITY SCANNING OPTIONS:
    --security-scan             Enable comprehensive security scanning (SBOM + vulnerabilities)
    --sbom-only                 Generate SBOMs only (no vulnerability scanning)
    --vuln-only                 Vulnerability scanning only (requires existing SBOMs)
    --scan-format FORMAT        Output format for security reports (json|sarif|table) (default: json)
    --fail-on SEVERITY         Exit with error if vulnerabilities >= severity found (critical|high|medium|low)
    --parallel-scan N           Number of parallel scanning processes (default: 3)
```

### Dependency Checking

The script automatically validates that all required command-line tools are installed before execution:

**Critical Dependencies** (script will not run without these):
- `podman` - Container runtime for accessing Red Hat registry
- `jq` - JSON processor for parsing catalog data
- `awk` - Text processing for formatting output
- `tr` - Character translation for data cleanup
- `wc` - Word count for statistics

**Basic Dependencies** (usually pre-installed):
- `cat` - File concatenation
- `echo` - Text output

#### Check Dependencies Only
```bash
# Validate dependencies without running the script
./rhoai_security_manifest.sh --check-deps

# Check dependencies with verbose output (shows tool versions)
./rhoai_security_manifest.sh --check-deps --verbose
```

If dependencies are missing, the script will provide specific installation instructions based on your system's package manager.

### Environment Variables

You can also configure the script using environment variables:

**Core Configuration**:
- `RHOAI_VERSION` - RHOAI version to generate manifest for
- `REGISTRY_URL` - Container registry base URL
- `OPENSHIFT_VERSION` - OpenShift version for operator index
- `OPERATOR_NAME` - Name of the operator to query
- `OUTPUT_FILE` - Output filename for the manifest
- `OUTPUT_DIR` - Output directory for reports
- `VERBOSE` - Enable verbose output (true/false)
- `GITHUB_BASE_URL` - GitHub repository base URL for manifests

**Security Scanning Configuration**:
- `SECURITY_SCAN` - Enable comprehensive security scanning (true/false)
- `SBOM_ONLY` - Generate SBOMs only (true/false)
- `VULN_ONLY` - Vulnerability scanning only (true/false)
- `SCAN_FORMAT` - Output format for security reports (json/sarif/table)
- `FAIL_ON_SEVERITY` - Exit with error on vulnerability severity (critical/high/medium/low)
- `PARALLEL_SCAN` - Number of parallel scanning processes

### Examples

#### Basic Manifest Generation

Generate manifest for a different RHOAI version:
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

Use a custom registry and output directory:
```bash
./rhoai_security_manifest.sh --registry my-registry.com/operator-index --output-dir /tmp/reports
```

#### Security Scanning Examples

Comprehensive security analysis with SBOM generation and vulnerability scanning:
```bash
./rhoai_security_manifest.sh --version 2.23.0 --security-scan
```

Generate only SBOMs without vulnerability scanning:
```bash
./rhoai_security_manifest.sh --version 2.23.0 --sbom-only
```

Perform vulnerability scanning on existing SBOMs:
```bash
./rhoai_security_manifest.sh --version 2.23.0 --vuln-only
```

Security scan with custom output format and failure conditions:
```bash
./rhoai_security_manifest.sh --security-scan --scan-format sarif --fail-on critical --output-dir /tmp/security-reports
```

High-performance scanning with parallel processing:
```bash
./rhoai_security_manifest.sh --security-scan --parallel-scan 8 --verbose
```

Generate human-readable security report:
```bash
./rhoai_security_manifest.sh --security-scan --scan-format table --verbose
```

## Output

### Basic Output

The script generates a text file containing container image URLs from multiple sources:
- **Red Hat Registry**: Images from the operator catalog
- **GitHub Manifests**: Additional images from the disconnected install helper repository

The default output filename follows the pattern `rhoai-{version}` (e.g., `rhoai-2220` for version 2.22.0).

### Security Scanning Output

When security scanning is enabled, the script creates a structured output directory:

```
./output/
├── rhoai-{version}-manifest.txt          # Container image list
├── rhoai-{version}-security-report.json  # Comprehensive security report
├── sboms/                                 # Software Bill of Materials
│   ├── {image-name}-sbom.json
│   └── ...
└── vulnerabilities/                       # Vulnerability scan results
    ├── {image-name}-vulnerabilities.{format}
    └── ...
```

**Security Report Features**:
- Aggregate vulnerability counts by severity (Critical, High, Medium, Low)
- Per-image analysis with package counts and vulnerability summaries
- JSON format for integration with security toolchains
- Support for SARIF and table formats for different use cases

## Key Features

### Multi-Source Data Collection
- **Registry Integration**: Queries Red Hat's operator catalog for official images
- **GitHub Integration**: Fetches additional images from disconnected install manifests
- **Intelligent Deduplication**: Merges and deduplicates images from multiple sources

### Advanced Security Scanning
- **SBOM Generation**: Creates comprehensive Software Bills of Materials using Syft
- **Vulnerability Analysis**: Performs detailed vulnerability scanning using Grype
- **Parallel Processing**: Configurable parallel scanning for improved performance
- **Multiple Output Formats**: JSON, SARIF, and human-readable table formats
- **CI/CD Integration**: Configurable failure conditions based on vulnerability severity

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

## Configuration Priority

Settings are applied in the following order (later values override earlier ones):
1. Default values
2. Environment variables  
3. Command line arguments

## Performance Considerations

- **Parallel Processing**: Default 3 concurrent scans, configurable up to system limits
- **Network Optimization**: Intelligent retry logic and timeout handling
- **Memory Management**: Efficient processing of large image sets
- **Caching**: Reuses analysis results where appropriate
