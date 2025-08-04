# RHOAI Security Manifest Tool - User Guide

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Overview

The RHOAI Security Manifest Tool is a comprehensive security assessment utility designed for Red Hat OpenShift AI (RHOAI) releases. It automatically discovers container images in RHOAI releases, analyzes their security vulnerabilities, and generates detailed security reports with automated grading.

### Key Features

- **Automated Container Discovery**: Finds all containers in RHOAI releases using Red Hat Container Catalog API
- **Vulnerability Analysis**: Scans containers for CVEs and security issues
- **Security Grading**: Assigns A-F grades based on vulnerability severity and count
- **Multiple Output Formats**: Supports JSON, CSV, HTML, and Markdown reports
- **Offline Mode**: Works with cached data when APIs are unavailable
- **Flexible Filtering**: Analyze specific containers or complete releases
- **Package-Level Details**: Optional detailed package vulnerability information

### Security Grading System

The tool uses a 100-point scoring system:
- **A Grade**: 90-100 points (Excellent security)
- **B Grade**: 80-89 points (Good security)
- **C Grade**: 70-79 points (Acceptable security)
- **D Grade**: 60-69 points (Poor security)
- **F Grade**: 0-59 points (Critical security issues)

**Scoring Deductions**:
- Critical vulnerability: -20 points
- High vulnerability: -10 points
- Medium vulnerability: -5 points
- Low vulnerability: -1 point

## Installation

### Prerequisites
- Python 3.9 or higher
- Internet connection (for API access)
- Disk space for local cache and database

### Installation Methods

#### Option 1: Using uv (Recommended)
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install the tool
uv pip install -e .
```

#### Option 2: Using pip
```bash
pip install -e .
```

#### Option 3: Development Installation
```bash
# Clone the repository
git clone <repository-url>
cd rhoai-security-manifest

# Install development dependencies
make setup-dev

# Verify installation
osai-security-manifest --help
```

### Verification
```bash
# Check version
osai-security-manifest version

# Test basic functionality
osai-security-manifest status --check-health
```

## Getting Started

### Basic Workflow

1. **Generate Your First Report**
   ```bash
   osai-security-manifest generate --release 2.8.0
   ```

2. **View the Report**
   The tool creates a timestamped JSON report in the `security_reports/` directory.

3. **Check Status**
   ```bash
   osai-security-manifest status
   ```

### Quick Examples

```bash
# Generate HTML report with package details
osai-security-manifest generate --release 2.8.0 --format html --packages

# Analyze specific containers only
osai-security-manifest generate --release 2.8.0 --containers workbench --containers notebook

# Use offline mode with cached data
osai-security-manifest generate --release 2.8.0 --offline

# Force refresh all data from APIs
osai-security-manifest generate --release 2.8.0 --force-refresh
```

## Command Reference

### `generate` - Generate Security Reports

The primary command for creating security manifests.

```bash
osai-security-manifest generate [OPTIONS]
```

**Required Options:**
- `--release TEXT`: OpenShift AI release version (e.g., 2.8.0)

**Optional Parameters:**
- `--format [json|csv|html|markdown]`: Output format (default: json)
- `--output PATH`: Custom output file path
- `--packages`: Include package-level vulnerability details
- `--offline`: Use cached data only, no API calls
- `--force-refresh`: Ignore cache, refresh all data
- `--containers TEXT`: Filter to specific containers (repeatable)

**Examples:**
```bash
# Basic report
osai-security-manifest generate --release 2.8.0

# Comprehensive HTML report
osai-security-manifest generate --release 2.8.0 --format html --packages --output my-report.html

# Quick offline analysis
osai-security-manifest generate --release 2.8.0 --offline --format csv
```

### `status` - System Status

Check application health and configuration.

```bash
osai-security-manifest status [OPTIONS]
```

**Options:**
- `--check-health`: Perform comprehensive health check
- `--show-config`: Display current configuration

**Examples:**
```bash
# Quick status
osai-security-manifest status

# Full health check
osai-security-manifest status --check-health --show-config
```

### `compare` - Compare Releases

Compare security postures between different releases.

```bash
osai-security-manifest compare --baseline 2.7.0 --target 2.8.0
```

### `cache` - Cache Management

Manage local data cache.

```bash
# Clear all cached data
osai-security-manifest cache clear

# Show cache statistics
osai-security-manifest cache status
```

### `interactive` - Interactive Mode

Launch interactive TUI for guided analysis.

```bash
osai-security-manifest interactive
```

### Global Options

Available for all commands:
- `--config PATH`: Path to configuration file
- `--debug/--no-debug`: Enable debug mode
- `--quiet/--no-quiet`: Suppress output
- `--no-color`: Disable colored output
- `--log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]`: Set logging level

## Configuration

### Configuration File

Create a YAML configuration file for persistent settings:

```yaml
# config.yaml
database:
  url: "sqlite:///security_manifest.db"
  retention_days: 180

api:
  timeout: 30
  max_retries: 3
  max_concurrent_requests: 10

cache:
  enabled: true
  directory: "cache/"

reports:
  output_directory: "security_reports/"

logging:
  level: "INFO"
  file_path: "logs/security_manifest.log"
```

**Usage:**
```bash
osai-security-manifest --config config.yaml generate --release 2.8.0
```

### Environment Variables

Override settings using environment variables:

```bash
export RHOAI_API_TIMEOUT=60
export RHOAI_LOG_LEVEL=DEBUG
export RHOAI_CACHE_DIR=/tmp/rhoai-cache
```

### Configuration Precedence

1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## Output Formats

### JSON Format (Default)

Structured data format ideal for programmatic processing:

```json
{
  "metadata": {
    "release": "2.8.0",
    "generated_at": "2024-01-15T10:30:00",
    "total_containers": 25
  },
  "summary": {
    "total_vulnerabilities": 150,
    "grade_distribution": {"A": 10, "B": 8, "C": 5, "D": 2, "F": 0},
    "security_posture": "good"
  },
  "containers": [...]
}
```

### CSV Format

Tabular format for spreadsheet analysis:
- Container Name, Registry URL, Security Grade
- Vulnerability counts by severity
- Total vulnerability count

### HTML Format

Rich web-based report with:
- Interactive charts and graphs
- Detailed vulnerability breakdowns
- Sortable container tables
- Executive summary dashboard

### Markdown Format

Documentation-friendly format suitable for:
- Git repositories
- Wiki pages
- Technical documentation

## Advanced Usage

### Filtering Containers

```bash
# Analyze only specific container types
osai-security-manifest generate --release 2.8.0 \
  --containers workbench \
  --containers notebook \
  --containers pipeline

# Use wildcards with shell expansion
osai-security-manifest generate --release 2.8.0 \
  --containers "*workbench*"
```

### Batch Processing

```bash
#!/bin/bash
# Analyze multiple releases
for version in 2.6.0 2.7.0 2.8.0; do
  osai-security-manifest generate --release $version --format json
done
```

### Performance Optimization

```bash
# Reduce API load with concurrent requests limit
osai-security-manifest --config high-perf-config.yaml generate --release 2.8.0

# Use offline mode for faster repeated analysis
osai-security-manifest generate --release 2.8.0 --offline
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Generate Security Report
  run: |
    osai-security-manifest generate --release ${{ matrix.version }} --format json
    # Upload report as artifact or fail build based on security grade
```

## Troubleshooting

### Common Issues

#### 1. API Timeout Errors
**Symptoms**: "Request timeout" or "Connection failed" errors

**Solutions**:
```bash
# Increase timeout
osai-security-manifest --config config.yaml generate --release 2.8.0
# where config.yaml has api.timeout: 60

# Use offline mode
osai-security-manifest generate --release 2.8.0 --offline
```

#### 2. Database Issues
**Symptoms**: "Database locked" or "Permission denied" errors

**Solutions**:
```bash
# Check database file permissions
ls -la security_manifest.db

# Clear cache and reinitialize
rm -f security_manifest.db
osai-security-manifest status --check-health
```

#### 3. Memory Issues with Large Releases
**Symptoms**: "Out of memory" or slow performance

**Solutions**:
```bash
# Reduce concurrent requests
# Edit config to set api.max_concurrent_requests: 5

# Filter containers
osai-security-manifest generate --release 2.8.0 --containers notebook
```

#### 4. Rate Limiting
**Symptoms**: "Too many requests" or HTTP 429 errors

**Solutions**:
```bash
# Reduce concurrent requests and add retries
# Configure api.max_retries: 5 and api.max_concurrent_requests: 3

# Use cached data
osai-security-manifest generate --release 2.8.0 --offline
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Enable debug output
osai-security-manifest --debug generate --release 2.8.0

# Check log files
tail -f logs/security_manifest.log

# Environment variable
export RHOAI_DEBUG=true
osai-security-manifest generate --release 2.8.0
```

### Health Checks

```bash
# Comprehensive system check
osai-security-manifest status --check-health

# Database integrity check
osai-security-manifest cache status

# API connectivity test
osai-security-manifest --debug status --check-health
```

## FAQ

### General Questions

**Q: How often should I run security analysis?**
A: Recommended frequency depends on your needs:
- Weekly for production environments
- Daily during development cycles
- Before major deployments

**Q: Can I run this tool in air-gapped environments?**
A: Yes, use `--offline` mode with pre-populated cache data.

**Q: What RHOAI versions are supported?**
A: All versions with semantic versioning (X.Y.Z format). The tool automatically adapts to available container catalogs.

### Technical Questions

**Q: How much disk space does the tool require?**
A: Typical usage:
- Database: 10-50 MB per release
- Cache: 50-200 MB per release
- Reports: 1-10 MB per report

**Q: Can I customize the security grading algorithm?**
A: Yes, modify the `GradingCriteria` class in `analysis/grading.py` or use configuration overrides.

**Q: How does the tool handle API rate limits?**
A: Built-in retry logic with exponential backoff and configurable concurrent request limits.

**Q: Is the vulnerability data real-time?**
A: Data freshness depends on Red Hat's API updates. The tool caches data but can force refresh with `--force-refresh`.

### Integration Questions

**Q: Can I integrate this with Jenkins/GitLab CI?**
A: Yes, the tool provides exit codes and structured output suitable for CI/CD integration.

**Q: How do I automate report generation?**
A: Use cron jobs, CI/CD pipelines, or container orchestration scheduled jobs.

**Q: Can I export data to other security tools?**
A: Yes, JSON output can be consumed by SIEM systems, vulnerability scanners, and security dashboards.

---

For additional support, check the project's issue tracker or contribute to the documentation.