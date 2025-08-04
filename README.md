# RHOAI Security Manifest Tool

A comprehensive security assessment tool for Red Hat OpenShift AI (RHOAI) releases. This tool generates detailed security reports by analyzing container vulnerabilities and providing actionable security assessments.

## 🎯 Overview

The RHOAI Security Manifest Tool helps security teams and administrators:
- Generate comprehensive security reports for RHOAI releases
- Track container vulnerabilities across releases
- Assess security posture with automated grading (A-F)
- Work offline with cached data
- Export reports in multiple formats (JSON, CSV, HTML, Markdown)

## 🚀 Quick Start

### Installation

```bash
# Using uv (recommended)
uv pip install -e .

# Using pip
pip install -e .

# For development
make setup-dev
```

### Basic Usage

```bash
# Generate security manifest for RHOAI 2.8.0
osai-security-manifest generate --release 2.8.0

# Generate HTML report with package details
osai-security-manifest generate --release 2.8.0 --format html --packages

# Use offline mode with cached data
osai-security-manifest generate --release 2.8.0 --offline

# Check application status
osai-security-manifest status --check-health
```

## 🏗️ Architecture

The tool follows a clean layered architecture designed for maintainability and extensibility:

```
┌─────────────────────────────────────┐
│         CLI Layer (cli/)            │  ← User interaction
├─────────────────────────────────────┤
│      Analysis Layer (analysis/)     │  ← Business logic
├─────────────────────────────────────┤
│        API Layer (api/)             │  ← External services
├─────────────────────────────────────┤
│     Database Layer (database/)      │  ← Data persistence
├─────────────────────────────────────┤
│      Reports Layer (reports/)       │  ← Output generation
├─────────────────────────────────────┤
│       Utils Layer (utils/)          │  ← Cross-cutting
└─────────────────────────────────────┘
```

### Project Structure

```
rhoai-security-manifest/
├── rhoai_security_manifest/      # Main package
│   ├── cli/                      # Command-line interface
│   │   ├── main.py              # Entry point & CLI setup
│   │   └── commands/            # Individual commands
│   ├── api/                     # External API clients
│   │   ├── container_catalog.py # Red Hat Container Catalog
│   │   └── security_data.py    # Security vulnerability data
│   ├── analysis/                # Core business logic
│   │   ├── orchestrator.py     # Workflow coordination
│   │   └── grading.py          # Security scoring algorithm
│   ├── database/                # Data persistence
│   │   ├── models.py           # SQLAlchemy models
│   │   ├── repository.py       # Data access layer
│   │   └── schema.py           # DB management
│   ├── reports/                 # Report generation
│   │   └── generators/
│   └── utils/                   # Shared utilities
├── tests/                       # Test suite
├── cache/                       # Local cache directory
├── logs/                        # Application logs
└── security_reports/            # Generated reports
```

## 🔄 Control Flow

### Main Workflow: Generate Command

```
User runs: osai-security-manifest generate --release 2.8.0
                    ↓
1. CLI initialization (config, logging, database)
                    ↓
2. Create SecurityAnalysisOrchestrator
                    ↓
3. orchestrator.analyze_release()
    ├── Discover containers via Red Hat API
    ├── Analyze security for each container
    ├── Grade containers (A-F scoring)
    ├── Store results in database
    └── Compile final results
                    ↓
4. Generate report (JSON/CSV/HTML/Markdown)
                    ↓
5. Display summary statistics
```

### Security Grading Algorithm

```python
# Starting score: 100 points
# Deductions:
- Critical vulnerability: -20 points
- High vulnerability: -10 points
- Medium vulnerability: -5 points
- Low vulnerability: -1 point

# Grade mapping:
- A: 90-100 points
- B: 80-89 points
- C: 70-79 points
- D: 60-69 points
- F: 0-59 points
```

## 💾 Data Model

The tool uses SQLite with SQLAlchemy ORM:

```
releases (1) ─── (*) containers (1) ─── (*) vulnerabilities
                                    └── (*) packages
```

Key tables:
- **releases**: RHOAI release versions
- **containers**: Container images in each release
- **vulnerabilities**: CVEs found in containers
- **packages**: Package-level vulnerability details

## 🌐 External Integrations

### Red Hat Container Catalog API
- **Purpose**: Discover containers in RHOAI releases
- **Endpoint**: `https://catalog.redhat.com/api/containers/v1/`
- **Operations**: Search containers, get metadata

### Red Hat Security Data API
- **Purpose**: Get vulnerability information
- **Operations**: Query CVEs, get CVSS scores, retrieve advisories

## 🛠️ Development Guide

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd rhoai-security-manifest

# Install development dependencies
make setup-dev

# Run quality checks
make pre-commit
```

### Common Development Tasks

```bash
# Run tests
make test

# Format code
make format

# Run linting
make lint

# Type checking
make type-check

# Security scan
make security

# Run in development
make run ARGS="generate --release 2.8.0"
```

### Adding New Features

#### Adding a New Report Format
1. Create generator in `reports/generators/`
2. Add format option to `generate.py`
3. Implement `_write_[format]_report()` method

#### Modifying Security Grading
1. Update `GradingCriteria` in `grading.py`
2. Adjust weights and thresholds
3. Update tests to reflect changes

#### Adding New CLI Command
1. Create file in `cli/commands/`
2. Use Click decorators for options
3. Register in `main.py` with `cli.add_command()`

## 📊 Configuration

Configuration can be customized via:
1. YAML config file: `--config /path/to/config.yaml`
2. Environment variables: `RHOAI_API_TIMEOUT=60`
3. CLI flags: `--debug`, `--quiet`

Default configuration structure:
```yaml
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

## 🧪 Testing

Run the test suite:
```bash
# All tests
make test

# With coverage
make test-cov

# Unit tests only
make test-unit

# Integration tests
make test-integration
```

## 🚀 Deployment

### PyPI Package
```bash
make build
uv publish
```

### Container Image
```bash
make docker-build
make docker-run
```

### Direct Installation
```bash
pip install git+https://github.com/your-org/rhoai-security-manifest.git
```

## 🔍 Troubleshooting

### Common Issues

1. **API Timeout Errors**
   - Increase timeout: `--config` with higher `api.timeout`
   - Use offline mode: `--offline`

2. **Database Issues**
   - Check permissions on `security_manifest.db`
   - Clear cache: `rm -rf cache/`

3. **Memory Issues with Large Releases**
   - Increase `api.max_concurrent_requests`
   - Use container filtering: `--containers notebook`

### Debug Mode

Enable detailed logging:
```bash
osai-security-manifest --debug generate --release 2.8.0
```

Check logs:
```bash
tail -f logs/security_manifest.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make pre-commit`
5. Submit a pull request

### Code Style
- Python 3.9+ type hints
- Black formatting
- Ruff linting
- Comprehensive docstrings

## 📚 For New Maintainers

### Key Files to Understand

1. **`cli/main.py`** - Entry point and CLI structure
2. **`cli/commands/generate.py`** - Main command implementation
3. **`analysis/orchestrator.py`** - Core business logic
4. **`analysis/grading.py`** - Security scoring algorithm
5. **`api/container_catalog.py`** - Container discovery
6. **`api/security_data.py`** - Vulnerability data retrieval
7. **`database/models.py`** - Data structures
8. **`utils/config.py`** - Configuration management

### Important Considerations

#### Security Best Practices
- Never store sensitive data or API keys
- Validate all inputs, especially release versions
- Handle API failures gracefully
- Log appropriately (INFO for normal, ERROR for failures)
- Test security grading changes thoroughly

#### Performance Tips
- Use async/await for API calls
- Process containers in parallel
- Maintain database indexes
- Balance cache freshness vs. performance

### Future Enhancements

The codebase is prepared for:
- Interactive TUI mode (`tui/` directory)
- Additional report formats (PDF, SARIF)
- Historical trending features
- CI/CD integration capabilities

## 📄 License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 🙏 Acknowledgments

This tool helps organizations maintain visibility into the security posture of their OpenShift AI deployments. Your contributions make a difference in keeping AI workloads secure.
