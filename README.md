RHOAI Security Manifest
=======================

A configurable script to produce a security manifest for [Red Hat OpenShift AI](https://www.redhat.com/en/products/ai/openshift-ai).

## Prerequisites

You will need to [login to Red Hat's Container Registry](https://access.redhat.com/articles/RegistryAuthentication) where the Product Images are stored.

This script requires the following tools to be installed:
- [podman](https://podman.io/) - Container runtime
- [jq](https://jqlang.github.io/jq/) - JSON processor
- [awk](https://www.gnu.org/software/gawk/) - Text processing tool

## Usage

### Basic Usage

Run with default settings (RHOAI version 2.22.0):
```bash
./rhoai_security_manifest.sh
```

### Command Line Options

```bash
./rhoai_security_manifest.sh [OPTIONS]

OPTIONS:
    -v, --version VERSION       RHOAI version (default: 2.22.0)
    -r, --registry URL          Registry URL (default: registry.redhat.io/redhat/redhat-operator-index)
    -o, --openshift VERSION     OpenShift version (default: v4.18)
    -p, --operator NAME         Operator name (default: rhods-operator)
    -f, --output FILE           Output filename (default: rhoai-{version})
    --check-deps                Check dependencies only and exit
    --verbose                   Enable verbose output with tool version information
    -h, --help                  Show help message
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

- `RHOAI_VERSION` - RHOAI version to generate manifest for
- `REGISTRY_URL` - Container registry base URL
- `OPENSHIFT_VERSION` - OpenShift version for operator index
- `OPERATOR_NAME` - Name of the operator to query
- `OUTPUT_FILE` - Output filename for the manifest

### Examples

#### Generate manifest for a different RHOAI version:
```bash
./rhoai_security_manifest.sh --version 2.23.0
```

#### Use a custom registry and output file:
```bash
./rhoai_security_manifest.sh --registry my-registry.com/operator-index --output my-manifest.txt
```

#### Use environment variables:
```bash
RHOAI_VERSION=2.21.0 OUTPUT_FILE=custom.txt ./rhoai_security_manifest.sh
```

#### Generate manifest for OpenShift 4.17:
```bash
./rhoai_security_manifest.sh --openshift v4.17 --version 2.21.0
```

## Output

The script generates a text file containing container image URLs that are part of the specified RHOAI version. The default output filename follows the pattern `rhoai-{version}` (e.g., `rhoai-2220` for version 2.22.0).

## Configuration Priority

Settings are applied in the following order (later values override earlier ones):
1. Default values
2. Environment variables
3. Command line arguments
