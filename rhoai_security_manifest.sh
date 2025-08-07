#!/bin/bash

# RHOAI Security Manifest Generator
# Generates a security manifest for Red Hat OpenShift AI

set -euo pipefail

# Global error tracking
ERRORS_ENCOUNTERED=0
WARNINGS_ENCOUNTERED=0

# Function to log errors and warnings
fn_log_error() {
    echo "ERROR: $1" >&2
    ERRORS_ENCOUNTERED=$((ERRORS_ENCOUNTERED + 1))
}

fn_log_warning() {
    echo "WARNING: $1" >&2
    WARNINGS_ENCOUNTERED=$((WARNINGS_ENCOUNTERED + 1))
}

fn_log_info() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo "INFO: $1" >&2
    fi
}

# Function to handle cleanup on exit
fn_cleanup_on_exit() {
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        fn_log_error "Script exited with code $exit_code"

        if [[ $ERRORS_ENCOUNTERED -gt 0 ]]; then
            echo "Total errors encountered: $ERRORS_ENCOUNTERED" >&2
        fi

        if [[ $WARNINGS_ENCOUNTERED -gt 0 ]]; then
            echo "Total warnings encountered: $WARNINGS_ENCOUNTERED" >&2
        fi

        # Clean up any temporary files or processes
        jobs -p | xargs -r kill 2>/dev/null || true
    fi
}

# Set up exit handler
trap fn_cleanup_on_exit EXIT

# Configuration variables with defaults
RHOAI_VERSION="${RHOAI_VERSION:-2.22.0}"
REGISTRY_URL="${REGISTRY_URL:-registry.redhat.io/redhat/redhat-operator-index}"
OPENSHIFT_VERSION="${OPENSHIFT_VERSION:-v4.18}"
OPERATOR_NAME="${OPERATOR_NAME:-rhods-operator}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
VERBOSE="${VERBOSE:-false}"
CHECK_DEPS_ONLY="${CHECK_DEPS_ONLY:-false}"
GITHUB_BASE_URL="${GITHUB_BASE_URL:-https://raw.githubusercontent.com/red-hat-data-services/rhoai-disconnected-install-helper/main}"

# Security scanning configuration
SECURITY_SCAN="${SECURITY_SCAN:-false}"
SBOM_ONLY="${SBOM_ONLY:-false}"
VULN_ONLY="${VULN_ONLY:-false}"
SCAN_FORMAT="${SCAN_FORMAT:-json}"
FAIL_ON_SEVERITY="${FAIL_ON_SEVERITY:-}"
PARALLEL_SCAN="${PARALLEL_SCAN:-3}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

# Function to display usage information
fn_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Generate a security manifest for Red Hat OpenShift AI.
Automatically fetches images from both Red Hat registry and GitHub disconnected helper manifests.
Optionally performs comprehensive security scanning with SBOM generation and vulnerability analysis.

OPTIONS:
    -v, --version VERSION       RHOAI version (default: ${RHOAI_VERSION})
    -r, --registry URL          Registry URL (default: ${REGISTRY_URL})
    -o, --openshift VERSION     OpenShift version (default: ${OPENSHIFT_VERSION})
    -p, --operator NAME         Operator name (default: ${OPERATOR_NAME})
    -f, --output FILE           Output filename (default: rhoai-\${version_formatted})
    -d, --output-dir DIR        Output directory for reports (default: ./output)
    --check-deps                Check dependencies only and exit
    --verbose                   Enable verbose output
    -h, --help                  Show this help message

SECURITY SCANNING OPTIONS:
    --security-scan             Enable comprehensive security scanning (SBOM + vulnerabilities)
    --sbom-only                 Generate SBOMs only (no vulnerability scanning)
    --vuln-only                 Vulnerability scanning only (requires existing SBOMs)
    --scan-format FORMAT        Output format for security reports (json|sarif|table) (default: ${SCAN_FORMAT})
    --fail-on SEVERITY         Exit with error if vulnerabilities >= severity found (critical|high|medium|low)
    --parallel-scan N           Number of parallel scanning processes (default: ${PARALLEL_SCAN})

ENVIRONMENT VARIABLES:
    RHOAI_VERSION              Same as --version
    REGISTRY_URL               Same as --registry
    OPENSHIFT_VERSION          Same as --openshift
    OPERATOR_NAME              Same as --operator
    OUTPUT_FILE                Same as --output
    OUTPUT_DIR                 Same as --output-dir
    VERBOSE                    Same as --verbose (true/false)
    GITHUB_BASE_URL            GitHub repository base URL for manifests
    SECURITY_SCAN              Same as --security-scan (true/false)
    SBOM_ONLY                  Same as --sbom-only (true/false)
    VULN_ONLY                  Same as --vuln-only (true/false)
    SCAN_FORMAT                Same as --scan-format
    FAIL_ON_SEVERITY           Same as --fail-on
    PARALLEL_SCAN              Same as --parallel-scan

EXAMPLES:
    # Use defaults (fetches from both registry and GitHub)
    $0

    # Check dependencies only
    $0 --check-deps

    # Verbose mode with dependency information
    $0 --verbose --check-deps

    # Specify RHOAI version
    $0 --version 2.23.0

    # Use custom registry and output file
    $0 --registry my-registry.com/operator-index --output my-manifest.txt

    # Use environment variables
    RHOAI_VERSION=2.21.0 OUTPUT_FILE=custom.txt $0

    # Generate manifest with verbose output
    $0 --version 2.23.0 --verbose

    # Use custom GitHub repository
    GITHUB_BASE_URL=https://raw.githubusercontent.com/my-org/my-repo/main $0

SECURITY SCANNING EXAMPLES:
    # Generate manifest with comprehensive security scanning
    $0 --version 2.23.0 --security-scan

    # Generate only SBOMs without vulnerability scanning
    $0 --version 2.23.0 --sbom-only

    # Perform vulnerability scanning on existing SBOMs
    $0 --version 2.23.0 --vuln-only

    # Security scan with custom output format and directory
    $0 --security-scan --scan-format sarif --output-dir /tmp/security-reports

    # Fail build on critical vulnerabilities with parallel processing
    $0 --security-scan --fail-on critical --parallel-scan 5

    # Generate security report in table format for human review
    $0 --security-scan --scan-format table --verbose

EOF
}

# Function to provide installation guidance for missing tools
fn_provide_installation_guidance() {
    local missing_tools=("$@")

    echo "" >&2
    echo "Installation guidance:" >&2

    # Detect package manager and OS
    local pkg_manager=""
    local install_cmd=""

    if command -v dnf &>/dev/null; then
        pkg_manager="dnf"
        install_cmd="sudo dnf install"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
        install_cmd="sudo yum install"
    elif command -v apt &>/dev/null; then
        pkg_manager="apt"
        install_cmd="sudo apt update && sudo apt install"
    elif command -v brew &>/dev/null; then
        pkg_manager="brew"
        install_cmd="brew install"
    elif command -v pacman &>/dev/null; then
        pkg_manager="pacman"
        install_cmd="sudo pacman -S"
    fi

    for tool in "${missing_tools[@]}"; do
        echo "• $tool:" >&2
        case "$tool" in
        "podman")
            if [[ -n "$pkg_manager" ]]; then
                echo "  $install_cmd podman" >&2
            fi
            echo "  Or visit: https://podman.io/getting-started/installation" >&2
            ;;
        "curl")
            if [[ -n "$pkg_manager" ]]; then
                echo "  $install_cmd curl" >&2
            fi
            echo "  Or visit: https://curl.se/download.html" >&2
            ;;
        "jq")
            if [[ -n "$pkg_manager" ]]; then
                echo "  $install_cmd jq" >&2
            fi
            echo "  Or visit: https://jqlang.github.io/jq/download/" >&2
            ;;
        "syft")
            echo "  Install via script: curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin" >&2
            if [[ "$pkg_manager" == "brew" ]]; then
                echo "  Or via Homebrew: brew install syft" >&2
            fi
            echo "  Or visit: https://github.com/anchore/syft" >&2
            ;;
        "grype")
            echo "  Install via script: curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin" >&2
            if [[ "$pkg_manager" == "brew" ]]; then
                echo "  Or via Homebrew: brew tap anchore/grype && brew install grype" >&2
            fi
            echo "  Or visit: https://github.com/anchore/grype" >&2
            ;;
        "awk" | "tr" | "wc" | "cat" | "echo")
            echo "  Part of coreutils package:" >&2
            if [[ -n "$pkg_manager" ]]; then
                case "$pkg_manager" in
                "dnf" | "yum")
                    echo "  $install_cmd coreutils" >&2
                    ;;
                "apt")
                    echo "  $install_cmd coreutils" >&2
                    ;;
                "brew")
                    echo "  $install_cmd coreutils" >&2
                    ;;
                "pacman")
                    echo "  $install_cmd coreutils" >&2
                    ;;
                esac
            fi
            ;;
        *)
            if [[ -n "$pkg_manager" ]]; then
                echo "  $install_cmd $tool" >&2
            fi
            ;;
        esac
    done

    echo "" >&2
}

# Function to validate dependencies
fn_validate_dependencies() {
    local missing_critical=()
    local missing_basic=()
    local all_tools_available=true

    # Critical tools - script cannot function without these
    local critical_tools=("podman" "jq" "awk" "tr" "wc" "curl")

    # Security scanning tools - required when security scanning is enabled
    local security_tools=("syft" "grype")

    # Basic tools - usually available, but good to check
    local basic_tools=("cat" "echo")

    # Check critical dependencies
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_critical+=("$tool")
            all_tools_available=false
        fi
    done

    # Check security scanning tools if security scanning is enabled
    if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" || "$VULN_ONLY" == "true" ]]; then
        for tool in "${security_tools[@]}"; do
            if ! command -v "$tool" &>/dev/null; then
                missing_critical+=("$tool")
                all_tools_available=false
            fi
        done
    fi

    # Check basic dependencies
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_basic+=("$tool")
        fi
    done

    # Report missing tools
    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        fn_log_error "Missing critical dependencies: ${missing_critical[*]}"
        echo "The script cannot function without these tools." >&2
        fn_provide_installation_guidance "${missing_critical[@]}"
        exit 1
    fi

    if [[ ${#missing_basic[@]} -gt 0 ]]; then
        fn_log_warning "Missing basic tools: ${missing_basic[*]}"
        echo "These are usually pre-installed. If you encounter issues, please install them." >&2
    fi

    # Optional: Show success message and version info in verbose mode
    if [[ "${VERBOSE:-}" == "true" ]]; then
        echo "✓ All required dependencies are available"
        fn_check_tool_versions
    fi
}

# Function to check and display tool versions (verbose mode only)
fn_check_tool_versions() {
    echo ""
    echo "Tool versions:"

    # Check versions for tools that support --version
    local tools_with_version=("podman" "jq" "curl")

    # Add security tools if they are available
    if command -v syft &>/dev/null; then
        tools_with_version+=("syft")
    fi
    if command -v grype &>/dev/null; then
        tools_with_version+=("grype")
    fi

    for tool in "${tools_with_version[@]}"; do
        if command -v "$tool" &>/dev/null; then
            local version=""
            case "$tool" in
            "podman")
                version=$(podman --version 2>/dev/null | head -n1 || echo "unknown")
                ;;
            "jq")
                version=$(jq --version 2>/dev/null || echo "unknown")
                ;;
            "curl")
                version=$(curl --version 2>/dev/null | head -n1 || echo "unknown")
                ;;
            "syft")
                version=$(syft --version 2>/dev/null || echo "unknown")
                ;;
            "grype")
                version=$(grype --version 2>/dev/null || echo "unknown")
                ;;
            esac
            echo "  $tool: $version"
        fi
    done

    # Basic tools typically don't have meaningful version info
    echo "  Core utilities (awk, tr, wc, cat, echo): part of system coreutils"
    echo ""
}

# Function to parse command line arguments
fn_parse_arguments() {
    if [[ "$VERBOSE" == "true" ]]; then
        fn_log_info "Parsing arguments: $*"
    fi
    
    while [[ $# -gt 0 ]]; do
        # Skip potential file descriptor arguments that may come from shell redirection
        if [[ "$1" =~ ^[0-9]$ ]]; then
            fn_log_warning "Skipping suspected file descriptor argument: $1"
            shift
            continue
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            fn_log_info "Processing argument: $1"
        fi
        
        case $1 in
        -v | --version)
            RHOAI_VERSION="$2"
            shift 2
            ;;
        -r | --registry)
            REGISTRY_URL="$2"
            shift 2
            ;;
        -o | --openshift)
            OPENSHIFT_VERSION="$2"
            shift 2
            ;;
        -p | --operator)
            OPERATOR_NAME="$2"
            shift 2
            ;;
        -f | --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -d | --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --check-deps)
            CHECK_DEPS_ONLY="true"
            shift
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --security-scan)
            SECURITY_SCAN="true"
            shift
            ;;
        --sbom-only)
            SBOM_ONLY="true"
            shift
            ;;
        --vuln-only)
            VULN_ONLY="true"
            shift
            ;;
        --scan-format)
            SCAN_FORMAT="$2"
            shift 2
            ;;
        --fail-on)
            FAIL_ON_SEVERITY="$2"
            shift 2
            ;;
        --parallel-scan)
            PARALLEL_SCAN="$2"
            shift 2
            ;;
        -h | --help)
            fn_usage
            exit 0
            ;;
        *)
            fn_log_error "Unknown option: '$1'"
            echo "Received arguments: $*" >&2
            echo "Use --help for usage information." >&2
            exit 1
            ;;
        esac
    done
    
    if [[ "$VERBOSE" == "true" ]]; then
        fn_log_info "Argument parsing completed successfully"
    fi
}

# Function to validate inputs
fn_validate_inputs() {
    if [[ ! "$RHOAI_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid RHOAI version format. Expected format: X.Y.Z (e.g., 2.22.0)" >&2
        exit 1
    fi

    if [[ ! "$OPENSHIFT_VERSION" =~ ^v[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid OpenShift version format. Expected format: vX.Y (e.g., v4.18)" >&2
        exit 1
    fi

    if [[ -z "$OPERATOR_NAME" ]]; then
        echo "Error: Operator name cannot be empty" >&2
        exit 1
    fi

    if [[ -z "$REGISTRY_URL" ]]; then
        echo "Error: Registry URL cannot be empty" >&2
        exit 1
    fi

    # Validate security scanning options
    if [[ -n "$SCAN_FORMAT" && ! "$SCAN_FORMAT" =~ ^(json|sarif|table)$ ]]; then
        echo "Error: Invalid scan format. Must be one of: json, sarif, table" >&2
        exit 1
    fi

    if [[ -n "$FAIL_ON_SEVERITY" && ! "$FAIL_ON_SEVERITY" =~ ^(critical|high|medium|low)$ ]]; then
        echo "Error: Invalid fail-on severity. Must be one of: critical, high, medium, low" >&2
        exit 1
    fi

    if [[ -n "$PARALLEL_SCAN" && ! "$PARALLEL_SCAN" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: Parallel scan count must be a positive integer" >&2
        exit 1
    fi

    # Validate conflicting options
    local scan_options_count=0
    [[ "$SECURITY_SCAN" == "true" ]] && scan_options_count=$((scan_options_count + 1))
    [[ "$SBOM_ONLY" == "true" ]] && scan_options_count=$((scan_options_count + 1))
    [[ "$VULN_ONLY" == "true" ]] && scan_options_count=$((scan_options_count + 1))

    if [[ $scan_options_count -gt 1 ]]; then
        echo "Error: Only one of --security-scan, --sbom-only, or --vuln-only can be specified" >&2
        exit 1
    fi
}

# Function to fetch GitHub manifest for a given version
fn_fetch_github_manifest() {
    local version="$1"
    local temp_file
    temp_file=$(mktemp)

    # Try different version formats for GitHub lookup
    local version_patterns=()

    # Add the exact version
    version_patterns+=("$version")

    # If version ends with .0, try without it (e.g., 2.22.0 -> 2.22)
    if [[ "$version" =~ ^([0-9]+\.[0-9]+)\.0$ ]]; then
        version_patterns+=("${BASH_REMATCH[1]}")
    fi

    for pattern in "${version_patterns[@]}"; do
        local github_url="${GITHUB_BASE_URL}/rhoai-${pattern}.md"

        if [[ "$VERBOSE" == "true" ]]; then
            echo "Attempting to fetch GitHub manifest: $github_url" >&2
        fi

        # Use curl with timeout and follow redirects
        if curl -s -f -L --max-time 30 "$github_url" >"$temp_file" 2>/dev/null; then
            local file_size
            file_size=$(wc -l <"$temp_file")

            if [[ "$file_size" -gt 0 ]]; then
                if [[ "$VERBOSE" == "true" ]]; then
                    echo "✓ Successfully fetched GitHub manifest ($file_size lines)" >&2
                fi
                echo "$temp_file"
                return 0
            fi
        fi

        if [[ "$VERBOSE" == "true" ]]; then
            echo "✗ Failed to fetch: $github_url" >&2
        fi
    done

    # Clean up temp file if all attempts failed
    rm -f "$temp_file"
    return 1
}

# Function to parse container images from GitHub manifest
fn_parse_github_images() {
    local manifest_file="$1"
    local temp_images
    temp_images=$(mktemp)

    # Extract container image references from the markdown file
    # Look for lines containing registry URLs and extract the image reference
    grep -E "(registry\.redhat\.io|quay\.io)" "$manifest_file" |
        grep -oE "(registry\.redhat\.io|quay\.io)/[^[:space:]]*" |
        sed 's/[[:space:]]*$//' |
        sort | uniq >"$temp_images"

    if [[ "$VERBOSE" == "true" ]]; then
        local image_count
        image_count=$(wc -l <"$temp_images")
        echo "Parsed $image_count unique images from GitHub manifest" >&2
    fi

    echo "$temp_images"
}

# Function to merge and deduplicate images from multiple sources
fn_merge_and_deduplicate() {
    local registry_file="$1"
    local github_file="$2"
    local output_file="$3"

    # Create header with source information
    {
        echo "# RHOAI Security Manifest - Version $RHOAI_VERSION"
        echo "# Generated on $(date)"
        echo "# Sources:"

        if [[ -f "$registry_file" ]]; then
            local registry_count
            registry_count=$(wc -l <"$registry_file")
            echo "#   - Registry: $registry_count images"
        fi

        if [[ -f "$github_file" ]]; then
            local github_count
            github_count=$(wc -l <"$github_file")
            echo "#   - GitHub manifest: $github_count images"
        fi

        echo "#"
        echo ""

        # Merge files and deduplicate
        if [[ -f "$registry_file" && -f "$github_file" ]]; then
            cat "$registry_file" "$github_file" | sort | uniq
        elif [[ -f "$registry_file" ]]; then
            cat "$registry_file"
        elif [[ -f "$github_file" ]]; then
            cat "$github_file"
        fi
    } >"$output_file"
}

# Function to generate output filename if not provided
fn_generate_output_filename() {
    if [[ -z "$OUTPUT_FILE" ]]; then
        # Convert version format for filename (e.g., 2.22.0 -> 2220)
        local version_formatted
        version_formatted=$(echo "$RHOAI_VERSION" | tr -d '.')
        OUTPUT_FILE="rhoai-${version_formatted}"
    fi
}

# Function to setup output directory structure
fn_setup_output_directory() {
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./output"
    fi

    # Create output directory structure
    mkdir -p "$OUTPUT_DIR" || {
        echo "Error: Cannot create output directory: $OUTPUT_DIR" >&2
        exit 1
    }

    # Create subdirectories for security scanning if enabled
    if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" || "$VULN_ONLY" == "true" ]]; then
        mkdir -p "$OUTPUT_DIR/sboms" || {
            echo "Error: Cannot create SBOM directory: $OUTPUT_DIR/sboms" >&2
            exit 1
        }

        if [[ "$SECURITY_SCAN" == "true" || "$VULN_ONLY" == "true" ]]; then
            mkdir -p "$OUTPUT_DIR/vulnerabilities" || {
                echo "Error: Cannot create vulnerabilities directory: $OUTPUT_DIR/vulnerabilities" >&2
                exit 1
            }
        fi
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        echo "Output directory structure created: $OUTPUT_DIR" >&2
    fi
}

# Function to generate SBOM for a container image
fn_generate_sbom() {
    local image="$1"
    local sbom_dir="$2"

    # Generate safe filename from image name
    local safe_name
    safe_name=$(echo "$image" | sed 's|[/:@]|_|g' | sed 's|_+|_|g')
    local sbom_file="${sbom_dir}/${safe_name}-sbom.json"

    if [[ "$VERBOSE" == "true" ]]; then
        echo "Generating SBOM for: $image" >&2
    fi

    # Generate SBOM using Syft with comprehensive scanning
    if syft "$image" -o syft-json --scope all-layers >"$sbom_file" 2>/dev/null; then
        if [[ "$VERBOSE" == "true" ]]; then
            local package_count
            package_count=$(jq '.artifacts | length' "$sbom_file" 2>/dev/null || echo "unknown")
            echo "✓ SBOM generated: $package_count packages found" >&2
        fi
        echo "$sbom_file"
        return 0
    else
        fn_log_warning "Failed to generate SBOM for: $image"
        rm -f "$sbom_file"
        return 1
    fi
}

# Function to scan vulnerabilities for an SBOM or image
fn_scan_vulnerabilities() {
    local input="$1" # Can be image name or SBOM file path
    local vuln_dir="$2"
    local input_type="$3" # "image" or "sbom"

    # Generate safe filename from input
    local safe_name
    if [[ "$input_type" == "sbom" ]]; then
        safe_name=$(basename "$input" .json | sed 's|-sbom$||')
    else
        safe_name=$(echo "$input" | sed 's|[/:@]|_|g' | sed 's|_+|_|g')
    fi

    local vuln_file="${vuln_dir}/${safe_name}-vulnerabilities.${SCAN_FORMAT}"

    if [[ "$VERBOSE" == "true" ]]; then
        if [[ "$input_type" == "sbom" ]]; then
            echo "Scanning vulnerabilities for SBOM: $(basename "$input")" >&2
        else
            echo "Scanning vulnerabilities for image: $input" >&2
        fi
    fi

    # Prepare Grype command based on input type and format
    local grype_cmd="grype"
    local grype_input="$input"

    if [[ "$input_type" == "sbom" ]]; then
        grype_input="sbom:$input"
    fi

    # Add output format
    grype_cmd="$grype_cmd $grype_input -o $SCAN_FORMAT"

    # Add scope for comprehensive scanning
    if [[ "$input_type" == "image" ]]; then
        grype_cmd="$grype_cmd --scope all-layers"
    fi

    # Execute vulnerability scan
    if eval "$grype_cmd" >"$vuln_file" 2>/dev/null; then
        if [[ "$VERBOSE" == "true" ]]; then
            local vuln_count="unknown"
            if [[ "$SCAN_FORMAT" == "json" ]]; then
                vuln_count=$(jq '.matches | length' "$vuln_file" 2>/dev/null || echo "unknown")
            elif [[ "$SCAN_FORMAT" == "table" ]]; then
                vuln_count=$(grep -c "^[^NAME]" "$vuln_file" 2>/dev/null || echo "unknown")
            fi
            echo "✓ Vulnerability scan completed: $vuln_count vulnerabilities found" >&2
        fi

        # Check for fail conditions
        if [[ -n "$FAIL_ON_SEVERITY" ]]; then
            fn_check_fail_condition "$vuln_file" "$FAIL_ON_SEVERITY"
        fi

        echo "$vuln_file"
        return 0
    else
        fn_log_warning "Failed to scan vulnerabilities for: $input"
        rm -f "$vuln_file"
        return 1
    fi
}

# Function to check fail condition based on vulnerability severity
fn_check_fail_condition() {
    local vuln_file="$1"
    local fail_severity="$2"

    if [[ ! -f "$vuln_file" || "$SCAN_FORMAT" != "json" ]]; then
        return 0 # Skip check if file doesn't exist or not JSON format
    fi

    local critical_count high_count medium_count low_count
    critical_count=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$vuln_file" 2>/dev/null || echo "0")
    high_count=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$vuln_file" 2>/dev/null || echo "0")
    medium_count=$(jq '[.matches[] | select(.vulnerability.severity == "Medium")] | length' "$vuln_file" 2>/dev/null || echo "0")
    low_count=$(jq '[.matches[] | select(.vulnerability.severity == "Low")] | length' "$vuln_file" 2>/dev/null || echo "0")

    case "$fail_severity" in
    "critical")
        if [[ $critical_count -gt 0 ]]; then
            fn_log_error "FAIL: Found $critical_count critical vulnerabilities"
            exit 1
        fi
        ;;
    "high")
        if [[ $critical_count -gt 0 || $high_count -gt 0 ]]; then
            fn_log_error "FAIL: Found $critical_count critical and $high_count high severity vulnerabilities"
            exit 1
        fi
        ;;
    "medium")
        if [[ $critical_count -gt 0 || $high_count -gt 0 || $medium_count -gt 0 ]]; then
            fn_log_error "FAIL: Found vulnerabilities: $critical_count critical, $high_count high, $medium_count medium"
            exit 1
        fi
        ;;
    "low")
        local total_count=$((critical_count + high_count + medium_count + low_count))
        if [[ $total_count -gt 0 ]]; then
            fn_log_error "FAIL: Found $total_count total vulnerabilities"
            exit 1
        fi
        ;;
    esac
}

# Function to process images in parallel
fn_process_images_parallel() {
    local images_file="$1"
    local processing_type="$2" # "sbom", "vuln", or "both"
    local sbom_dir="$3"
    local vuln_dir="$4"

    if [[ ! -f "$images_file" ]]; then
        fn_log_error "Images file not found: $images_file"
        return 1
    fi

    # Count total images (excluding comments and empty lines)
    local total_images
    total_images=$(grep -v '^#' "$images_file" | grep -v '^$' | wc -l)

    if [[ $total_images -eq 0 ]]; then
        fn_log_warning "No images found to process"
        return 0
    fi

    echo "Processing $total_images images with up to $PARALLEL_SCAN parallel processes..."

    local processed=0
    local successful=0
    local failed=0

    # Process images in parallel using background processes
    while IFS= read -r image; do
        # Skip comments and empty lines
        [[ "$image" =~ ^#.*$ || -z "$image" ]] && continue

        # Wait if we've reached the parallel limit
        while [[ $(jobs -r | wc -l) -ge $PARALLEL_SCAN ]]; do
            sleep 0.1
        done

        # Process image in background
        {
            local image_success=true

            if [[ "$processing_type" == "sbom" || "$processing_type" == "both" ]]; then
                if ! fn_generate_sbom "$image" "$sbom_dir" >/dev/null; then
                    image_success=false
                fi
            fi

            if [[ "$processing_type" == "vuln" && "$image_success" == "true" ]]; then
                if ! fn_scan_vulnerabilities "$image" "$vuln_dir" "image" >/dev/null; then
                    image_success=false
                fi
            elif [[ "$processing_type" == "both" && "$image_success" == "true" ]]; then
                # For comprehensive scanning, use the generated SBOM
                local safe_name
                safe_name=$(echo "$image" | sed 's|[/:@]|_|g' | sed 's|_+|_|g')
                local sbom_file="${sbom_dir}/${safe_name}-sbom.json"

                if [[ -f "$sbom_file" ]]; then
                    if ! fn_scan_vulnerabilities "$sbom_file" "$vuln_dir" "sbom" >/dev/null; then
                        image_success=false
                    fi
                else
                    image_success=false
                fi
            fi

            # Report result
            if [[ "$image_success" == "true" ]]; then
                echo "SUCCESS:$image"
            else
                echo "FAILED:$image"
            fi
        } &

        processed=$((processed + 1))

        if [[ "$VERBOSE" == "true" && $((processed % 10)) -eq 0 ]]; then
            echo "Queued $processed/$total_images images for processing..." >&2
        fi

    done <"$images_file"

    # Wait for all background processes to complete
    echo "Waiting for all scanning processes to complete..."
    wait

    # Count results (this is a simple approach - in production you'd want more robust tracking)
    successful=$(jobs -p | wc -l)
    failed=$((total_images - successful))

    echo "Processing completed: $successful successful, $failed failed"

    if [[ $failed -gt 0 ]]; then
        fn_log_warning "$failed images failed to process"
    fi

    return 0
}

# Function to generate comprehensive security report
fn_generate_security_report() {
    local images_file="$1"
    local sbom_dir="$2"
    local vuln_dir="$3"
    local report_file="$4"

    local version_formatted
    version_formatted=$(echo "$RHOAI_VERSION" | tr -d '.')

    echo "Generating comprehensive security report..."

    # Initialize report structure
    {
        echo "{"
        echo "  \"metadata\": {"
        echo "    \"report_type\": \"rhoai_security_analysis\","
        echo "    \"rhoai_version\": \"$RHOAI_VERSION\","
        echo "    \"generated_at\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "    \"scan_format\": \"$SCAN_FORMAT\","
        echo "    \"total_images\": $(grep -v '^#' "$images_file" | grep -v '^$' | wc -l)"
        echo "  },"
        echo "  \"summary\": {"

        # Calculate summary statistics
        local total_vulnerabilities=0
        local critical_vulnerabilities=0
        local high_vulnerabilities=0
        local medium_vulnerabilities=0
        local low_vulnerabilities=0
        local images_with_vulnerabilities=0
        local total_packages=0

        if [[ -d "$vuln_dir" && "$SCAN_FORMAT" == "json" ]]; then
            for vuln_file in "$vuln_dir"/*.json; do
                [[ -f "$vuln_file" ]] || continue

                local file_vulns
                file_vulns=$(jq '.matches | length' "$vuln_file" 2>/dev/null || echo "0")
                total_vulnerabilities=$((total_vulnerabilities + file_vulns))

                if [[ $file_vulns -gt 0 ]]; then
                    images_with_vulnerabilities=$((images_with_vulnerabilities + 1))
                fi

                local critical_count high_count medium_count low_count
                critical_count=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$vuln_file" 2>/dev/null || echo "0")
                high_count=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$vuln_file" 2>/dev/null || echo "0")
                medium_count=$(jq '[.matches[] | select(.vulnerability.severity == "Medium")] | length' "$vuln_file" 2>/dev/null || echo "0")
                low_count=$(jq '[.matches[] | select(.vulnerability.severity == "Low")] | length' "$vuln_file" 2>/dev/null || echo "0")

                critical_vulnerabilities=$((critical_vulnerabilities + critical_count))
                high_vulnerabilities=$((high_vulnerabilities + high_count))
                medium_vulnerabilities=$((medium_vulnerabilities + medium_count))
                low_vulnerabilities=$((low_vulnerabilities + low_count))
            done
        fi

        if [[ -d "$sbom_dir" ]]; then
            for sbom_file in "$sbom_dir"/*.json; do
                [[ -f "$sbom_file" ]] || continue

                local file_packages
                file_packages=$(jq '.artifacts | length' "$sbom_file" 2>/dev/null || echo "0")
                total_packages=$((total_packages + file_packages))
            done
        fi

        echo "    \"total_vulnerabilities\": $total_vulnerabilities,"
        echo "    \"critical_vulnerabilities\": $critical_vulnerabilities,"
        echo "    \"high_vulnerabilities\": $high_vulnerabilities,"
        echo "    \"medium_vulnerabilities\": $medium_vulnerabilities,"
        echo "    \"low_vulnerabilities\": $low_vulnerabilities,"
        echo "    \"images_with_vulnerabilities\": $images_with_vulnerabilities,"
        echo "    \"total_packages\": $total_packages"
        echo "  },"
        echo "  \"scan_results\": ["

        # Include individual scan results
        local first_result=true
        while IFS= read -r image; do
            # Skip comments and empty lines
            [[ "$image" =~ ^#.*$ || -z "$image" ]] && continue

            local safe_name
            safe_name=$(echo "$image" | sed 's|[/:@]|_|g' | sed 's|_+|_|g')

            local sbom_file="${sbom_dir}/${safe_name}-sbom.json"
            local vuln_file="${vuln_dir}/${safe_name}-vulnerabilities.json"

            if [[ "$first_result" == "false" ]]; then
                echo "    ,"
            fi
            first_result=false

            echo "    {"
            echo "      \"image\": \"$image\","
            echo "      \"sbom_available\": $([ -f "$sbom_file" ] && echo "true" || echo "false"),"
            echo "      \"vulnerabilities_available\": $([ -f "$vuln_file" ] && echo "true" || echo "false")"

            if [[ -f "$sbom_file" ]]; then
                local package_count
                package_count=$(jq '.artifacts | length' "$sbom_file" 2>/dev/null || echo "0")
                echo "      ,\"package_count\": $package_count"
            fi

            if [[ -f "$vuln_file" && "$SCAN_FORMAT" == "json" ]]; then
                local vuln_count critical_count high_count medium_count low_count
                vuln_count=$(jq '.matches | length' "$vuln_file" 2>/dev/null || echo "0")
                critical_count=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$vuln_file" 2>/dev/null || echo "0")
                high_count=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$vuln_file" 2>/dev/null || echo "0")
                medium_count=$(jq '[.matches[] | select(.vulnerability.severity == "Medium")] | length' "$vuln_file" 2>/dev/null || echo "0")
                low_count=$(jq '[.matches[] | select(.vulnerability.severity == "Low")] | length' "$vuln_file" 2>/dev/null || echo "0")

                echo "      ,\"vulnerability_summary\": {"
                echo "        \"total\": $vuln_count,"
                echo "        \"critical\": $critical_count,"
                echo "        \"high\": $high_count,"
                echo "        \"medium\": $medium_count,"
                echo "        \"low\": $low_count"
                echo "      }"
            fi

            echo -n "    }"

        done <"$images_file"

        echo ""
        echo "  ]"
        echo "}"

    } >"$report_file"

    echo "✓ Comprehensive security report generated: $report_file"

    # Generate human-readable summary if verbose
    if [[ "$VERBOSE" == "true" ]]; then
        echo ""
        echo "Security Summary:"
        echo "  Total Images: $(grep -v '^#' "$images_file" | grep -v '^$' | wc -l)"
        echo "  Total Vulnerabilities: $total_vulnerabilities"
        echo "    Critical: $critical_vulnerabilities"
        echo "    High: $high_vulnerabilities"
        echo "    Medium: $medium_vulnerabilities"
        echo "    Low: $low_vulnerabilities"
        echo "  Images with Vulnerabilities: $images_with_vulnerabilities"
        echo "  Total Packages: $total_packages"
    fi
}

# Main function to generate the security manifest
fn_generate_manifest() {
    echo "Generating RHOAI security manifest..."
    echo "Version: $RHOAI_VERSION"
    echo "Registry: $REGISTRY_URL:$OPENSHIFT_VERSION"
    echo "Operator: $OPERATOR_NAME"
    echo "GitHub Source: $GITHUB_BASE_URL"
    echo "Output: $OUTPUT_FILE"

    # Show security scanning configuration if enabled
    if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" || "$VULN_ONLY" == "true" ]]; then
        echo "Security Scanning: Enabled"
        echo "  Mode: $(
            [[ "$SECURITY_SCAN" == "true" ]] && echo "Full (SBOM + Vulnerabilities)"
            [[ "$SBOM_ONLY" == "true" ]] && echo "SBOM Only"
            [[ "$VULN_ONLY" == "true" ]] && echo "Vulnerabilities Only"
        )"
        echo "  Format: $SCAN_FORMAT"
        echo "  Parallel Processes: $PARALLEL_SCAN"
        [[ -n "$FAIL_ON_SEVERITY" ]] && echo "  Fail on: $FAIL_ON_SEVERITY severity"
        echo "  Output Directory: $OUTPUT_DIR"
    fi
    echo ""

    local temp_registry_file=""
    local temp_github_file=""

    # Fetch registry images
    echo "Fetching images from registry..."

    local full_registry_url="${REGISTRY_URL}:${OPENSHIFT_VERSION}"
    temp_registry_file=$(mktemp)

    # Generate the catalog and extract images
    catalog=$(podman run --rm -it --entrypoint bash "$full_registry_url" -c "cat /configs/${OPERATOR_NAME}/catalog.json")

    if [[ -z "$catalog" ]]; then
        echo "Error: Failed to retrieve catalog from registry" >&2
        rm -f "$temp_registry_file"
        exit 1
    fi

    echo "$catalog" | tr -d '\000-\037' |
        jq -r --arg operator "$OPERATOR_NAME" --arg version "$RHOAI_VERSION" \
            'select(.schema=="olm.bundle") | 
         select(.name==($operator + "." + $version)) | 
         .relatedImages[] | 
         if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end' |
        awk '{ print $2 }' >"$temp_registry_file"

    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to generate registry manifest" >&2
        rm -f "$temp_registry_file"
        exit 1
    fi

    local registry_count
    registry_count=$(wc -l <"$temp_registry_file")
    echo "✓ Found $registry_count images from registry"

    # Fetch GitHub manifest images
    echo "Fetching images from GitHub manifest..."

    local github_manifest_file
    if github_manifest_file=$(fn_fetch_github_manifest "$RHOAI_VERSION"); then
        temp_github_file=$(fn_parse_github_images "$github_manifest_file")
        rm -f "$github_manifest_file"

        local github_count
        github_count=$(wc -l <"$temp_github_file")
        echo "✓ Found $github_count images from GitHub manifest"
    else
        echo "⚠ Warning: Could not fetch GitHub manifest for version $RHOAI_VERSION" >&2
        echo "  Continuing with registry data only..." >&2
    fi

    # Merge and deduplicate results
    echo "Merging and deduplicating image lists..."
    fn_merge_and_deduplicate "$temp_registry_file" "$temp_github_file" "$OUTPUT_FILE"

    # Clean up temporary files
    rm -f "$temp_registry_file" "$temp_github_file"

    # Report results
    if [[ -f "$OUTPUT_FILE" ]]; then
        echo "✓ Security manifest generated successfully: $OUTPUT_FILE"

        # Count total images (excluding header comments)
        local total_images
        total_images=$(grep -v '^#' "$OUTPUT_FILE" | grep -v '^$' | wc -l)
        echo "Total unique images: $total_images"

        if [[ "$VERBOSE" == "true" ]]; then
            echo ""
            echo "Manifest contents preview:"
            head -20 "$OUTPUT_FILE"
            if [[ $(wc -l <"$OUTPUT_FILE") -gt 20 ]]; then
                echo "... (showing first 20 lines)"
            fi
        fi

        # Perform security scanning if enabled
        if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" || "$VULN_ONLY" == "true" ]]; then
            echo ""
            echo "Starting security analysis..."

            # Setup output directory structure
            fn_setup_output_directory

            local version_formatted
            version_formatted=$(echo "$RHOAI_VERSION" | tr -d '.')

            # Copy manifest to output directory for consistency
            local output_manifest="$OUTPUT_DIR/rhoai-${version_formatted}-manifest.txt"
            cp "$OUTPUT_FILE" "$output_manifest"
            echo "✓ Manifest copied to: $output_manifest"

            # Determine what scanning to perform
            if [[ "$SECURITY_SCAN" == "true" ]]; then
                # Comprehensive scanning: SBOM generation + vulnerability scanning
                echo "Performing comprehensive security scanning..."
                fn_process_images_parallel "$output_manifest" "both" "$OUTPUT_DIR/sboms" "$OUTPUT_DIR/vulnerabilities"

                # Generate comprehensive security report
                local security_report="$OUTPUT_DIR/rhoai-${version_formatted}-security-report.json"
                fn_generate_security_report "$output_manifest" "$OUTPUT_DIR/sboms" "$OUTPUT_DIR/vulnerabilities" "$security_report"

            elif [[ "$SBOM_ONLY" == "true" ]]; then
                # SBOM generation only
                echo "Generating SBOMs for all images..."
                fn_process_images_parallel "$output_manifest" "sbom" "$OUTPUT_DIR/sboms" ""

                echo "✓ SBOM generation completed. Files available in: $OUTPUT_DIR/sboms"

            elif [[ "$VULN_ONLY" == "true" ]]; then
                # Vulnerability scanning only (requires existing SBOMs or scans images directly)
                echo "Performing vulnerability scanning..."

                # Check if SBOMs exist, otherwise scan images directly
                if [[ -d "$OUTPUT_DIR/sboms" && $(find "$OUTPUT_DIR/sboms" -name "*.json" | wc -l) -gt 0 ]]; then
                    echo "Using existing SBOMs for vulnerability scanning..."
                    # Process existing SBOMs for vulnerability scanning
                    for sbom_file in "$OUTPUT_DIR/sboms"/*.json; do
                        [[ -f "$sbom_file" ]] || continue

                        if [[ "$VERBOSE" == "true" ]]; then
                            echo "Scanning SBOM: $(basename "$sbom_file")"
                        fi

                        fn_scan_vulnerabilities "$sbom_file" "$OUTPUT_DIR/vulnerabilities" "sbom" >/dev/null &

                        # Limit parallel processes
                        while [[ $(jobs -r | wc -l) -ge $PARALLEL_SCAN ]]; do
                            sleep 0.1
                        done
                    done

                    # Wait for all scans to complete
                    wait
                    echo "✓ Vulnerability scanning of existing SBOMs completed"
                else
                    echo "No existing SBOMs found. Scanning images directly..."
                    fn_process_images_parallel "$output_manifest" "vuln" "" "$OUTPUT_DIR/vulnerabilities"
                fi

                # Generate vulnerability summary report
                local vuln_report="$OUTPUT_DIR/rhoai-${version_formatted}-vulnerabilities-report.json"
                fn_generate_security_report "$output_manifest" "$OUTPUT_DIR/sboms" "$OUTPUT_DIR/vulnerabilities" "$vuln_report"
            fi

            echo ""
            echo "Security analysis completed!"
            echo "Output directory: $OUTPUT_DIR"
            echo "  ├── rhoai-${version_formatted}-manifest.txt"

            if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" ]]; then
                local sbom_count=$(find "$OUTPUT_DIR/sboms" -name "*.json" 2>/dev/null | wc -l)
                echo "  ├── sboms/ ($sbom_count SBOM files)"
            fi

            if [[ "$SECURITY_SCAN" == "true" || "$VULN_ONLY" == "true" ]]; then
                local vuln_count=$(find "$OUTPUT_DIR/vulnerabilities" -name "*.$SCAN_FORMAT" 2>/dev/null | wc -l)
                echo "  ├── vulnerabilities/ ($vuln_count vulnerability reports)"
            fi

            if [[ "$SECURITY_SCAN" == "true" || "$VULN_ONLY" == "true" ]]; then
                echo "  └── rhoai-${version_formatted}-security-report.json"
            fi
        fi

    else
        echo "Error: Failed to generate security manifest" >&2
        exit 1
    fi
}

# Main execution
fn_main() {

    fn_parse_arguments "$@"
    fn_validate_dependencies

    # If only checking dependencies, exit after validation
    if [[ "$CHECK_DEPS_ONLY" == "true" ]]; then
        echo "✓ All dependencies are available. Script is ready to run."
        exit 0
    fi

    fn_validate_inputs
    fn_generate_output_filename

    # Setup output directory if security scanning is enabled
    if [[ "$SECURITY_SCAN" == "true" || "$SBOM_ONLY" == "true" || "$VULN_ONLY" == "true" ]]; then
        fn_setup_output_directory
    fi

    fn_generate_manifest
}

# Run main function with all arguments
fn_main "$@"
