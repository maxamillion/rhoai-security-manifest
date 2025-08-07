#!/bin/bash

# RHOAI Security Manifest Generator
# Generates a security manifest for Red Hat OpenShift AI

set -euo pipefail

# Configuration variables with defaults
RHOAI_VERSION="${RHOAI_VERSION:-2.22.0}"
REGISTRY_URL="${REGISTRY_URL:-registry.redhat.io/redhat/redhat-operator-index}"
OPENSHIFT_VERSION="${OPENSHIFT_VERSION:-v4.18}"
OPERATOR_NAME="${OPERATOR_NAME:-rhods-operator}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
VERBOSE="${VERBOSE:-false}"
CHECK_DEPS_ONLY="${CHECK_DEPS_ONLY:-false}"

# Function to display usage information
fn_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate a security manifest for Red Hat OpenShift AI.

OPTIONS:
    -v, --version VERSION       RHOAI version (default: ${RHOAI_VERSION})
    -r, --registry URL          Registry URL (default: ${REGISTRY_URL})
    -o, --openshift VERSION     OpenShift version (default: ${OPENSHIFT_VERSION})
    -p, --operator NAME         Operator name (default: ${OPERATOR_NAME})
    -f, --output FILE           Output filename (default: rhoai-\${version_formatted})
    --check-deps                Check dependencies only and exit
    --verbose                   Enable verbose output
    -h, --help                  Show this help message

ENVIRONMENT VARIABLES:
    RHOAI_VERSION              Same as --version
    REGISTRY_URL               Same as --registry
    OPENSHIFT_VERSION          Same as --openshift
    OPERATOR_NAME              Same as --operator
    OUTPUT_FILE                Same as --output
    VERBOSE                    Same as --verbose (true/false)

EXAMPLES:
    # Use defaults
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
    
    if command -v dnf &> /dev/null; then
        pkg_manager="dnf"
        install_cmd="sudo dnf install"
    elif command -v yum &> /dev/null; then
        pkg_manager="yum"
        install_cmd="sudo yum install"
    elif command -v apt &> /dev/null; then
        pkg_manager="apt"
        install_cmd="sudo apt update && sudo apt install"
    elif command -v brew &> /dev/null; then
        pkg_manager="brew"
        install_cmd="brew install"
    elif command -v pacman &> /dev/null; then
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
            "jq")
                if [[ -n "$pkg_manager" ]]; then
                    echo "  $install_cmd jq" >&2
                fi
                echo "  Or visit: https://jqlang.github.io/jq/download/" >&2
                ;;
            "awk"|"tr"|"wc"|"cat"|"echo")
                echo "  Part of coreutils package:" >&2
                if [[ -n "$pkg_manager" ]]; then
                    case "$pkg_manager" in
                        "dnf"|"yum")
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
    local critical_tools=("podman" "jq" "awk" "tr" "wc")
    
    # Basic tools - usually available, but good to check
    local basic_tools=("cat" "echo")
    
    # Check critical dependencies
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_critical+=("$tool")
            all_tools_available=false
        fi
    done
    
    # Check basic dependencies
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_basic+=("$tool")
        fi
    done
    
    # Report missing tools
    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        echo "Error: Missing critical dependencies: ${missing_critical[*]}" >&2
        echo "The script cannot function without these tools." >&2
        fn_provide_installation_guidance "${missing_critical[@]}"
        exit 1
    fi
    
    if [[ ${#missing_basic[@]} -gt 0 ]]; then
        echo "Warning: Missing basic tools: ${missing_basic[*]}" >&2
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
    local tools_with_version=("podman" "jq")
    
    for tool in "${tools_with_version[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version=""
            case "$tool" in
                "podman")
                    version=$(podman --version 2>/dev/null | head -n1 || echo "unknown")
                    ;;
                "jq")
                    version=$(jq --version 2>/dev/null || echo "unknown")
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
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--version)
                RHOAI_VERSION="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY_URL="$2"
                shift 2
                ;;
            -o|--openshift)
                OPENSHIFT_VERSION="$2"
                shift 2
                ;;
            -p|--operator)
                OPERATOR_NAME="$2"
                shift 2
                ;;
            -f|--output)
                OUTPUT_FILE="$2"
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
            -h|--help)
                fn_usage
                exit 0
                ;;
            *)
                echo "Error: Unknown option $1" >&2
                echo "Use --help for usage information." >&2
                exit 1
                ;;
        esac
    done
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
}

# Function to generate output filename if not provided
fn_generate_output_filename() {
    if [[ -z "$OUTPUT_FILE" ]]; then
        # Convert version format for filename (e.g., 2.22.0 -> 2220)
        local version_formatted=$(echo "$RHOAI_VERSION" | tr -d '.')
        OUTPUT_FILE="rhoai-${version_formatted}"
    fi
}

# Main function to generate the security manifest
fn_generate_manifest() {
    echo "Generating RHOAI security manifest..."
    echo "Version: $RHOAI_VERSION"
    echo "Registry: $REGISTRY_URL:$OPENSHIFT_VERSION"
    echo "Operator: $OPERATOR_NAME"
    echo "Output: $OUTPUT_FILE"
    echo ""
    
    local full_registry_url="${REGISTRY_URL}:${OPENSHIFT_VERSION}"
    
    # Generate the catalog and extract images
    catalog=$(podman run --rm -it --entrypoint bash "$full_registry_url" -c "cat /configs/${OPERATOR_NAME}/catalog.json")
    
    if [[ -z "$catalog" ]]; then
        echo "Error: Failed to retrieve catalog from registry" >&2
        exit 1
    fi
    
    echo "$catalog" | tr -d '\000-\037' | \
        jq -r --arg operator "$OPERATOR_NAME" --arg version "$RHOAI_VERSION" \
        'select(.schema=="olm.bundle") | 
         select(.name==($operator + "." + $version)) | 
         .relatedImages[] | 
         if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end' | \
        awk '{ print $2 }' > "$OUTPUT_FILE"
    
    if [[ $? -eq 0 ]]; then
        echo "Security manifest generated successfully: $OUTPUT_FILE"
        echo "Total images found: $(wc -l < "$OUTPUT_FILE")"
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
    fn_generate_manifest
}

# Run main function with all arguments
fn_main "$@"
