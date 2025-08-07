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
GITHUB_BASE_URL="${GITHUB_BASE_URL:-https://raw.githubusercontent.com/red-hat-data-services/rhoai-disconnected-install-helper/main}"

# Function to display usage information
fn_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate a security manifest for Red Hat OpenShift AI.
Automatically fetches images from both Red Hat registry and GitHub disconnected helper manifests.

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
    GITHUB_BASE_URL            GitHub repository base URL for manifests

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
    local critical_tools=("podman" "jq" "awk" "tr" "wc" "curl")
    
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
    local tools_with_version=("podman" "jq" "curl")
    
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
                "curl")
                    version=$(curl --version 2>/dev/null | head -n1 || echo "unknown")
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
        if curl -s -f -L --max-time 30 "$github_url" > "$temp_file" 2>/dev/null; then
            local file_size
            file_size=$(wc -l < "$temp_file")
            
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
    grep -E "(registry\.redhat\.io|quay\.io)" "$manifest_file" | \
        grep -oE "(registry\.redhat\.io|quay\.io)/[^[:space:]]*" | \
        sed 's/[[:space:]]*$//' | \
        sort | uniq > "$temp_images"
    
    if [[ "$VERBOSE" == "true" ]]; then
        local image_count
        image_count=$(wc -l < "$temp_images")
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
            registry_count=$(wc -l < "$registry_file")
            echo "#   - Registry: $registry_count images"
        fi
        
        if [[ -f "$github_file" ]]; then
            local github_count
            github_count=$(wc -l < "$github_file")
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
    } > "$output_file"
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

# Main function to generate the security manifest
fn_generate_manifest() {
    echo "Generating RHOAI security manifest..."
    echo "Version: $RHOAI_VERSION"
    echo "Registry: $REGISTRY_URL:$OPENSHIFT_VERSION"
    echo "Operator: $OPERATOR_NAME"
    echo "GitHub Source: $GITHUB_BASE_URL"
    echo "Output: $OUTPUT_FILE"
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
    
    echo "$catalog" | tr -d '\000-\037' | \
        jq -r --arg operator "$OPERATOR_NAME" --arg version "$RHOAI_VERSION" \
        'select(.schema=="olm.bundle") | 
         select(.name==($operator + "." + $version)) | 
         .relatedImages[] | 
         if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end' | \
        awk '{ print $2 }' > "$temp_registry_file"
    
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to generate registry manifest" >&2
        rm -f "$temp_registry_file"
        exit 1
    fi
    
    local registry_count
    registry_count=$(wc -l < "$temp_registry_file")
    echo "✓ Found $registry_count images from registry"
    
    # Fetch GitHub manifest images
    echo "Fetching images from GitHub manifest..."
    
    local github_manifest_file
    if github_manifest_file=$(fn_fetch_github_manifest "$RHOAI_VERSION"); then
        temp_github_file=$(fn_parse_github_images "$github_manifest_file")
        rm -f "$github_manifest_file"
        
        local github_count
        github_count=$(wc -l < "$temp_github_file")
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
            if [[ $(wc -l < "$OUTPUT_FILE") -gt 20 ]]; then
                echo "... (showing first 20 lines)"
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
    fn_generate_manifest
}

# Run main function with all arguments
fn_main "$@"
