#!/bin/bash

# Product ID for Red Hat OpenShift AI
_PRODUCT_ID="63b85b573112fe5a95ee9a3a"

# API Base URL
_PYXIS_URL="https://catalog.redhat.com/api/containers/v1"
_PYXIS_QUERY_DATA_FILE="pyxis_query_data.json"

# Output file for the report
_REPORT_FILE="openshift_ai_security_report.txt"

# Function to fetch repositories for a given product ID
fn_get_repositories() {
    local product_id="$1"
    curl -s "${_PYXIS_URL}/product-listings/id/${product_id}/repositories" | jq -r '.data[].repository'
}

# Function to get images for a given repository
fn_get_images() {
    local repository="$1"
    curl -s "${_PYXIS_URL}/repositories/registry/registry.access.redhat.com/repository/${repository}/images" | jq -r '.data[]._id'
}

# Function to get vulnerabilities for a given image ID
fn_get_vulnerabilities() {
    local image_id="$1"
    curl -s "${_PYXIS_URL}/images/id/${image_id}/vulnerabilities" | jq -r '.data[] | "\(.cve_id) - \(.severity)"'
}

# Main function to generate the report
main() {
    echo "Generating security report for Red Hat OpenShift AI..."
    echo "Report will be saved to: ${_REPORT_FILE}"
    echo "" > "${_REPORT_FILE}"

    repositories=$(fn_get_repositories "${_PRODUCT_ID}")

    if [ -z "$repositories" ]; then
        echo "No repositories found for the given product ID."
        exit 1
    fi

    for repo in $repositories; do
        echo "Fetching images for repository: ${repo}"
        echo "==========================================" >> "${_REPORT_FILE}"
        echo "Repository: ${repo}" >> "${_REPORT_FILE}"
        echo "==========================================" >> "${_REPORT_FILE}"

        images=$(fn_get_images "${repo}")

        if [ -z "$images" ]; then
            echo "No images found for repository: ${repo}"
            continue
        fi

        for image in $images; do
            echo "  Fetching vulnerabilities for image: ${image}"
            echo "  Image ID: ${image}" >> "${_REPORT_FILE}"
            vulnerabilities=$(fn_get_vulnerabilities "${image}")

            if [ -n "$vulnerabilities" ]; then
                echo -e "    Vulnerabilities:\n${vulnerabilities}" >> "${_REPORT_FILE}"
            else
                echo "    No vulnerabilities found." >> "${_REPORT_FILE}"
            fi
            echo "" >> "${_REPORT_FILE}"
        done
    done

    echo "Report generation complete."
}

main
