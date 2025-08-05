#!/bin/bash

# A script to retrieve all container images for a specific Red Hat product
# using the Pyxis API.
#
# Dependencies: curl, jq
#
# Usage:
#   export PYXIS_API_KEY="your_api_key"
#  ./get_product_images.sh "Red Hat OpenShift AI"

set -euo pipefail

# --- Configuration ---
PRODUCT_NAME="${1:-"Red Hat OpenShift AI"}"
if [[ -z "$PRODUCT_NAME" ]]; then
    echo "Usage: $0 \"<Product Name>\"" >&2
    exit 1
fi

# API_KEY="${PYXIS_API_KEY:-}"
# if [[ -z "$API_KEY" ]]; then
#     echo "Error: PYXIS_API_KEY environment variable is not set." >&2
#     exit 1
# fi

BASE_URL="https://catalog.redhat.com/api/containers/v1"
VENDOR_LABEL="redhat"
OUTPUT_FILE="openshift_ai_images.json"

# --- Helper Functions ---

# Function to make an authenticated API call and handle errors
# Usage: api_call <endpoint_path>
api_call() {
    local endpoint="$1"
    local url="${BASE_URL}${endpoint}"
    
    local response
    # response=$(curl -s -w "\n%{http_code}" -H "X-API-KEY: ${API_KEY}" "${url}")
    response=$(curl -s -w "\n%{http_code}" "${url}")
    local http_code
    http_code=$(tail -n1 <<< "$response")
    local body
    body=$(sed '$ d' <<< "$response")

    if [[ "$http_code" -ne 200 ]]; then
        echo "Error: API call failed for ${url} with status ${http_code}" >&2
        echo "Response: ${body}" >&2
        exit 1
    fi
    echo "$body"
}

# Function to fetch all pages for a given list endpoint
# Usage: fetch_all_pages <endpoint_path>
fetch_all_pages() {
    local base_endpoint="$1"
    local page=0
    local page_size=100
    local all_data=""

    echo "Fetching all pages from endpoint: ${base_endpoint}" >&2

    while true; do
        local paginated_endpoint="${base_endpoint}?page=${page}&page_size=${page_size}"
        local body
        body=$(api_call "${paginated_endpoint}")
        
        local current_page_data
        current_page_data=$(echo "$body" | jq '.data')
        
        if [[ $(echo "$current_page_data" | jq 'length') -eq 0 ]]; then
            break
        fi
        
        all_data=$(echo "$all_data" | jq --argjson new_data "$current_page_data" '. + $new_data')
        ((page++))
    done

    __RETURN__="$all_data"
}


# --- Main Logic ---

echo "--- Stage 1: Finding Vendor Organization ID for '${VENDOR_LABEL}' ---"
VENDOR_INFO=$(api_call "/vendors/label/${VENDOR_LABEL}")
ORG_ID=$(echo "$VENDOR_INFO" | jq -r '.org_id')
if [[ -z "$ORG_ID" ]]; then
    echo "Error: Could not find organization ID for vendor '${VENDOR_LABEL}'." >&2
    exit 1
fi
echo "Found Org ID: ${ORG_ID}"

echo "--- Stage 2: Finding Product Listing ID for '${PRODUCT_NAME}' ---"
ENCODED_PRODUCT_NAME=$(printf %s "$PRODUCT_NAME" | jq -s -R -r @uri)
PRODUCT_LISTING_INFO=$(api_call "/product-listings?filter=name%3D%3D%22Red%20Hat%20OpenShift%20AI%22")
PRODUCT_ID=$(echo "$PRODUCT_LISTING_INFO" | jq -r '.data.[]._id')
if [[ -z "$PRODUCT_ID" ]]; then
    echo "Error: Could not find product listing for '${PRODUCT_NAME}'." >&2
    exit 1
fi
echo "Found Product ID: ${PRODUCT_ID}"

echo "--- Stage 3: Fetching all repositories for the product ---"
fetch_all_pages "/product-listings/id/${PRODUCT_ID}/repositories"
REPOSITORIES="${__RETURN__}"
__RETURN__="" # Clear the return variable
REPO_COUNT=$(echo "$REPOSITORIES" | jq 'length')
echo "Found ${REPO_COUNT} repositories associated with the product."

echo "--- Stage 4: Fetching all images from each repository ---"
ALL_IMAGES=""
while IFS= read -r repo_obj; do
    registry=$(echo "$repo_obj" | jq -r '.registry')
    repository=$(echo "$repo_obj" | jq -r '.repository')

    echo "Fetching images for: ${registry}/${repository}" >&2
    
    fetch_all_pages "/repositories/registry/${registry}/repository/${repository}/images"
    IMAGES_FOR_REPO="${__RETURN__}"
    __RETURN__="" # Clear the return variable
    ALL_IMAGES=$(echo "$ALL_IMAGES" | jq --argjson new_images "$IMAGES_FOR_REPO" '. + $new_images')

done < <(echo "$REPOSITORIES" | jq -c '.')

IMAGE_COUNT=$(echo "$ALL_IMAGES" | jq 'length')
echo "--- Aggregation Complete ---"
echo "Found a total of ${IMAGE_COUNT} images across all repositories."

echo "Saving complete image list to ${OUTPUT_FILE}..."
echo "$ALL_IMAGES" | jq '.' > "$OUTPUT_FILE"

echo "Process finished successfully. Data saved to ${OUTPUT_FILE}."
