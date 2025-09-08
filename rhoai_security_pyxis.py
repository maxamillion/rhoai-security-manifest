#!/usr/bin/env python3

import requests
import json
import csv
import argparse
import sys
import logging
import time
from datetime import datetime
from pprint import pprint

# Import Atlas client for vulnerability analysis
try:
    from atlas_client import AtlasClient, extract_purls_from_image_data

    ATLAS_AVAILABLE = True
except ImportError:
    ATLAS_AVAILABLE = False


def setup_logging(log_level=None, verbose=False):
    """Configure logging for the application.

    Args:
        log_level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        verbose (bool): Legacy verbose flag for backward compatibility
    """
    # Handle legacy verbose flag
    if log_level is None:
        log_level = "DEBUG" if verbose else "INFO"

    # Convert string to logging level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)


def get_image_name(image):
    """Extract image name in registry/repository format with SHA256 digest.

    Args:
        image (dict): Image data from Pyxis API

    Returns:
        str: Image name in format "registry/repository:sha256_8chars" or fallback value
    """
    try:
        # Extract registry and repository
        if image.get("repositories") and len(image["repositories"]) > 0:
            registry = image["repositories"][0].get("registry", "")
            repository = image["repositories"][0].get("repository", "")

            if registry and repository:
                base_name = f"{registry}/{repository}"

                # Try to extract SHA256 digest from image_id field
                image_id = image.get("image_id", "")
                if image_id and image_id.startswith("sha256:"):
                    sha256_hash = image_id.replace("sha256:", "")
                    if len(sha256_hash) >= 8:
                        return f"{base_name}:{sha256_hash[:8]}"

                # Return base name if no valid SHA256 found
                return base_name

        # Fallback: try display_data if available for backward compatibility
        if image.get("display_data") and image["display_data"].get("name"):
            return image["display_data"]["name"]

        # Final fallback: use image ID if available
        return image.get("_id", "unknown")

    except (KeyError, TypeError, IndexError):
        return "unknown"


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Query Red Hat Pyxis API for RHOAI security information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --release v2.21
  %(prog)s --release v2.22 --format json --verbose
  %(prog)s -r v2.23 --format csv --output rhoai_security_v2.23.csv
  %(prog)s --release v2.24 --format text --output rhoai_report.txt --verbose
  %(prog)s --release v2.21 --show-all-cves
  %(prog)s --release v2.22 --log-level WARNING
  %(prog)s --release v2.23 --log-level DEBUG --format json
  %(prog)s --release v2.22 --no-atlas --format json
  %(prog)s --release v2.23 --no-atlas --atlas-url https://custom-atlas.example.com
        """,
    )
    parser.add_argument(
        "-r",
        "--release",
        default="v2.21",
        help="RHOAI release version (default: v2.21)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format: text (human-readable), json, or csv (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: stdout for text, auto-generated for json/csv)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output for text format"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging and progress information",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress status messages (except errors)"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Set logging level (default: INFO, or DEBUG if --verbose is used)",
    )
    parser.add_argument(
        "--show-all-cves",
        action="store_true",
        help="Show all CVEs for each image without truncation (default: show first 3)",
    )
    parser.add_argument(
        "--no-atlas",
        action="store_true",
        help="Disable Atlas Release API integration (Atlas analysis is enabled by default)",
    )
    parser.add_argument(
        "--atlas-url",
        default="https://atlas.release.devshift.net",
        help="Atlas Release API base URL (default: https://atlas.release.devshift.net)",
    )
    parser.add_argument(
        "--atlas-timeout",
        type=int,
        default=30,
        help="Atlas API timeout in seconds (default: 30)",
    )
    return parser.parse_args()


def get_output_filename(release, format_type, custom_output=None):
    """Generate output filename based on release and format."""
    if custom_output:
        return custom_output

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if format_type == "json":
        return f"rhoai_security_{release}_{timestamp}.json"
    elif format_type == "csv":
        return f"rhoai_security_{release}_{timestamp}.csv"
    else:
        return None  # stdout for text format


def format_text_output(
    images_data, total_cves, use_color=True, show_all_cves=False, atlas_cves=None
):
    """Format data for human-readable text output."""
    output_lines = []

    # ANSI color codes
    if use_color:
        HEADER = "\033[95m"
        OKBLUE = "\033[94m"
        OKCYAN = "\033[96m"
        OKGREEN = "\033[92m"
        WARNING = "\033[93m"
        FAIL = "\033[91m"
        ENDC = "\033[0m"
        BOLD = "\033[1m"
    else:
        HEADER = OKBLUE = OKCYAN = OKGREEN = WARNING = FAIL = ENDC = BOLD = ""

    # Header
    output_lines.append(f"{HEADER}{BOLD}RHOAI Security Analysis Report{ENDC}")
    output_lines.append(
        f"{HEADER}Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{ENDC}"
    )
    output_lines.append("=" * 70)
    output_lines.append("")

    # Summary
    output_lines.append(f"{BOLD}Summary:{ENDC}")
    output_lines.append(f"  Total Images Analyzed: {OKBLUE}{len(images_data)}{ENDC}")
    output_lines.append(
        f"  Pyxis Unique CVEs: {WARNING if len(total_cves) > 0 else OKGREEN}{len(total_cves)}{ENDC}"
    )

    # Add Atlas summary if available
    if atlas_cves is not None:
        atlas_count = len(atlas_cves)
        combined_cves = set(total_cves) | set(atlas_cves)
        output_lines.append(
            f"  Atlas Unique CVEs: {WARNING if atlas_count > 0 else OKGREEN}{atlas_count}{ENDC}"
        )
        output_lines.append(
            f"  Combined Unique CVEs: {WARNING if len(combined_cves) > 0 else OKGREEN}{len(combined_cves)}{ENDC}"
        )

    output_lines.append("")

    # Detailed image information
    output_lines.append(f"{BOLD}Image Details:{ENDC}")
    output_lines.append("-" * 50)

    for i, image in enumerate(images_data, 1):
        output_lines.append(f"{OKCYAN}[{i}] {get_image_name(image)}{ENDC}")
        output_lines.append(f"    ID: {image['_id']}")

        advisory_url = f"https://access.redhat.com/errata/{image['repositories'][0]['_links']['image_advisory']['href'].split('/')[-1]}"
        output_lines.append(f"    Advisory: {OKBLUE}{advisory_url}{ENDC}")

        freshness_grade = image["freshness_grades"][0]["grade"]
        grade_color = (
            OKGREEN
            if freshness_grade == "A"
            else WARNING if freshness_grade in ["B", "C"] else FAIL
        )
        output_lines.append(
            f"    Freshness Grade: {grade_color}{freshness_grade}{ENDC}"
        )

        # Pyxis CVE count for this image
        cve_count = len(image.get("cves", []))
        cve_color = OKGREEN if cve_count == 0 else WARNING if cve_count < 5 else FAIL
        output_lines.append(f"    Pyxis CVEs: {cve_color}{cve_count}{ENDC}")

        if image.get("cves"):
            if show_all_cves:
                # Show all CVEs without truncation
                for cve in image["cves"]:
                    output_lines.append(f"      - {cve}")
            else:
                # Show first 3 CVEs (original behavior)
                for cve in image["cves"][:3]:
                    output_lines.append(f"      - {cve}")
                if len(image["cves"]) > 3:
                    output_lines.append(f"      ... and {len(image['cves']) - 3} more")
        else:
            output_lines.append(f"      {OKGREEN}No Pyxis CVEs found{ENDC}")

        # Atlas CVE information
        atlas_data = image.get("atlas_data", {})
        if atlas_data:
            atlas_cves = atlas_data.get("atlas_cves", [])
            atlas_count = len(atlas_cves)
            atlas_status = atlas_data.get("analysis_status", "unknown")

            if atlas_status == "analyzed":
                atlas_color = (
                    OKGREEN
                    if atlas_count == 0
                    else WARNING if atlas_count < 5 else FAIL
                )
                output_lines.append(f"    Atlas CVEs: {atlas_color}{atlas_count}{ENDC}")

                if atlas_cves and show_all_cves:
                    for cve in atlas_cves[:3]:
                        output_lines.append(f"      - {cve}")
                    if len(atlas_cves) > 3:
                        output_lines.append(
                            f"      ... and {len(atlas_cves) - 3} more Atlas CVEs"
                        )
                elif atlas_cves:
                    output_lines.append(f"      {atlas_cves[0]}")
                    if len(atlas_cves) > 1:
                        output_lines.append(f"      ... and {len(atlas_cves) - 1} more")
                elif atlas_count == 0:
                    output_lines.append(f"      {OKGREEN}No Atlas CVEs found{ENDC}")
            else:
                output_lines.append(
                    f"    Atlas CVEs: {WARNING}Not analyzed ({atlas_status}){ENDC}"
                )

        output_lines.append("")

    # Complete CVE list
    if total_cves:
        output_lines.append(
            f"{BOLD}Complete CVE List ({len(total_cves)} unique):{ENDC}"
        )
        output_lines.append("-" * 40)
        for cve in sorted(total_cves):
            output_lines.append(f"  - {cve}")

    return "\n".join(output_lines)


def format_json_output(images_data, total_cves, release, atlas_cves=None):
    """Format data for JSON output."""
    metadata = {
        "release": release,
        "generated_at": datetime.now().isoformat(),
        "total_images": len(images_data),
        "total_unique_cves": len(total_cves),
    }

    # Add Atlas metadata if available
    if atlas_cves is not None:
        metadata["atlas_enabled"] = True
        metadata["atlas_unique_cves"] = len(atlas_cves)
        combined_cves = set(total_cves) | set(atlas_cves)
        metadata["combined_unique_cves"] = len(combined_cves)
    else:
        metadata["atlas_enabled"] = False

    result = {
        "metadata": metadata,
        "images": images_data,
        "unique_cves": sorted(total_cves),
    }

    # Add Atlas CVEs if available
    if atlas_cves is not None:
        result["atlas_unique_cves"] = sorted(atlas_cves)
        combined_cves = set(total_cves) | set(atlas_cves)
        result["combined_unique_cves"] = sorted(combined_cves)

    return result


def format_csv_output(images_data, total_cves):
    """Format data for CSV output."""
    csv_data = []

    for image in images_data:
        advisory_url = f"https://access.redhat.com/errata/{image['repositories'][0]['_links']['image_advisory']['href'].split('/')[-1]}"
        cve_list = "; ".join(image.get("cves", []))

        # Atlas data
        atlas_data = image.get("atlas_data", {})
        atlas_cves = atlas_data.get("atlas_cves", [])
        atlas_cve_list = "; ".join(atlas_cves)
        atlas_status = atlas_data.get("analysis_status", "not_analyzed")

        csv_data.append(
            {
                "image_name": get_image_name(image),
                "image_id": image["_id"],
                "advisory_url": advisory_url,
                "freshness_grade": image["freshness_grades"][0]["grade"],
                "pyxis_cve_count": len(image.get("cves", [])),
                "pyxis_cves": cve_list,
                "atlas_cve_count": len(atlas_cves),
                "atlas_cves": atlas_cve_list,
                "atlas_status": atlas_status,
                "creation_date": image.get("creation_date", ""),
            }
        )

    return csv_data


def write_output(content, filename, format_type):
    """Write content to file or stdout."""
    if format_type == "text" and not filename:
        print(content)
        return

    try:
        if format_type == "json":
            with open(filename, "w") as f:
                json.dump(content, f, indent=2)
        elif format_type == "csv":
            with open(filename, "w", newline="") as f:
                if content:
                    writer = csv.DictWriter(f, fieldnames=content[0].keys())
                    writer.writeheader()
                    writer.writerows(content)
        else:  # text
            with open(filename, "w") as f:
                f.write(content)

        print(f"Output written to: {filename}")
    except Exception as e:
        print(f"Error writing to file {filename}: {e}", file=sys.stderr)
        sys.exit(1)


def analyze_atlas_vulnerabilities(images_data, atlas_client, logger):
    """Analyze vulnerabilities using Atlas Release API.

    Args:
        images_data: List of image data dictionaries
        atlas_client: Configured AtlasClient instance
        logger: Logger instance

    Returns:
        Dictionary mapping image IDs to Atlas vulnerability data
    """
    atlas_results = {}

    if not images_data:
        logger.warning("No images provided for Atlas vulnerability analysis")
        return atlas_results

    try:
        # Extract PURLs from all images
        all_purls = []
        image_to_purls = {}

        for image in images_data:
            image_id = image.get("_id", "unknown")
            image_purls = extract_purls_from_image_data(image)

            if image_purls:
                image_to_purls[image_id] = image_purls
                all_purls.extend(image_purls)
                logger.debug(f"Generated {len(image_purls)} PURLs for image {image_id}")
            else:
                logger.warning(f"No PURLs generated for image {image_id}")

        if not all_purls:
            logger.warning("No PURLs generated from image data")
            return atlas_results

        logger.info(f"Analyzing {len(all_purls)} PURLs with Atlas API...")

        # Analyze vulnerabilities via Atlas API
        atlas_response = atlas_client.analyze_vulnerabilities(all_purls)

        # Process Atlas response and map back to images
        if atlas_response and isinstance(atlas_response, dict):
            logger.info("Successfully received Atlas vulnerability analysis")

            for image_id, image_purls in image_to_purls.items():
                image_atlas_data = {
                    "purls": image_purls,
                    "vulnerabilities": [],
                    "atlas_cves": [],
                    "analysis_status": "analyzed",
                }

                # Extract vulnerability data for this image's PURLs
                for purl in image_purls:
                    if purl in atlas_response:
                        purl_data = atlas_response[purl]
                        if isinstance(purl_data, dict):
                            image_atlas_data["vulnerabilities"].append(purl_data)

                            # Extract CVE IDs
                            if "vulnerabilities" in purl_data:
                                for vuln in purl_data.get("vulnerabilities", []):
                                    if isinstance(vuln, dict) and "cve_id" in vuln:
                                        cve_id = vuln["cve_id"]
                                        if cve_id not in image_atlas_data["atlas_cves"]:
                                            image_atlas_data["atlas_cves"].append(
                                                cve_id
                                            )

                atlas_results[image_id] = image_atlas_data
                logger.debug(
                    f"Atlas analysis for {image_id}: {len(image_atlas_data['atlas_cves'])} CVEs found"
                )

        logger.info(
            f"Atlas vulnerability analysis completed for {len(atlas_results)} images"
        )
        return atlas_results

    except Exception as e:
        logger.error(f"Atlas vulnerability analysis failed: {e}")
        return atlas_results


def fetch_operator_bundle_images(rhoai_release, pyxis_base_url, logger):
    """Fetch additional RHOAI images from operator bundles."""
    logger.info("Fetching additional images from operator bundles...")

    # Convert release format: v2.21 -> 2.21.0
    if rhoai_release.startswith("v"):
        if len(rhoai_release.split(".")) == 2:
            bundle_release = rhoai_release[1:] + ".0"
        elif len(rhoai_release.split(".")) == 3:
            bundle_release = rhoai_release[1:]
    else:
        bundle_release = rhoai_release + ".0"

    logger.debug(f"Using operator bundle release format: {bundle_release}")

    operator_bundle_images = []

    try:
        # Query operator bundles endpoint
        pyxis_operator_bundle_url = f"{pyxis_base_url}/v1/operators/bundles"
        operator_bundle_params = {
            "filter": f"csv_name=='rhods-operator.{bundle_release}'"
        }

        logger.debug(f"Querying operator bundles: {pyxis_operator_bundle_url}")
        logger.debug(f"Bundle filter: {operator_bundle_params['filter']}")

        operator_bundle_response = requests.get(
            pyxis_operator_bundle_url, params=operator_bundle_params
        )
        operator_bundle_response.raise_for_status()
        operator_bundle_data = operator_bundle_response.json()["data"]

        if not operator_bundle_data:
            logger.error(f"No operator bundles found for release {bundle_release}")
            return operator_bundle_images

        # Sort by creation date and get the most recent
        operators_sorted_by_date = sorted(
            operator_bundle_data, key=lambda operator: operator["creation_date"]
        )
        latest_operator = operators_sorted_by_date[-1]

        logger.info(
            f"Found operator bundle with {len(latest_operator.get('related_images', []))} related images"
        )

        # Process each related image
        pyxis_images_url = f"{pyxis_base_url}/v1/images"

        for idx, image in enumerate(latest_operator.get("related_images", []), 1):
            image_digest = image["digest"]
            logger.debug(
                f"Processing operator bundle image {idx}: {image_digest[:20]}..."
            )

            image_digest_params = {
                "filter": f"(docker_image_digest=='{image_digest}' or repositories.manifest_list_digest=='{image_digest}')"
            }

            image_response = requests.get(pyxis_images_url, params=image_digest_params)
            image_response.raise_for_status()
            image_data = image_response.json()["data"]

            for image_obj in image_data:
                if image_obj.get("architecture") == "amd64":
                    # filter out ose-cli images, for some reason there's always a few
                    if "ose-cli" not in image_obj["repositories"][0]["repository"]:
                        operator_bundle_images.append(image_obj)
                        logger.debug(
                            f"Added amd64 image: {image_obj.get('_id', 'unknown')}"
                        )

        logger.info(
            f"Successfully fetched {len(operator_bundle_images)} operator bundle images"
        )
        return operator_bundle_images

    except requests.RequestException as e:
        logger.warning(f"Failed to fetch operator bundle images: {e}")
        return operator_bundle_images
    except KeyError as e:
        logger.warning(f"Unexpected operator bundle API response structure: {e}")
        return operator_bundle_images
    except Exception as e:
        logger.warning(f"Error processing operator bundle images: {e}")
        return operator_bundle_images


def main():
    args = parse_arguments()

    # Setup logging based on arguments
    logger = setup_logging(args.log_level, args.verbose)

    # Configure quiet mode
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    rhoai_release = args.release
    start_time = time.time()

    logger.info(f"Starting RHOAI security analysis for release: {rhoai_release}")
    logger.info(f"Output format: {args.format}")

    rhoai_total_cves = []

    # this is static, someone on the Pyxis team gave me this
    rhoai_product_id = "63b85b573112fe5a95ee9a3a"
    logger.debug(f"Using RHOAI product ID: {rhoai_product_id}")

    pyxis_base_url = "https://catalog.redhat.com/api/containers"
    logger.debug(f"Pyxis API base URL: {pyxis_base_url}")

    try:
        # get the list of image data related to RHOAI
        logger.info("Fetching RHOAI repository listings from Pyxis API...")
        repositories_url = (
            f"{pyxis_base_url}/v1/product-listings/id/{rhoai_product_id}/repositories"
        )
        logger.debug(f"Repository request URL: {repositories_url}")

        repositories_in_rhoai_request = requests.get(repositories_url)
        repositories_in_rhoai_request.raise_for_status()

        repositories_data = repositories_in_rhoai_request.json()["data"]
        logger.info(f"Found {len(repositories_data)} repositories to analyze")

        # pull only the images that are tagged with the RHOAI release
        logger.info(f"Searching for images tagged with release: {rhoai_release}")
        rhoai_images = []

        for repo_idx, repo in enumerate(repositories_data, 1):
            repo_name = repo.get("display_data", {}).get("name", "unknown")
            logger.info(
                f"Processing repository {repo_idx}/{len(repositories_data)}: {repo_name}"
            )

            detected_rhoai_images = []
            images_url = f"{pyxis_base_url}/{repo['_links']['images']['href']}"
            logger.debug(f"Fetching images from: {images_url}")

            images_in_repository_request = requests.get(images_url)
            images_in_repository_request.raise_for_status()

            images_data = images_in_repository_request.json()["data"]
            logger.debug(f"Found {len(images_data)} total images in repository")

            for image in images_data:
                for repository in image["repositories"]:
                    for tags in repository["tags"]:
                        if rhoai_release in tags["name"]:
                            logger.debug(
                                f"Found matching tag: {tags['name']} in image {image.get('_id', 'unknown')}"
                            )
                            detected_rhoai_images.append(image)

            if detected_rhoai_images:
                logger.info(
                    f"Found {len(detected_rhoai_images)} images for {repo_name} with release {rhoai_release}"
                )
                images_sorted_by_date = sorted(
                    detected_rhoai_images,
                    key=lambda repo_images: repo_images["creation_date"],
                )
                image_found = images_sorted_by_date[-1]
                image_found["display_data"] = repo["display_data"]
                rhoai_images.append(image_found)
                logger.debug(
                    f"Selected most recent image: {image_found.get('_id', 'unknown')}"
                )
            else:
                logger.debug(
                    f"No images found for {repo_name} with release {rhoai_release}"
                )

        logger.info(f"Total images selected for analysis: {len(rhoai_images)}")

        # Fetch additional images from operator bundles
        operator_bundle_images = fetch_operator_bundle_images(
            rhoai_release, pyxis_base_url, logger
        )
        if operator_bundle_images:
            logger.info(
                f"Adding {len(operator_bundle_images)} operator bundle images to analysis"
            )
            rhoai_images.extend(operator_bundle_images)
            logger.info(f"Updated total images for analysis: {len(rhoai_images)}")
        else:
            logger.info("No operator bundle images found or accessible")

        # Collect CVE data for each image
        logger.info("Collecting CVE data for each image...")

        for image_idx, image in enumerate(rhoai_images, 1):
            image_name = get_image_name(image)
            logger.info(
                f"Analyzing CVEs for image {image_idx}/{len(rhoai_images)}: {image_name}"
            )

            cve_url = f"{pyxis_base_url}/{image['_links']['vulnerabilities']['href']}"
            logger.debug(f"Fetching CVE data from: {cve_url}")

            cve_data = requests.get(cve_url)
            cve_data.raise_for_status()

            image_cves = []
            cve_response_data = cve_data.json()["data"]

            if cve_response_data:
                logger.debug(f"Found {len(cve_response_data)} CVEs for {image_name}")
                for cve in cve_response_data:
                    cve_url = f"https://access.redhat.com/security/cve/{cve['cve_id']}"
                    image_cves.append(cve_url)
                    rhoai_total_cves.append(cve_url)
            else:
                logger.debug(f"No CVEs found for {image_name}")

            # Add CVE data to image object
            image["cves"] = image_cves
            logger.info(
                f"Completed CVE analysis for {image_name}: {len(image_cves)} CVEs found"
            )

        # Remove duplicates from total CVEs
        unique_total_cves = list(set(rhoai_total_cves))
        logger.info(
            f"Analysis complete: {len(unique_total_cves)} unique CVEs found across all images"
        )

        # Atlas API vulnerability analysis (if enabled)
        atlas_results = {}
        atlas_total_cves = set()

        if not args.no_atlas:
            if not ATLAS_AVAILABLE:
                logger.error(
                    "Atlas integration enabled by default but atlas_client module not available"
                )
                logger.error(
                    "Please ensure atlas_client.py is in the same directory or use --no-atlas to disable"
                )
            else:
                logger.info("Starting Atlas Release API vulnerability analysis...")
                try:
                    atlas_client = AtlasClient(
                        base_url=args.atlas_url, timeout=args.atlas_timeout
                    )

                    # Test Atlas API connection
                    if atlas_client.test_connection():
                        logger.info("Atlas API connection successful")
                        atlas_results = analyze_atlas_vulnerabilities(
                            rhoai_images, atlas_client, logger
                        )

                        # Collect Atlas CVEs and add to images
                        for image in rhoai_images:
                            image_id = image.get("_id", "unknown")
                            if image_id in atlas_results:
                                atlas_data = atlas_results[image_id]
                                image["atlas_data"] = atlas_data
                                # Add Atlas CVEs to total count
                                atlas_total_cves.update(
                                    atlas_data.get("atlas_cves", [])
                                )
                            else:
                                image["atlas_data"] = {
                                    "analysis_status": "skipped",
                                    "atlas_cves": [],
                                    "vulnerabilities": [],
                                }

                        logger.info(
                            f"Atlas analysis found {len(atlas_total_cves)} additional unique CVEs"
                        )
                    else:
                        logger.error(
                            "Atlas API connection failed - skipping Atlas analysis (use --no-atlas to disable)"
                        )

                except Exception as e:
                    logger.error(f"Atlas vulnerability analysis failed: {e}")
                    logger.info(
                        "Continuing with Pyxis-only analysis (use --no-atlas to disable Atlas)"
                    )
        else:
            logger.info("Atlas integration disabled via --no-atlas flag")

        # Show timing information
        analysis_time = time.time() - start_time
        logger.info(f"Data collection completed in {analysis_time:.2f} seconds")

        # Generate output based on format
        logger.info(f"Generating {args.format} output...")
        output_filename = get_output_filename(rhoai_release, args.format, args.output)
        if output_filename:
            logger.info(f"Output will be written to: {output_filename}")

        # Prepare Atlas CVE data for output
        atlas_cves_list = list(atlas_total_cves) if atlas_total_cves else None

        if args.format == "json":
            formatted_data = format_json_output(
                rhoai_images, unique_total_cves, rhoai_release, atlas_cves_list
            )
            write_output(formatted_data, output_filename, "json")
        elif args.format == "csv":
            formatted_data = format_csv_output(rhoai_images, unique_total_cves)
            write_output(formatted_data, output_filename, "csv")
        else:  # text format
            formatted_text = format_text_output(
                rhoai_images,
                unique_total_cves,
                not args.no_color,
                args.show_all_cves,
                atlas_cves_list,
            )
            write_output(formatted_text, output_filename, "text")

        # Save raw image data (for debugging/reference)
        debug_filename = "rhoai_images.json"
        logger.debug(f"Saving raw image data to: {debug_filename}")
        with open(debug_filename, "w") as f:
            json.dump(rhoai_images, f, indent=2)

        total_time = time.time() - start_time
        logger.info(
            f"RHOAI security analysis completed successfully in {total_time:.2f} seconds"
        )

        # Enhanced summary with Atlas data
        summary_parts = [
            f"{len(rhoai_images)} images analyzed",
            f"{len(unique_total_cves)} Pyxis CVEs found",
        ]

        if atlas_total_cves:
            summary_parts.append(f"{len(atlas_total_cves)} Atlas CVEs found")
            combined_total = len(set(unique_total_cves) | atlas_total_cves)
            summary_parts.append(f"{combined_total} combined unique CVEs")

        logger.info(f"Summary: {', '.join(summary_parts)}")

    except requests.RequestException as e:
        logger.error(f"Error accessing Pyxis API: {e}")
        print(f"Error accessing Pyxis API: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        logger.error(f"Error parsing API response - missing key: {e}")
        print(f"Error parsing API response - missing key: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
