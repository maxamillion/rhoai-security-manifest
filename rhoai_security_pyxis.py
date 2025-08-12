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


def setup_logging(verbose=False):
    """Configure logging for the application."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)


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
        "--show-all-cves",
        action="store_true",
        help="Show all CVEs for each image without truncation (default: show first 3)"
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


def format_text_output(images_data, total_cves, use_color=True, show_all_cves=False):
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
        f"  Total Unique CVEs: {WARNING if len(total_cves) > 0 else OKGREEN}{len(total_cves)}{ENDC}"
    )
    output_lines.append("")

    # Detailed image information
    output_lines.append(f"{BOLD}Image Details:{ENDC}")
    output_lines.append("-" * 50)

    for i, image in enumerate(images_data, 1):
        output_lines.append(f"{OKCYAN}[{i}] {image['display_data']['name']}{ENDC}")
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

        # CVE count for this image
        cve_count = len(image.get("cves", []))
        cve_color = OKGREEN if cve_count == 0 else WARNING if cve_count < 5 else FAIL
        output_lines.append(f"    CVEs: {cve_color}{cve_count}{ENDC}")

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
            output_lines.append(f"      {OKGREEN}No CVEs found{ENDC}")

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


def format_json_output(images_data, total_cves, release):
    """Format data for JSON output."""
    return {
        "metadata": {
            "release": release,
            "generated_at": datetime.now().isoformat(),
            "total_images": len(images_data),
            "total_unique_cves": len(total_cves),
        },
        "images": images_data,
        "unique_cves": sorted(total_cves),
    }


def format_csv_output(images_data, total_cves):
    """Format data for CSV output."""
    csv_data = []

    for image in images_data:
        advisory_url = f"https://access.redhat.com/errata/{image['repositories'][0]['_links']['image_advisory']['href'].split('/')[-1]}"
        cve_list = "; ".join(image.get("cves", []))

        csv_data.append(
            {
                "image_name": image["display_data"]["name"],
                "image_id": image["_id"],
                "advisory_url": advisory_url,
                "freshness_grade": image["freshness_grades"][0]["grade"],
                "cve_count": len(image.get("cves", [])),
                "cves": cve_list,
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


def main():
    args = parse_arguments()

    # Setup logging based on arguments
    logger = setup_logging(args.verbose)

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

        # Collect CVE data for each image
        logger.info("Collecting CVE data for each image...")

        for image_idx, image in enumerate(rhoai_images, 1):
            image_name = image.get("display_data", {}).get("name", "unknown")
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

        # Show timing information
        analysis_time = time.time() - start_time
        logger.info(f"Data collection completed in {analysis_time:.2f} seconds")

        # Generate output based on format
        logger.info(f"Generating {args.format} output...")
        output_filename = get_output_filename(rhoai_release, args.format, args.output)
        if output_filename:
            logger.info(f"Output will be written to: {output_filename}")

        if args.format == "json":
            formatted_data = format_json_output(
                rhoai_images, unique_total_cves, rhoai_release
            )
            write_output(formatted_data, output_filename, "json")
        elif args.format == "csv":
            formatted_data = format_csv_output(rhoai_images, unique_total_cves)
            write_output(formatted_data, output_filename, "csv")
        else:  # text format
            formatted_text = format_text_output(
                rhoai_images, unique_total_cves, not args.no_color, args.show_all_cves
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
        logger.info(
            f"Summary: {len(rhoai_images)} images analyzed, {len(unique_total_cves)} unique CVEs found"
        )

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
