#!/usr/bin/env python3

import requests
import json
import csv
import argparse
import sys
from datetime import datetime
from pprint import pprint


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Query Red Hat Pyxis API for RHOAI security information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --release v2.21
  %(prog)s --release v2.22 --format json
  %(prog)s -r v2.23 --format csv --output rhoai_security_v2.23.csv
  %(prog)s --release v2.24 --format text --output rhoai_report.txt
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


def format_text_output(images_data, total_cves, use_color=True):
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
            for cve in image["cves"][:3]:  # Show first 3 CVEs
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
    rhoai_release = args.release

    rhoai_total_cves = []

    # this is static, someone on the Pyxis team gave me this
    rhoai_product_id = "63b85b573112fe5a95ee9a3a"

    pyxis_base_url = "https://catalog.redhat.com/api/containers"

    try:
        # get the list of image data related to RHOAI
        repositories_in_rhoai_request = requests.get(
            f"{pyxis_base_url}/v1/product-listings/id/{rhoai_product_id}/repositories"
        )
        repositories_in_rhoai_request.raise_for_status()

        # pull only the images that are tagged with the RHOAI release
        rhoai_images = []
        for repo in repositories_in_rhoai_request.json()["data"]:
            detected_rhoai_images = []
            images_in_repository_request = requests.get(
                f"{pyxis_base_url}/{repo['_links']['images']['href']}"
            )
            images_in_repository_request.raise_for_status()

            for image in images_in_repository_request.json()["data"]:
                for repository in image["repositories"]:
                    for tags in repository["tags"]:
                        if rhoai_release in tags["name"]:
                            detected_rhoai_images.append(image)
            if detected_rhoai_images:
                images_sorted_by_date = sorted(
                    detected_rhoai_images,
                    key=lambda repo_images: repo_images["creation_date"],
                )
                image_found = images_sorted_by_date[-1]
                image_found["display_data"] = repo["display_data"]
                rhoai_images.append(image_found)

        # Collect CVE data for each image
        for image in rhoai_images:
            cve_data = requests.get(
                f"{pyxis_base_url}/{image['_links']['vulnerabilities']['href']}"
            )
            cve_data.raise_for_status()

            image_cves = []
            if cve_data.json()["data"]:
                for cve in cve_data.json()["data"]:
                    cve_url = f"https://access.redhat.com/security/cve/{cve['cve_id']}"
                    image_cves.append(cve_url)
                    rhoai_total_cves.append(cve_url)

            # Add CVE data to image object
            image["cves"] = image_cves

        # Remove duplicates from total CVEs
        unique_total_cves = list(set(rhoai_total_cves))

        # Generate output based on format
        output_filename = get_output_filename(rhoai_release, args.format, args.output)

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
                rhoai_images, unique_total_cves, not args.no_color
            )
            write_output(formatted_text, output_filename, "text")

        # Save raw image data (for debugging/reference)
        with open("rhoai_images.json", "w") as f:
            json.dump(rhoai_images, f, indent=2)

    except requests.RequestException as e:
        print(f"Error accessing Pyxis API: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(f"Error parsing API response - missing key: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
