#!/usr/bin/env python3

import requests
import json
from pprint import pprint


def main():
    # should be a parameter
    rhoai_release = "v2.21"
    
    rhoai_total_cves = []

    # this is static, someone on the Pyxis team gave me this
    rhoai_product_id = "63b85b573112fe5a95ee9a3a"

    pyxis_base_url = "https://catalog.redhat.com/api/containers"

    # get the list of image data related to RHOAI
    repositories_in_rhoai_request = requests.get(
        f"{pyxis_base_url}/v1/product-listings/id/{rhoai_product_id}/repositories"
    )

    # pull only the images that are tagged with the RHOAI release
    rhoai_images = []
    for repo in repositories_in_rhoai_request.json()["data"]:
        detected_rhoai_images = []
        images_in_repository_request = requests.get(
            f"{pyxis_base_url}/{repo['_links']['images']['href']}"
        )
        for image in images_in_repository_request.json()["data"]:
            for repository in image['repositories']:
                for tags in repository['tags']:
                    if rhoai_release in tags['name']:
                        detected_rhoai_images.append(image)
        if detected_rhoai_images:
            images_sorted_by_date = sorted(
                detected_rhoai_images,
                key=lambda repo_images: repo_images['creation_date']
            )
            image_found = images_sorted_by_date[-1]
            image_found['display_data'] = repo['display_data']
            rhoai_images.append(image_found)
    
    with open("rhoai_images.json", "w") as f:
        json.dump(rhoai_images, f)
    # print(":::::::::::::::::: DEBUG ::::::::::::::::::")
    # pprint(rhoai_images)

    for image in rhoai_images:
        # for repo in image['repositories']:
        #     print(f"::::: {image['display_data']['name']} in {repo['name']}")
        print(f"::::: {image['display_data']['name']}")
        print(f"::::: id: {image['_id']}")
        print(f"::::: Advisory: {pyxis_base_url}{image['repositories'][0]['_links']['image_advisory']['href']}")
        print(f"::::: Freshness Grade: {image['freshness_grades'][0]['grade']}")
        print("CVE Data:")
        
        cve_data = requests.get(
            f"{pyxis_base_url}/{image['_links']['vulnerabilities']['href']}"
        )
        if not cve_data.json()["data"]:
            print("No CVEs found")
        else: 
            for cve in [c["cve_id"] for c in cve_data.json()["data"]]:
                rhoai_total_cves.append(f"https://access.redhat.com/security/cve/{cve}")
                print(f"- https://access.redhat.com/security/cve/{cve}")
                
        print("\n")
    print(f"Total RHOAI Unique CVEs from all images: {len(list(set(rhoai_total_cves)))}")
    for cve in list(set(rhoai_total_cves)):
        print(f"- {cve}")


if __name__ == "__main__":
    main()
