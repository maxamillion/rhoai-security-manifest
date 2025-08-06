#!/bin/bash



catalog=$(podman run --rm -it --entrypoint bash registry.redhat.io/redhat/redhat-operator-index:v4.18 -c 'cat /configs/rhods-operator/catalog.json'); echo "$catalog" | tr -d '\000-\037' | jq -r 'select( .schema=="olm.bundle" ) | select( .name=="rhods-operator.'${RHOAI_VERSION:-2.22.0}'" ) | .relatedImages[] | if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end' | awk '{ print $2 }' > rhoai-2220
