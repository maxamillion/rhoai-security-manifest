"""Security Data Mapper for Product Listings to Hydra API correlation."""

from datetime import datetime
from typing import Any

from ..utils.logging import get_logger
from .container_catalog import ContainerImage
from .product_listings import OperatorBundle, ProductListing
from .security_data import CVEData

logger = get_logger("api.security_data_mapper")


class SecurityDataMapper:
    """Maps Product Listings data to Red Hat Security Data API queries."""

    def __init__(self):
        """Initialize the security data mapper."""
        # Container name patterns for security queries
        self._container_patterns = {
            # Core operator patterns
            "rhods-operator": ["rhods", "openshift-ai", "rhoai", "data-science"],
            "odh-dashboard": ["dashboard", "console", "ui"],
            "odh-notebook-controller": ["notebook", "jupyter", "controller"],
            # ML Pipelines patterns
            "odh-ml-pipelines": ["pipelines", "kubeflow", "ml-pipeline", "argo"],
            "ml-pipelines-api-server": ["api-server", "pipelines-api"],
            "ml-pipelines-persistenceagent": ["persistence", "metadata"],
            "ml-pipelines-scheduledworkflow": ["workflow", "scheduler"],
            "ml-pipelines-viewercontroller": ["viewer", "controller"],
            # KServe patterns
            "odh-kserve": ["kserve", "serving", "inference"],
            "kserve-controller": ["controller", "serving"],
            "kserve-agent": ["agent", "proxy"],
            "kserve-router": ["router", "gateway"],
            "kserve-storage-initializer": ["storage", "initializer"],
            # ModelMesh patterns
            "odh-modelmesh": ["modelmesh", "serving", "grpc"],
            "modelmesh-controller": ["controller", "serving"],
            "modelmesh-runtime-adapter": ["adapter", "runtime"],
            "modelmesh-serving-runtime": ["serving-runtime", "runtime"],
            # Serving runtimes patterns
            "odh-pytorch": ["pytorch", "torch", "python"],
            "odh-tensorflow": ["tensorflow", "tf", "python"],
            "odh-triton": ["triton", "nvidia", "inference"],
            "odh-openvino": ["openvino", "intel", "inference"],
            "odh-tgis": ["tgis", "text-generation", "llm"],
            "odh-caikit-tgis": ["caikit", "tgis", "nlp"],
            # Notebook images patterns
            "odh-generic-data-science-notebook": ["datascience", "notebook", "jupyter"],
            "odh-minimal-notebook": ["minimal", "notebook", "jupyter"],
            "odh-pytorch-notebook": ["pytorch", "notebook", "jupyter"],
            "odh-tensorflow-notebook": ["tensorflow", "notebook", "jupyter"],
            "odh-trustyai-notebook": ["trustyai", "notebook", "jupyter"],
            "odh-habana-notebook": ["habana", "notebook", "jupyter"],
            # TrustyAI patterns
            "odh-trustyai": ["trustyai", "explainability", "ai-fairness"],
            "trustyai-service": ["trustyai", "service", "explainability"],
            "trustyai-service-operator": ["trustyai", "operator", "controller"],
            # Additional components patterns
            "odh-mm-rest-proxy": ["rest-proxy", "proxy", "api"],
            "odh-model-controller": ["model", "controller", "serving"],
        }

        # Package name mappings for RPM-level security analysis
        self._package_mappings = {
            # Base RHEL packages
            "rhel": ["glibc", "openssl", "systemd", "kernel", "bash", "coreutils"],
            # Python ecosystem
            "python": ["python3", "python3-pip", "python3-setuptools", "python3-wheel"],
            # Java ecosystem
            "java": ["java-11-openjdk", "java-17-openjdk", "maven"],
            # Container runtime
            "container": ["podman", "buildah", "skopeo", "runc"],
            # Network and security
            "network": ["curl", "wget", "openssh", "openssl-libs"],
            # Development tools
            "development": ["gcc", "make", "cmake", "git"],
        }

    def map_product_to_security_queries(
        self, product_listing: ProductListing, release_version: str
    ) -> list[dict[str, Any]]:
        """Map product listing to security API query parameters.

        Args:
            product_listing: Product listing with operator bundles
            release_version: RHOAI release version

        Returns:
            List of individual security query parameters for Hydra API
        """
        queries = []

        logger.info(
            f"Mapping product listing to security queries for version {release_version}"
        )

        # Base product-level queries - individual terms
        base_terms = ["openshift-ai", "rhoai", "rhods", "data-science"]

        for term in base_terms:
            queries.append(
                {
                    "query_type": "product",
                    "terms": [term],  # Single term per query
                    "version": release_version,
                    "priority": "high",
                }
            )

        # Category-level queries - individual terms
        category_terms = ["machine-learning", "artificial-intelligence", "ai-ml"]

        for term in category_terms:
            queries.append(
                {
                    "query_type": "product_category",
                    "terms": [term],  # Single term per query
                    "version": release_version,
                    "priority": "medium",
                }
            )

        # Operator bundle specific queries
        for bundle in product_listing.operator_bundles:
            bundle_queries = self._map_bundle_to_queries(bundle, release_version)
            queries.extend(bundle_queries)

        logger.info(
            f"Generated {len(queries)} individual security queries for product analysis"
        )
        return queries

    def resolve_container_security_identifiers(
        self, container: ContainerImage
    ) -> dict[str, Any]:
        """Resolve container to security identifiers for Hydra API.

        Args:
            container: Container image object

        Returns:
            Dictionary with security identifiers and individual search terms
        """
        identifiers = {
            "container_name": container.name,
            "registry_url": container.registry_url,
            "digest": container.digest,
            "tag": container.tag,
            "search_terms": [],
            "package_patterns": [],
            "advisory_terms": [],
            "cve_terms": [],
        }

        # Extract base container name for pattern matching
        base_name = self._extract_base_name(container.name)

        # Get search patterns for this container - use individual terms, not combined
        if base_name in self._container_patterns:
            identifiers["search_terms"].extend(self._container_patterns[base_name])

        # Add container-specific terms as individual search queries
        identifiers["search_terms"].extend(
            [
                base_name,  # Just the base name
                "openshift-ai",  # Hyphenated version
                "rhods",  # Core product name
                "rhoai",  # Alternative product name
            ]
        )

        # Only add the actual container name if it's likely to be meaningful
        if not any(
            stop_word in container.name.lower()
            for stop_word in ["sha256", "latest", "registry"]
        ):
            identifiers["search_terms"].append(container.name)

        # Add package patterns based on container type
        identifiers["package_patterns"] = self._get_package_patterns(base_name)

        # Add advisory search terms as individual terms
        identifiers["advisory_terms"] = ["openshift-ai", "rhoai", "rhods", base_name]

        # Add CVE search terms as individual terms
        identifiers["cve_terms"] = ["openshift-ai", "rhoai", "rhods", base_name]

        # Remove duplicates while preserving order
        identifiers["search_terms"] = list(dict.fromkeys(identifiers["search_terms"]))
        identifiers["advisory_terms"] = list(
            dict.fromkeys(identifiers["advisory_terms"])
        )
        identifiers["cve_terms"] = list(dict.fromkeys(identifiers["cve_terms"]))

        logger.debug(
            f"Resolved {len(identifiers['search_terms'])} individual search terms for {container.name}: {identifiers['search_terms']}"
        )
        return identifiers

    def correlate_vulnerabilities_to_product(
        self,
        vulnerabilities: list[CVEData],
        product_listing: ProductListing,
        containers: list[ContainerImage],
    ) -> dict[str, Any]:
        """Correlate vulnerabilities back to specific product components.

        Args:
            vulnerabilities: List of CVE vulnerabilities
            product_listing: Product listing information
            containers: List of container images

        Returns:
            Correlation mapping between vulnerabilities and product components
        """
        correlation = {
            "total_vulnerabilities": len(vulnerabilities),
            "product_components": {},
            "operator_bundles": {},
            "container_mappings": {},
            "severity_distribution": {},
            "component_risk_scores": {},
            "generated_at": datetime.now().isoformat(),
        }

        logger.info(
            f"Correlating {len(vulnerabilities)} vulnerabilities to product components"
        )

        # Group vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        correlation["severity_distribution"] = severity_counts

        # Map vulnerabilities to containers
        for container in containers:
            container_key = container.name
            container_vulns = self._filter_vulnerabilities_for_container(
                vulnerabilities, container
            )

            if container_vulns:
                correlation["container_mappings"][container_key] = {
                    "vulnerabilities": len(container_vulns),
                    "critical": len(
                        [v for v in container_vulns if v.severity.value == "Critical"]
                    ),
                    "high": len(
                        [v for v in container_vulns if v.severity.value == "High"]
                    ),
                    "medium": len(
                        [v for v in container_vulns if v.severity.value == "Medium"]
                    ),
                    "low": len(
                        [v for v in container_vulns if v.severity.value == "Low"]
                    ),
                    "registry_url": container.registry_url,
                    "cve_ids": [v.cve_id for v in container_vulns[:10]],  # Top 10 CVEs
                }

        # Map vulnerabilities to operator bundles
        for bundle in product_listing.operator_bundles:
            bundle_key = f"{bundle.package}-{bundle.ocp_version}"
            bundle_containers = [
                c for c in containers if c.labels.get("bundle") == bundle.package
            ]

            bundle_vulns = []
            for container in bundle_containers:
                container_vulns = self._filter_vulnerabilities_for_container(
                    vulnerabilities, container
                )
                bundle_vulns.extend(container_vulns)

            if bundle_vulns:
                correlation["operator_bundles"][bundle_key] = {
                    "package": bundle.package,
                    "ocp_version": bundle.ocp_version,
                    "containers": len(bundle_containers),
                    "vulnerabilities": len(bundle_vulns),
                    "risk_score": self._calculate_risk_score(bundle_vulns),
                }

        # Calculate component risk scores
        for component, data in correlation["container_mappings"].items():
            risk_score = (
                data["critical"] * 10
                + data["high"] * 7
                + data["medium"] * 4
                + data["low"] * 1
            )
            correlation["component_risk_scores"][component] = risk_score

        logger.info(
            f"Correlation complete: {len(correlation['container_mappings'])} containers, "
            f"{len(correlation['operator_bundles'])} bundles analyzed"
        )

        return correlation

    def _map_bundle_to_queries(
        self, bundle: OperatorBundle, release_version: str
    ) -> list[dict[str, Any]]:
        """Map operator bundle to specific security queries.

        Args:
            bundle: Operator bundle information
            release_version: RHOAI release version

        Returns:
            List of individual security query parameters
        """
        queries = []

        # Get validated search terms for the bundle package
        validated_terms = self._get_validated_bundle_terms(bundle.package)

        for term in validated_terms:
            queries.append(
                {
                    "query_type": "operator_bundle",
                    "terms": [term],  # Single term per query
                    "version": release_version,
                    "ocp_version": bundle.ocp_version,
                    "priority": "high",
                }
            )

        # Channel-specific query (only if it's a valid search term)
        if bundle.channel and self._is_valid_search_term(bundle.channel):
            queries.append(
                {
                    "query_type": "operator_channel",
                    "terms": [bundle.channel],  # Single term per query
                    "version": release_version,
                    "priority": "medium",
                }
            )

        # CSV-specific query (only if it's a valid search term)
        if bundle.csv_name and self._is_valid_search_term(bundle.csv_name):
            queries.append(
                {
                    "query_type": "csv",
                    "terms": [bundle.csv_name],  # Single term per query
                    "version": release_version,
                    "priority": "medium",
                }
            )

        return queries

    def _get_validated_bundle_terms(self, bundle_package: str) -> list[str]:
        """Get validated search terms for a bundle package.

        Args:
            bundle_package: Bundle package name

        Returns:
            List of validated search terms that are likely to work with the API
        """
        terms = []

        # Known problematic patterns to avoid
        problematic_patterns = [
            "rhods-rhods-operator",
            "openshift-rhods-operator",
            "rhoai-rhoai",
            "rhods-rhods",
        ]

        # Base term (the package name itself)
        if self._is_valid_search_term(bundle_package):
            terms.append(bundle_package)

        # Generate alternative terms, avoiding problematic patterns
        potential_terms = [
            bundle_package,
            f"rhods-{bundle_package}",
            f"openshift-{bundle_package}",
        ]

        for term in potential_terms:
            # Skip terms that match problematic patterns
            if any(problematic in term.lower() for problematic in problematic_patterns):
                logger.debug(f"Skipping problematic term pattern: '{term}'")
                continue

            if self._is_valid_search_term(term) and term not in terms:
                terms.append(term)

        # If no terms are valid, provide safe fallbacks
        if not terms:
            logger.warning(
                f"No valid terms found for bundle '{bundle_package}', using fallbacks"
            )
            terms = ["rhods-operator", "openshift-ai", "rhoai"]

        logger.debug(
            f"Generated {len(terms)} validated terms for bundle '{bundle_package}': {terms}"
        )
        return terms

    def _is_valid_search_term(self, term: str) -> bool:
        """Check if a search term is likely to work with the Red Hat Security Data API.

        Args:
            term: Search term to validate

        Returns:
            True if the term is likely to work, False otherwise
        """
        if not term or not term.strip():
            return False

        term = term.strip()

        # Known problematic patterns
        problematic_patterns = [
            "rhods-rhods-operator",
            "openshift-rhods-operator",
            "rhoai-rhoai",
            "rhods-rhods",
            # Add more as discovered
        ]

        # Check for exact problematic matches
        if term.lower() in [p.lower() for p in problematic_patterns]:
            return False

        # Basic validation rules
        if len(term) < 3:  # Too short
            return False

        if term.count("-") > 2:  # Too many hyphens typically cause issues
            return False

        # Contains only valid characters (alphanumeric, hyphens, underscores, dots)
        import re

        if not re.match(r"^[a-zA-Z0-9\-_\.]+$", term):
            return False

        # Check for double hyphens or other suspicious patterns
        if "--" in term or term.startswith("-") or term.endswith("-"):
            return False

        return True

    def _extract_base_name(self, container_name: str) -> str:
        """Extract base name from container name for pattern matching.

        Args:
            container_name: Full container name

        Returns:
            Base container name for pattern matching
        """
        # Remove common suffixes
        suffixes_to_remove = ["-rhel8", "-rhel9", "-ubi8", "-ubi9"]
        base_name = container_name

        for suffix in suffixes_to_remove:
            if base_name.endswith(suffix):
                base_name = base_name[: -len(suffix)]
                break

        return base_name

    def _get_package_patterns(self, base_name: str) -> list[str]:
        """Get RPM package patterns for container type.

        Args:
            base_name: Base container name

        Returns:
            List of RPM package patterns to search for
        """
        patterns = []

        # Add base RHEL packages for all containers
        patterns.extend(self._package_mappings["rhel"])

        # Add specific patterns based on container type
        if "python" in base_name or "notebook" in base_name:
            patterns.extend(self._package_mappings["python"])

        if "java" in base_name:
            patterns.extend(self._package_mappings["java"])

        # Add container runtime packages for all
        patterns.extend(self._package_mappings["container"])

        return patterns

    def _filter_vulnerabilities_for_container(
        self, vulnerabilities: list[CVEData], container: ContainerImage
    ) -> list[CVEData]:
        """Filter vulnerabilities relevant to specific container.

        Args:
            vulnerabilities: All vulnerabilities
            container: Specific container

        Returns:
            Filtered list of relevant vulnerabilities
        """
        base_name = self._extract_base_name(container.name)
        container_patterns = self._container_patterns.get(base_name, [])

        relevant_vulns = []
        for vuln in vulnerabilities:
            # Check if vulnerability mentions container or related terms
            vuln_text = (
                f"{vuln.description} {vuln.package_name or ''} {vuln.cve_id}".lower()
            )

            # Check against container patterns
            for pattern in container_patterns:
                if pattern.lower() in vuln_text:
                    relevant_vulns.append(vuln)
                    break

            # Check direct container name match
            if base_name.lower() in vuln_text or container.name.lower() in vuln_text:
                if vuln not in relevant_vulns:
                    relevant_vulns.append(vuln)

        return relevant_vulns

    def _calculate_risk_score(self, vulnerabilities: list[CVEData]) -> float:
        """Calculate risk score for a set of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Calculated risk score (0-100)
        """
        if not vulnerabilities:
            return 0.0

        # Weight vulnerabilities by severity
        score = 0.0
        for vuln in vulnerabilities:
            if vuln.severity.value == "Critical":
                score += 10.0
            elif vuln.severity.value == "High":
                score += 7.0
            elif vuln.severity.value == "Medium":
                score += 4.0
            elif vuln.severity.value == "Low":
                score += 1.0

        # Normalize to 0-100 scale (cap at 100)
        return min(score, 100.0)
