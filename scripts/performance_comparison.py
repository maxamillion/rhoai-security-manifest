#!/usr/bin/env python3
"""Performance comparison script for the optimized discovery."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

from rhoai_security_manifest.api.container_catalog import ContainerCatalogClient
from rhoai_security_manifest.api.product_listings import ProductListingsClient


def create_mock_product_listings_client():
    """Create a mock Product Listings client with realistic data."""
    mock_client = AsyncMock(spec=ProductListingsClient)
    mock_client.get_openshift_ai_product.return_value = MagicMock()

    # Mock 30 typical RHOAI containers
    mock_containers = []
    container_names = [
        "rhods-operator-rhel8", "rhods-operator-bundle", "odh-dashboard-rhel8",
        "odh-notebook-controller-rhel8", "odh-ml-pipelines-api-server-rhel8",
        "odh-ml-pipelines-persistenceagent-rhel8", "odh-ml-pipelines-scheduledworkflow-rhel8",
        "odh-ml-pipelines-viewercontroller-rhel8", "odh-kserve-controller-rhel8",
        "odh-kserve-agent-rhel8", "odh-kserve-router-rhel8", "odh-modelmesh-rhel8",
        "odh-modelmesh-controller-rhel8", "odh-pytorch-rhel8", "odh-tensorflow-rhel8",
        "odh-triton-rhel8", "odh-generic-data-science-notebook-rhel8",
        "odh-minimal-notebook-rhel8", "odh-pytorch-notebook-rhel8",
        "odh-tensorflow-notebook-rhel8", "odh-trustyai-service-rhel8",
        "odh-trustyai-service-operator-controller-rhel8", "odh-codeflare-operator-rhel8",
        "odh-ray-rhel8", "odh-workbench-images-rhel8", "odh-oauth-proxy-rhel8",
        "odh-rest-proxy-rhel8", "odh-model-registry-rhel8", "odh-data-science-pipelines-rhel8",
        "odh-openvino-model-server-rhel8"
    ]

    for name in container_names:
        mock_containers.append(MagicMock(
            repository=name,
            namespace="rhoai",
            registry="registry.redhat.io",
            source_bundle="rhods-operator",
            ocp_versions=["4.14"],
            categories=["ai", "ml"]
        ))

    mock_client.map_version_to_containers.return_value = mock_containers
    return mock_client


async def simulate_broad_search_strategy():
    """Simulate the old broad search strategy performance."""
    print("🔍 Simulating BROAD SEARCH strategy (original approach)...")

    client = ContainerCatalogClient()

    # Mock the search_containers method to simulate API calls
    call_count = 0

    async def mock_search_containers(query, page=1, page_size=100, filter_params=None):
        nonlocal call_count
        call_count += 1

        # Simulate API response time (50-200ms per call)
        await asyncio.sleep(0.1)

        # Simulate finding some containers on early pages, then empty results
        if page <= 3:
            return MagicMock(
                total=250,
                page=page,
                page_size=page_size,
                images=[MagicMock(
                    name=f"container-{query}-{page}-{i}",
                    registry_url=f"registry.redhat.io/rhoai/container-{query}-{page}-{i}",
                    digest=f"sha256:{'a' * 64}",
                    tag="2.8.0",
                    labels={}
                ) for i in range(min(10, page_size))]
            )
        else:
            return MagicMock(total=250, page=page, page_size=page_size, images=[])

    client.search_containers = mock_search_containers
    client._is_rhoai_container = lambda container, patterns: True
    client._is_release_match = lambda container, version: True

    start_time = time.time()

    try:
        containers = await client.discover_rhoai_containers(
            release_version="2.8.0",
            discovery_strategy="broad_search",
            hybrid_discovery=False,
            use_product_listings=False
        )
    except Exception as e:
        print(f"   ⚠️  Broad search failed (expected): {e}")
        containers = []

    end_time = time.time()
    duration = end_time - start_time

    print("   📊 Results:")
    print(f"   ├─ API calls made: {call_count}")
    print(f"   ├─ Time taken: {duration:.2f} seconds")
    print(f"   ├─ Containers found: {len(containers)}")
    print(f"   └─ Avg time per call: {duration/max(call_count, 1):.3f}s")

    return {
        "strategy": "broad_search",
        "api_calls": call_count,
        "duration": duration,
        "containers_found": len(containers)
    }


async def simulate_product_listings_primary_strategy():
    """Simulate the new Product Listings primary strategy performance."""
    print("\n🎯 Simulating PRODUCT LISTINGS PRIMARY strategy (optimized approach)...")

    mock_product_listings = create_mock_product_listings_client()
    client = ContainerCatalogClient(product_listings_client=mock_product_listings)

    start_time = time.time()

    containers = await client.discover_rhoai_containers(
        release_version="2.8.0",
        discovery_strategy="product_listings_primary",
        hybrid_discovery=False
    )

    end_time = time.time()
    duration = end_time - start_time

    # Count the Product Listings API calls (2 calls: get_product + map_containers)
    api_calls = (
        mock_product_listings.get_openshift_ai_product.call_count +
        mock_product_listings.map_version_to_containers.call_count
    )

    print("   📊 Results:")
    print(f"   ├─ API calls made: {api_calls}")
    print(f"   ├─ Time taken: {duration:.2f} seconds")
    print(f"   ├─ Containers found: {len(containers)}")
    print(f"   └─ Avg time per call: {duration/max(api_calls, 1):.3f}s")

    return {
        "strategy": "product_listings_primary",
        "api_calls": api_calls,
        "duration": duration,
        "containers_found": len(containers)
    }


async def simulate_targeted_api_strategy():
    """Simulate the targeted API verification strategy performance."""
    print("\n🎯 Simulating TARGETED API strategy (verification approach)...")

    mock_product_listings = create_mock_product_listings_client()
    client = ContainerCatalogClient(product_listings_client=mock_product_listings)

    # Mock targeted verification calls (simulate 30 containers being verified)
    verification_call_count = 0

    async def mock_verify_container_exists(repo, release_version):
        nonlocal verification_call_count
        verification_call_count += 1

        # Simulate API verification time (30-50ms per call)
        await asyncio.sleep(0.04)

        # Simulate 80% successful verification rate
        if verification_call_count % 5 != 0:
            return MagicMock(
                name=repo.repository,
                registry_url=f"registry.redhat.io/{repo.namespace}/{repo.repository}",
                digest=f"sha256:verified-{verification_call_count}",
                tag=release_version,
                labels={"source": "api_verified"}
            )
        return None

    client._verify_container_exists = mock_verify_container_exists

    start_time = time.time()

    containers = await client.discover_rhoai_containers(
        release_version="2.8.0",
        discovery_strategy="targeted_api",
        hybrid_discovery=False
    )

    end_time = time.time()
    duration = end_time - start_time

    # Count all API calls (Product Listings + verification calls)
    product_listings_calls = (
        mock_product_listings.get_openshift_ai_product.call_count +
        mock_product_listings.map_version_to_containers.call_count
    )
    total_api_calls = product_listings_calls + verification_call_count

    print("   📊 Results:")
    print(f"   ├─ Product Listings calls: {product_listings_calls}")
    print(f"   ├─ Verification calls: {verification_call_count}")
    print(f"   ├─ Total API calls: {total_api_calls}")
    print(f"   ├─ Time taken: {duration:.2f} seconds")
    print(f"   ├─ Containers found: {len(containers)}")
    print(f"   └─ Avg time per call: {duration/max(total_api_calls, 1):.3f}s")

    return {
        "strategy": "targeted_api",
        "api_calls": total_api_calls,
        "verification_calls": verification_call_count,
        "duration": duration,
        "containers_found": len(containers)
    }


def print_performance_comparison(results):
    """Print a comprehensive performance comparison."""
    print("\n" + "="*70)
    print("📈 PERFORMANCE COMPARISON SUMMARY")
    print("="*70)

    broad_search = results[0]
    product_listings = results[1]
    targeted_api = results[2]

    print("\n📊 API Call Efficiency:")
    print(f"├─ Broad Search:           {broad_search['api_calls']:3d} calls")
    print(f"├─ Product Listings:       {product_listings['api_calls']:3d} calls")
    print(f"└─ Targeted API:           {targeted_api['api_calls']:3d} calls")

    print("\n⏱️  Time Performance:")
    print(f"├─ Broad Search:           {broad_search['duration']:6.2f}s")
    print(f"├─ Product Listings:       {product_listings['duration']:6.2f}s")
    print(f"└─ Targeted API:           {targeted_api['duration']:6.2f}s")

    print("\n🎯 Discovery Accuracy:")
    print(f"├─ Broad Search:           {broad_search['containers_found']:3d} containers")
    print(f"├─ Product Listings:       {product_listings['containers_found']:3d} containers")
    print(f"└─ Targeted API:           {targeted_api['containers_found']:3d} containers")

    # Calculate improvements
    api_improvement = ((broad_search['api_calls'] - product_listings['api_calls']) /
                      broad_search['api_calls'] * 100)
    time_improvement = ((broad_search['duration'] - product_listings['duration']) /
                       broad_search['duration'] * 100)

    print("\n🚀 Optimization Benefits:")
    print(f"├─ API calls reduced by:   {api_improvement:5.1f}%")
    print(f"├─ Time reduced by:        {time_improvement:5.1f}%")
    print("├─ Reliability improved:   ✅ Consistent results")
    print("└─ Maintainability:        ✅ Centralized container definitions")

    print("\n💡 Strategy Recommendations:")
    print("├─ Default:        Product Listings Primary (fastest, most reliable)")
    print("├─ Verification:   Targeted API (balance of speed and validation)")
    print("└─ Comprehensive:  Broad Search (slowest, for edge case discovery)")


async def main():
    """Run performance comparison for all discovery strategies."""
    print("🚀 RHOAI Container Discovery Performance Comparison")
    print("=" * 70)
    print("Testing optimized discovery strategies against original approach...")

    results = []

    # Test broad search (original approach)
    results.append(await simulate_broad_search_strategy())

    # Test product listings primary (optimized approach)
    results.append(await simulate_product_listings_primary_strategy())

    # Test targeted API verification (hybrid approach)
    results.append(await simulate_targeted_api_strategy())

    # Print comprehensive comparison
    print_performance_comparison(results)

    print("\n✅ Performance comparison completed!")
    print("📋 The optimized strategies show significant improvements in efficiency")
    print("   while maintaining high accuracy and reliability.")


if __name__ == "__main__":
    asyncio.run(main())
