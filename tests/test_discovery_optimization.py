"""Test the optimized container discovery functionality."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from rhoai_security_manifest.api.container_catalog import ContainerCatalogClient
from rhoai_security_manifest.api.product_listings import ProductListingsClient
from rhoai_security_manifest.utils.config import DiscoveryConfig


@pytest.mark.asyncio
async def test_discovery_strategy_configuration():
    """Test that discovery strategy configuration is properly validated."""
    # Test valid strategies
    valid_strategies = ["product_listings_primary", "targeted_api", "broad_search"]
    for strategy in valid_strategies:
        config = DiscoveryConfig(discovery_strategy=strategy)
        assert config.discovery_strategy == strategy

    # Test invalid strategy
    with pytest.raises(ValueError):
        DiscoveryConfig(discovery_strategy="invalid_strategy")


@pytest.mark.asyncio
async def test_product_listings_primary_strategy():
    """Test the product_listings_primary strategy prioritizes Product Listings."""
    # Mock Product Listings client
    mock_product_listings = AsyncMock(spec=ProductListingsClient)
    mock_product_listings.get_openshift_ai_product.return_value = MagicMock()
    mock_product_listings.map_version_to_containers.return_value = [
        MagicMock(
            repository="test-container",
            namespace="rhoai",
            registry="registry.redhat.io",
            source_bundle="test-bundle",
            ocp_versions=["4.14"],
            categories=["test"],
        )
    ]

    # Create client with mocked Product Listings
    client = ContainerCatalogClient(product_listings_client=mock_product_listings)

    # Mock the search_containers method to ensure it's not called
    client.search_containers = AsyncMock()

    # Test discovery with product_listings_primary strategy
    containers = await client.discover_rhoai_containers(
        release_version="2.8.0",
        discovery_strategy="product_listings_primary",
        hybrid_discovery=False,  # Disable hybrid to ensure only Product Listings is used
    )

    # Verify Product Listings was called
    mock_product_listings.get_openshift_ai_product.assert_called_once()
    mock_product_listings.map_version_to_containers.assert_called_once()

    # Verify search_containers was NOT called (broad search avoided)
    client.search_containers.assert_not_called()

    # Verify we got containers
    assert len(containers) == 1
    assert containers[0].name == "test-container"
    assert "product_listings" in containers[0].labels["source"]


@pytest.mark.asyncio
async def test_targeted_api_strategy():
    """Test the targeted_api strategy performs verification calls."""
    # Mock Product Listings client
    mock_product_listings = AsyncMock(spec=ProductListingsClient)
    mock_product_listings.get_openshift_ai_product.return_value = MagicMock()
    mock_product_listings.map_version_to_containers.return_value = [
        MagicMock(
            repository="test-container",
            namespace="rhoai",
            registry="registry.redhat.io",
            source_bundle="test-bundle",
            ocp_versions=["4.14"],
            categories=["test"],
        )
    ]

    # Create client with mocked Product Listings
    client = ContainerCatalogClient(product_listings_client=mock_product_listings)

    # Mock the _verify_container_exists method
    client._verify_container_exists = AsyncMock(
        return_value=None
    )  # Simulate API verification failure

    # Test discovery with targeted_api strategy
    containers = await client.discover_rhoai_containers(
        release_version="2.8.0",
        discovery_strategy="targeted_api",
        hybrid_discovery=False,
    )

    # Verify Product Listings was called
    mock_product_listings.get_openshift_ai_product.assert_called_once()

    # Verify verification was attempted
    client._verify_container_exists.assert_called_once()

    # Should fall back to Product Listings data when verification fails
    assert len(containers) == 1
    assert "product_listings_fallback" in containers[0].labels["source"]


@pytest.mark.asyncio
async def test_caching_functionality():
    """Test that response caching works correctly."""
    client = ContainerCatalogClient()

    # Test cache initialization
    assert hasattr(client, "_response_cache")
    assert isinstance(client._response_cache, dict)

    # Test cache key generation and storage would be done in actual verification
    # This is a basic test to ensure the cache attribute exists


def test_max_api_pages_configuration():
    """Test that max_api_pages configuration is properly set."""
    config = DiscoveryConfig(max_api_pages=50)
    assert config.max_api_pages == 50

    # Test validation
    with pytest.raises(ValueError):
        DiscoveryConfig(max_api_pages=5)  # Below minimum

    with pytest.raises(ValueError):
        DiscoveryConfig(max_api_pages=1000)  # Above maximum


if __name__ == "__main__":
    pytest.main([__file__])
