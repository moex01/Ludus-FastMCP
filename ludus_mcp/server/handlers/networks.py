"""Network operation handlers."""

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.schemas.networks import Network, NetworkCreate
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.validation import validate_network_name

logger = get_logger(__name__)


class NetworkHandler:
    """Handler for network operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the network handler."""
        self.client = client

    async def create_network(self, range_id: str, data: NetworkCreate) -> Network:
        """Create a new network."""
        name = validate_network_name(data.name)
        logger.debug(f"Creating network: {name} in range {range_id}")

        result = await self.client.create_network(
            range_id, name, data.cidr, data.description
        )
        return Network(**result)

    async def get_network(self, range_id: str, network_id: str) -> Network:
        """Get a network by ID."""
        logger.debug(f"Getting network: {network_id} in range {range_id}")
        result = await self.client.get_network(range_id, network_id)
        return Network(**result)

    async def list_networks(self, range_id: str) -> list[Network]:
        """List all networks in a range."""
        logger.debug(f"Listing networks in range: {range_id}")
        results = await self.client.list_networks(range_id)
        return [Network(**r) for r in results]

    async def delete_network(self, range_id: str, network_id: str) -> dict:
        """Delete a network."""
        logger.debug(f"Deleting network: {network_id} in range {range_id}")
        return await self.client.delete_network(range_id, network_id)

