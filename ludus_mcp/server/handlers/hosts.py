"""Host operation handlers."""

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.schemas.hosts import Host, HostCreate, HostStatus
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.validation import validate_host_name

logger = get_logger(__name__)


class HostHandler:
    """Handler for host operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the host handler."""
        self.client = client

    async def create_host(self, range_id: str, data: HostCreate) -> Host:
        """Create a new host."""
        name = validate_host_name(data.name)
        logger.debug(f"Creating host: {name} in range {range_id}")

        result = await self.client.create_host(
            range_id=range_id,
            name=name,
            network_id=data.network_id,
            template=data.template,
            cpu=data.cpu,
            memory=data.memory,
            disk=data.disk,
            description=data.description,
        )
        return Host(**result)

    async def get_host(self, range_id: str, host_id: str) -> Host:
        """Get a host by ID."""
        logger.debug(f"Getting host: {host_id} in range {range_id}")
        result = await self.client.get_host(range_id, host_id)
        return Host(**result)

    async def list_hosts(self, range_id: str) -> list[Host]:
        """List all hosts in a range."""
        logger.debug(f"Listing hosts in range: {range_id}")
        results = await self.client.list_hosts(range_id)
        return [Host(**r) for r in results]

    async def start_host(self, range_id: str, host_id: str) -> HostStatus:
        """Start a host."""
        logger.debug(f"Starting host: {host_id} in range {range_id}")
        result = await self.client.start_host(range_id, host_id)
        return HostStatus(**result)

    async def stop_host(self, range_id: str, host_id: str) -> HostStatus:
        """Stop a host."""
        logger.debug(f"Stopping host: {host_id} in range {range_id}")
        result = await self.client.stop_host(range_id, host_id)
        return HostStatus(**result)

    async def delete_host(self, range_id: str, host_id: str) -> dict:
        """Delete a host."""
        logger.debug(f"Deleting host: {host_id} in range {range_id}")
        return await self.client.delete_host(range_id, host_id)

