"""Power state management handlers."""

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class PowerHandler:
    """Handler for power state operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the power handler."""
        self.client = client

    async def power_on_range(self, user_id: str | None = None) -> dict:
        """Power on all VMs in the range."""
        logger.debug(f"Powering on range for user: {user_id or 'current'}")
        return await self.client.power_on_range(user_id)

    async def power_off_range(self, user_id: str | None = None) -> dict:
        """Power off all VMs in the range."""
        logger.debug(f"Powering off range for user: {user_id or 'current'}")
        return await self.client.power_off_range(user_id)

