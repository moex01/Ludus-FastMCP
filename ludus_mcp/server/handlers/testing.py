"""Testing state management handlers."""

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class TestingHandler:
    """Handler for testing state operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the testing handler."""
        self.client = client

    async def start_testing(self, user_id: str | None = None) -> dict:
        """Start testing state."""
        logger.debug(f"Starting testing for user: {user_id or 'current'}")
        return await self.client.start_testing(user_id)

    async def stop_testing(self, user_id: str | None = None) -> dict:
        """Stop testing state."""
        logger.debug(f"Stopping testing for user: {user_id or 'current'}")
        return await self.client.stop_testing(user_id)

    async def allow_testing(
        self, allowed_config: dict, user_id: str | None = None
    ) -> dict:
        """Allow testing from specific IPs/domains."""
        logger.debug(f"Allowing testing for user: {user_id or 'current'}")
        return await self.client.allow_testing(allowed_config, user_id)

    async def deny_testing(
        self, denied_config: dict, user_id: str | None = None
    ) -> dict:
        """Deny testing from specific IPs/domains."""
        logger.debug(f"Denying testing for user: {user_id or 'current'}")
        return await self.client.deny_testing(denied_config, user_id)

    async def update_testing(
        self, testing_config: dict, user_id: str | None = None
    ) -> dict:
        """Update testing configuration."""
        logger.debug(f"Updating testing config for user: {user_id or 'current'}")
        return await self.client.update_testing(testing_config, user_id)

