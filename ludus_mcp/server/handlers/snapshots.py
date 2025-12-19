"""Snapshot operation handlers."""

from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class SnapshotHandler:
    """Handler for snapshot operations (Ludus API format)."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the snapshot handler."""
        self.client = client

    async def list_snapshots(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List all snapshots for the range."""
        logger.debug(f"Listing snapshots for user: {user_id or 'current'}")
        return await self.client.list_snapshots(user_id)

    async def create_snapshot(
        self, snapshot_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Create a snapshot."""
        logger.debug(f"Creating snapshot for user: {user_id or 'current'}")
        return await self.client.create_snapshot(snapshot_config, user_id)

    async def rollback_snapshot(
        self, snapshot_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Rollback to a snapshot."""
        logger.debug(f"Rolling back snapshot for user: {user_id or 'current'}")
        return await self.client.rollback_snapshot(snapshot_config, user_id)

    async def remove_snapshot(
        self, snapshot_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Remove a snapshot."""
        logger.debug(f"Removing snapshot for user: {user_id or 'current'}")
        return await self.client.remove_snapshot(snapshot_config, user_id)

