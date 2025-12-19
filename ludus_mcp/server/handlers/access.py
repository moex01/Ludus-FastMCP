"""Access sharing and management handlers."""

from typing import Any
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class AccessHandler:
    """Handler for range access sharing and management."""

    def __init__(self, client: LudusAPIClient):
        """Initialize the access handler."""
        self.client = client

    async def get_range_access(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Get current access configuration for a range.

        Args:
            user_id: User ID (admin only)

        Returns:
            Access configuration
        """
        logger.info(f"Getting range access for user: {user_id or 'current'}")
        return await self.client.get_range_access(user_id)

    async def grant_range_access(
        self,
        users: list[str],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Grant other users access to your range.

        Args:
            users: List of user IDs to grant access to
            user_id: Range owner user ID (admin only)

        Returns:
            Updated access configuration
        """
        logger.info(f"Granting range access to users: {users}")

        # Get current access config
        current_access = await self.client.get_range_access(user_id)

        # Add new users to allowed list
        allowed_users = current_access.get("allowedUsers", [])
        for new_user in users:
            if new_user not in allowed_users:
                allowed_users.append(new_user)

        # Update access config
        access_config = {
            "allowedUsers": allowed_users
        }

        return await self.client.update_range_access(access_config, user_id)

    async def revoke_range_access(
        self,
        users: list[str],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Revoke access to your range from specific users.

        Args:
            users: List of user IDs to revoke access from
            user_id: Range owner user ID (admin only)

        Returns:
            Updated access configuration
        """
        logger.info(f"Revoking range access from users: {users}")

        # Get current access config
        current_access = await self.client.get_range_access(user_id)

        # Remove users from allowed list
        allowed_users = current_access.get("allowedUsers", [])
        allowed_users = [u for u in allowed_users if u not in users]

        # Update access config
        access_config = {
            "allowedUsers": allowed_users
        }

        return await self.client.update_range_access(access_config, user_id)

    async def set_range_access(
        self,
        users: list[str],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Set the complete list of users who can access your range.

        Args:
            users: Complete list of user IDs who should have access
            user_id: Range owner user ID (admin only)

        Returns:
            Updated access configuration
        """
        logger.info(f"Setting range access to users: {users}")

        access_config = {
            "allowedUsers": users
        }

        return await self.client.update_range_access(access_config, user_id)

    async def clear_range_access(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Remove all access grants from your range.

        Args:
            user_id: Range owner user ID (admin only)

        Returns:
            Updated access configuration
        """
        logger.info("Clearing all range access")

        access_config = {
            "allowedUsers": []
        }

        return await self.client.update_range_access(access_config, user_id)

    def format_access_info(self, access: dict[str, Any], owner_id: str | None = None) -> str:
        """Format access information for display."""
        allowed_users = access.get("allowedUsers", [])

        lines = ["## Range Access Configuration\n"]

        if owner_id:
            lines.append(f"**Range Owner:** {owner_id}")
            lines.append("")

        if allowed_users:
            lines.append(f"**Shared with {len(allowed_users)} user(s):**")
            for user in allowed_users:
                lines.append(f"  • {user}")
            lines.append("")
            lines.append("### Actions:")
            lines.append("- Revoke access: `ludus.revoke_range_access(users=['user_id'])`")
            lines.append("- Clear all access: `ludus.clear_range_access()`")
        else:
            lines.append("**Access:** Private (no users granted access)")
            lines.append("")
            lines.append("### Actions:")
            lines.append("- Grant access: `ludus.grant_range_access(users=['user_id1', 'user_id2'])`")

        return "\n".join(lines)
