"""User management FastMCP tools for Ludus MCP server."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.users import UserHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_user_tools(client: LudusAPIClient) -> FastMCP:
    """Create user management tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with user management tools registered
    """
    mcp = FastMCP("User Management")
    registry = LazyHandlerRegistry(client)

    # ==================== USER MANAGEMENT TOOLS ====================

    @mcp.tool()
    async def list_users() -> list[dict]:
        """List all users in the Ludus system.

        Returns:
            List of all users with their information
        """
        handler = registry.get_handler("user", UserHandler)
        result = await handler.list_users()
        return format_tool_response(result)

    @mcp.tool()
    async def get_user(user_id: str) -> dict:
        """Get information about a specific user.

        Args:
            user_id: User ID to retrieve

        Returns:
            User information
        """
        handler = registry.get_handler("user", UserHandler)
        result = await handler.get_user(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def add_user(
        username: str,
        password: str,
        is_admin: bool = False,
        proxmox_username: str | None = None
    ) -> dict:
        """Add a new user to the Ludus system.

        Args:
            username: Username for the new user
            password: Password for the new user
            is_admin: Whether the user should have admin privileges
            proxmox_username: Optional Proxmox username for the user

        Returns:
            Created user information
        """
        handler = registry.get_handler("user", UserHandler)
        result = await handler.add_user(username, password, is_admin, proxmox_username)
        return format_tool_response(result)

    @mcp.tool()
    async def remove_user(user_id: str) -> dict:
        """Remove a user from the Ludus system.

        Args:
            user_id: User ID to remove

        Returns:
            Removal result
        """
        handler = registry.get_handler("user", UserHandler)
        result = await handler.remove_user(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_user_apikey(user_id: str) -> dict:
        """Get API key for a user.

        Args:
            user_id: User ID to get API key for

        Returns:
            User's API key information
        """
        handler = registry.get_handler("user", UserHandler)
        result = await handler.get_user_apikey(user_id)
        return format_tool_response(result)

    return mcp
