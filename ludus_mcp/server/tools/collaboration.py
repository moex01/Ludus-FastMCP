"""Collaboration and resource management FastMCP tools for Ludus MCP server."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.collaboration import CollaborationHandler
from ludus_mcp.server.handlers.resource_management import ResourceManagementHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_collaboration_tools(client: LudusAPIClient) -> FastMCP:
    """Create collaboration and resource management tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with collaboration tools registered
    """
    mcp = FastMCP("Collaboration & Resources")
    registry = LazyHandlerRegistry(client)

    # ==================== COLLABORATION TOOLS ====================

    @mcp.tool()
    async def share_range_config(
        target_user_ids: list[str] | None = None,
        make_public: bool = False,
        permissions: list[str] | None = None,
        user_id: str | None = None
    ) -> dict:
        """Share range configuration with other users.

        Args:
            target_user_ids: List of user IDs to share with
            make_public: Make configuration publicly accessible
            permissions: Permissions to grant (read, clone, modify)
            user_id: Optional user ID (admin only)

        Returns:
            Share result with access link
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.share_range_config(
            target_user_ids, make_public, permissions, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def import_community_scenario(
        scenario_url: str,
        user_id: str | None = None
    ) -> dict:
        """Import a scenario from the community repository.

        Args:
            scenario_url: URL to community scenario
            user_id: Optional user ID (admin only)

        Returns:
            Import result with scenario information
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.import_community_scenario(scenario_url, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def publish_scenario(
        scenario_key: str,
        title: str,
        description: str,
        tags: list[str] | None = None,
        public: bool = True,
        user_id: str | None = None
    ) -> dict:
        """Publish a scenario to the community repository.

        Args:
            scenario_key: Scenario to publish
            title: Scenario title
            description: Scenario description
            tags: Optional tags for categorization
            public: Make scenario publicly accessible
            user_id: Optional user ID (admin only)

        Returns:
            Publish result with scenario URL
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.publish_scenario(
            scenario_key, title, description, tags, public, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def list_range_templates(user_id: str | None = None) -> list[dict]:
        """List available range templates from the community.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            List of range templates
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.list_range_templates(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_range_template(
        template_id: str,
        user_id: str | None = None
    ) -> dict:
        """Get a specific range template configuration.

        Args:
            template_id: Range template ID
            user_id: Optional user ID (admin only)

        Returns:
            Range template configuration
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.get_range_template(template_id, user_id)
        return format_tool_response(result)

    # ==================== RESOURCE MANAGEMENT TOOLS ====================

    @mcp.tool()
    async def get_resource_quotas(user_id: str | None = None) -> dict:
        """Get resource quotas and current usage.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Resource quotas and usage information
        """
        handler = registry.get_handler("resource_management", ResourceManagementHandler)
        result = await handler.get_resource_quotas(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def optimize_resource_allocation(
        user_id: str | None = None
    ) -> dict:
        """Optimize resource allocation for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Optimization recommendations and applied changes
        """
        handler = registry.get_handler("resource_management", ResourceManagementHandler)
        result = await handler.optimize_resource_allocation(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def schedule_maintenance_window(
        start_time: str,
        duration_minutes: int,
        operations: list[str],
        notify_users: bool = True,
        user_id: str | None = None
    ) -> dict:
        """Schedule a maintenance window for the range.

        Args:
            start_time: Start time in ISO format
            duration_minutes: Duration in minutes
            operations: List of operations to perform during maintenance
            notify_users: Send notifications to users with access
            user_id: Optional user ID (admin only)

        Returns:
            Maintenance window scheduling result
        """
        handler = registry.get_handler("resource_management", ResourceManagementHandler)
        result = await handler.schedule_maintenance_window(
            start_time, duration_minutes, operations, notify_users, user_id
        )
        return format_tool_response(result)

    # ==================== INTERACTIVE TOOLS ====================

    @mcp.tool()
    async def interactive_build_range(
        prompt: str,
        user_id: str | None = None
    ) -> dict:
        """Interactively build a range using natural language prompts.

        Args:
            prompt: Natural language description of desired range
            user_id: Optional user ID (admin only)

        Returns:
            Suggested configuration and deployment plan
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.interactive_build_range(prompt, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def build_range_from_prompt(
        prompt: str,
        auto_deploy: bool = False,
        user_id: str | None = None
    ) -> dict:
        """Build a range configuration from a natural language prompt.

        Args:
            prompt: Natural language description of desired range
            auto_deploy: Automatically deploy after building configuration
            user_id: Optional user ID (admin only)

        Returns:
            Generated configuration and deployment result if auto_deploy=True
        """
        handler = registry.get_handler("collaboration", CollaborationHandler)
        result = await handler.build_range_from_prompt(prompt, auto_deploy, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def list_ranges(user_id: str | None = None) -> list[dict]:
        """List all ranges (admin only).

        Args:
            user_id: Optional user ID (must be admin)

        Returns:
            List of all ranges in the system
        """
        result = await client.list_ranges()
        return format_tool_response(result)

    return mcp
