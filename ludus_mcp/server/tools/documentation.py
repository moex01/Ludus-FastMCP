"""Documentation generation FastMCP tools for Ludus MCP server."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.documentation import DocumentationHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_documentation_tools(client: LudusAPIClient) -> FastMCP:
    """Create documentation generation tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with documentation tools registered
    """
    mcp = FastMCP("Documentation")
    registry = LazyHandlerRegistry(client)

    # ==================== DOCUMENTATION GENERATION TOOLS ====================

    @mcp.tool()
    async def generate_range_documentation(
        format: str = "markdown",
        include_network_diagram: bool = True,
        include_credentials: bool = False,
        user_id: str | None = None
    ) -> dict:
        """Generate comprehensive documentation for the range.

        Args:
            format: Documentation format (markdown, html, pdf)
            include_network_diagram: Include network topology diagram
            include_credentials: Include credentials in documentation
            user_id: Optional user ID (admin only)

        Returns:
            Documentation content or download link
        """
        handler = registry.get_handler("documentation", DocumentationHandler)
        result = await handler.generate_range_documentation(
            format, include_network_diagram, include_credentials, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def get_attack_path_documentation(
        scenario_key: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Generate attack path documentation for a scenario.

        Args:
            scenario_key: Optional scenario key (defaults to current deployment)
            user_id: Optional user ID (admin only)

        Returns:
            Attack path documentation with techniques and mitigations
        """
        handler = registry.get_handler("documentation", DocumentationHandler)
        result = await handler.get_attack_path_documentation(scenario_key, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def export_lab_guide(
        scenario_key: str | None = None,
        format: str = "markdown",
        include_solutions: bool = False,
        user_id: str | None = None
    ) -> dict:
        """Export lab guide for training purposes.

        Args:
            scenario_key: Optional scenario key (defaults to current deployment)
            format: Export format (markdown, html, pdf)
            include_solutions: Include solution steps
            user_id: Optional user ID (admin only)

        Returns:
            Lab guide content or download link
        """
        handler = registry.get_handler("documentation", DocumentationHandler)
        result = await handler.export_lab_guide(
            scenario_key, format, include_solutions, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def create_scenario_playbook(
        scenario_key: str,
        title: str,
        description: str,
        objectives: list[str],
        steps: list[dict[str, Any]],
        user_id: str | None = None
    ) -> dict:
        """Create a scenario playbook for training.

        Args:
            scenario_key: Scenario identifier
            title: Playbook title
            description: Playbook description
            objectives: Learning objectives
            steps: List of playbook steps with instructions
            user_id: Optional user ID (admin only)

        Returns:
            Created playbook information
        """
        handler = registry.get_handler("documentation", DocumentationHandler)
        result = await handler.create_scenario_playbook(
            scenario_key, title, description, objectives, steps, user_id
        )
        return format_tool_response(result)

    return mcp
