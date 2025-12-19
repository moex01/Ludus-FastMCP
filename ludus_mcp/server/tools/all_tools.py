"""Complete tool registration - imports all tool modules and combines them."""

from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.tools.core import create_core_tools
from ludus_mcp.server.tools.deployment import create_deployment_tools
from ludus_mcp.server.tools.role_management import create_role_management_tools


def create_all_tools(client: LudusAPIClient) -> FastMCP:
    """Create and combine all FastMCP tool modules.

    This function creates a single FastMCP server with all tools from:
    - Core operations (ranges, snapshots, power, templates, hosts, networks, testing)
    - Deployment (scenarios, orchestration, monitoring, validation)

    Args:
        client: Ludus API client

    Returns:
        FastMCP server with all tools registered
    """
    # Start with core tools
    mcp = create_core_tools(client)

    # Create deployment tools and merge them
    deployment_mcp = create_deployment_tools(client)
    mcp.mount(deployment_mcp)

    # Create role management tools and merge them
    role_mcp = create_role_management_tools(client)
    mcp.mount(role_mcp)

    return mcp
