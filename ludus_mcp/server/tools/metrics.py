"""Metrics and monitoring FastMCP tools for Ludus MCP server."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.metrics import MetricsHandler
from ludus_mcp.server.handlers.inventory import InventoryHandler
from ludus_mcp.server.handlers.network_analysis import NetworkAnalysisHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_metrics_tools(client: LudusAPIClient) -> FastMCP:
    """Create metrics and monitoring tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with metrics tools registered
    """
    mcp = FastMCP("Metrics & Monitoring")
    registry = LazyHandlerRegistry(client)

    # ==================== METRICS TOOLS ====================

    @mcp.tool()
    async def get_range_metrics(user_id: str | None = None) -> dict:
        """Get comprehensive metrics for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Range metrics (CPU, memory, disk, network usage)
        """
        handler = registry.get_handler("metrics", MetricsHandler)
        result = await handler.get_range_metrics(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_deployment_metrics(
        deployment_id: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Get metrics for a specific deployment.

        Args:
            deployment_id: Optional deployment ID (defaults to current)
            user_id: Optional user ID (admin only)

        Returns:
            Deployment metrics
        """
        handler = registry.get_handler("metrics", MetricsHandler)
        result = await handler.get_deployment_metrics(deployment_id, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_cost_estimation(user_id: str | None = None) -> dict:
        """Get cost estimation for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Cost estimation based on resource usage
        """
        handler = registry.get_handler("metrics", MetricsHandler)
        result = await handler.get_cost_estimation(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def export_metrics(
        format: str = "json",
        start_time: str | None = None,
        end_time: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Export metrics data.

        Args:
            format: Export format (json, csv, prometheus)
            start_time: Optional start time for metrics (ISO format)
            end_time: Optional end time for metrics (ISO format)
            user_id: Optional user ID (admin only)

        Returns:
            Exported metrics data
        """
        handler = registry.get_handler("metrics", MetricsHandler)
        result = await handler.export_metrics(format, start_time, end_time, user_id)
        return format_tool_response(result)

    # ==================== INVENTORY TOOLS ====================

    @mcp.tool()
    async def get_range_ansible_inventory(user_id: str | None = None) -> str:
        """Get Ansible inventory for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Ansible inventory in INI format
        """
        result = await client.get_range_ansible_inventory(user_id)
        return result

    @mcp.tool()
    async def get_range_sshconfig(user_id: str | None = None) -> str:
        """Get SSH config for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            SSH config content
        """
        result = await client.get_range_sshconfig(user_id)
        return result

    @mcp.tool()
    async def get_range_rdpconfigs(user_id: str | None = None) -> dict:
        """Get RDP configuration files for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary of VM names to RDP config content
        """
        result = await client.get_range_rdpconfigs(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_range_etchosts(user_id: str | None = None) -> str:
        """Get /etc/hosts entries for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            /etc/hosts content
        """
        result = await client.get_range_etchosts(user_id)
        return result

    # ==================== NETWORK ANALYSIS TOOLS ====================

    @mcp.tool()
    async def test_network_connectivity(
        source_vm: str,
        target_vm: str,
        protocol: str = "tcp",
        port: int | None = None,
        user_id: str | None = None
    ) -> dict:
        """Test network connectivity between VMs.

        Args:
            source_vm: Source VM name
            target_vm: Target VM name
            protocol: Protocol to test (tcp, udp, icmp)
            port: Optional port number for tcp/udp
            user_id: Optional user ID (admin only)

        Returns:
            Connectivity test result
        """
        handler = registry.get_handler("network_analysis", NetworkAnalysisHandler)
        result = await handler.test_network_connectivity(
            source_vm, target_vm, protocol, port, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def get_network_topology(user_id: str | None = None) -> dict:
        """Get network topology visualization data.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Network topology data
        """
        handler = registry.get_handler("network_analysis", NetworkAnalysisHandler)
        result = await handler.get_network_topology(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def diagnose_network_issues(user_id: str | None = None) -> dict:
        """Diagnose network connectivity issues.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Network diagnostics report
        """
        handler = registry.get_handler("network_analysis", NetworkAnalysisHandler)
        result = await handler.diagnose_network_issues(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def capture_network_traffic(
        vm_name: str,
        interface: str = "eth0",
        duration: int = 60,
        filter: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Capture network traffic on a VM.

        Args:
            vm_name: VM name to capture traffic from
            interface: Network interface to capture on
            duration: Capture duration in seconds
            filter: Optional BPF filter expression
            user_id: Optional user ID (admin only)

        Returns:
            Traffic capture result with download link
        """
        handler = registry.get_handler("network_analysis", NetworkAnalysisHandler)
        result = await handler.capture_network_traffic(
            vm_name, interface, duration, filter, user_id
        )
        return format_tool_response(result)

    @mcp.tool()
    async def visualize_range(user_id: str | None = None) -> dict:
        """Generate visualization data for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Visualization data (network diagram, topology, etc.)
        """
        handler = registry.get_handler("network_analysis", NetworkAnalysisHandler)
        result = await handler.visualize_range(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def health_checks(user_id: str | None = None) -> dict:
        """Run health checks on all VMs in the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Health check results for all VMs
        """
        handler = registry.get_handler("metrics", MetricsHandler)
        result = await handler.health_checks(user_id)
        return format_tool_response(result)

    return mcp
