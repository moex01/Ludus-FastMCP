"""Security and SIEM FastMCP tools for Ludus MCP server."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.siem import SIEMHandler
from ludus_mcp.server.handlers.wazuh import WazuhHandler
from ludus_mcp.server.handlers.access import AccessHandler
from ludus_mcp.server.handlers.security_compliance import SecurityComplianceHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_security_tools(client: LudusAPIClient) -> FastMCP:
    """Create security and SIEM tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with security tools registered
    """
    mcp = FastMCP("Security & SIEM")
    registry = LazyHandlerRegistry(client)

    # ==================== SIEM TOOLS ====================

    @mcp.tool()
    async def get_siem_info(user_id: str | None = None) -> dict:
        """Get SIEM information for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            SIEM configuration and status
        """
        handler = registry.get_handler("siem", SIEMHandler)
        result = await handler.get_siem_info(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_siem_alerts(
        user_id: str | None = None,
        severity: str | None = None,
        limit: int = 100
    ) -> list[dict]:
        """Get SIEM alerts for the range.

        Args:
            user_id: Optional user ID (admin only)
            severity: Filter by severity level (low, medium, high, critical)
            limit: Maximum number of alerts to return

        Returns:
            List of SIEM alerts
        """
        handler = registry.get_handler("siem", SIEMHandler)
        result = await handler.get_siem_alerts(user_id, severity, limit)
        return format_tool_response(result)

    @mcp.tool()
    async def get_siem_agents(user_id: str | None = None) -> list[dict]:
        """Get SIEM agents for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            List of SIEM agents
        """
        handler = registry.get_handler("siem", SIEMHandler)
        result = await handler.get_siem_agents(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_detection_summary(user_id: str | None = None) -> dict:
        """Get detection summary from SIEM.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Detection summary with statistics
        """
        handler = registry.get_handler("siem", SIEMHandler)
        result = await handler.get_detection_summary(user_id)
        return format_tool_response(result)

    # ==================== WAZUH TOOLS ====================

    @mcp.tool()
    async def get_wazuh_info(user_id: str | None = None) -> dict:
        """Get Wazuh SIEM information for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Wazuh configuration and status
        """
        handler = registry.get_handler("wazuh", WazuhHandler)
        result = await handler.get_wazuh_info(user_id)
        return format_tool_response(result)

    # ==================== ACCESS CONTROL TOOLS ====================

    @mcp.tool()
    async def get_range_access(user_id: str | None = None) -> dict:
        """Get range access configuration.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Range access configuration
        """
        handler = registry.get_handler("access", AccessHandler)
        result = await handler.get_range_access(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def grant_range_access(
        target_user_id: str,
        permissions: list[str],
        user_id: str | None = None
    ) -> dict:
        """Grant access to range for another user.

        Args:
            target_user_id: User ID to grant access to
            permissions: List of permissions to grant (read, write, admin)
            user_id: Optional user ID (admin only)

        Returns:
            Grant result
        """
        handler = registry.get_handler("access", AccessHandler)
        result = await handler.grant_range_access(target_user_id, permissions, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def revoke_range_access(
        target_user_id: str,
        user_id: str | None = None
    ) -> dict:
        """Revoke range access from a user.

        Args:
            target_user_id: User ID to revoke access from
            user_id: Optional user ID (admin only)

        Returns:
            Revoke result
        """
        handler = registry.get_handler("access", AccessHandler)
        result = await handler.revoke_range_access(target_user_id, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def clear_range_access(user_id: str | None = None) -> dict:
        """Clear all range access permissions.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Clear result
        """
        handler = registry.get_handler("access", AccessHandler)
        result = await handler.clear_range_access(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def range_access_logs(
        user_id: str | None = None,
        limit: int = 100
    ) -> list[dict]:
        """Get range access logs.

        Args:
            user_id: Optional user ID (admin only)
            limit: Maximum number of log entries to return

        Returns:
            List of access log entries
        """
        handler = registry.get_handler("access", AccessHandler)
        result = await handler.range_access_logs(user_id, limit)
        return format_tool_response(result)

    # ==================== SECURITY COMPLIANCE TOOLS ====================

    @mcp.tool()
    async def security_audit(user_id: str | None = None) -> dict:
        """Run security audit on the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Security audit report
        """
        handler = registry.get_handler("security_compliance", SecurityComplianceHandler)
        result = await handler.security_audit(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def compliance_check(
        framework: str = "nist",
        user_id: str | None = None
    ) -> dict:
        """Check compliance against security framework.

        Args:
            framework: Security framework to check against (nist, pci, iso27001)
            user_id: Optional user ID (admin only)

        Returns:
            Compliance check results
        """
        handler = registry.get_handler("security_compliance", SecurityComplianceHandler)
        result = await handler.compliance_check(framework, user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def rotate_credentials(user_id: str | None = None) -> dict:
        """Rotate credentials for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Credential rotation result
        """
        handler = registry.get_handler("security_compliance", SecurityComplianceHandler)
        result = await handler.rotate_credentials(user_id)
        return format_tool_response(result)

    @mcp.tool()
    async def get_vulnerability_scan(user_id: str | None = None) -> dict:
        """Get vulnerability scan results for the range.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Vulnerability scan results
        """
        handler = registry.get_handler("security_compliance", SecurityComplianceHandler)
        result = await handler.get_vulnerability_scan(user_id)
        return format_tool_response(result)

    return mcp
