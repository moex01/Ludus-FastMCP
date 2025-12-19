"""Integration FastMCP tools for Ludus MCP server - webhooks, Slack, Jira, Git."""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.integrations import IntegrationsHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response


def create_integration_tools(client: LudusAPIClient) -> FastMCP:
    """Create integration tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with integration tools registered
    """
    mcp = FastMCP("Integrations")
    registry = LazyHandlerRegistry(client)

    # ==================== WEBHOOK INTEGRATION ====================

    @mcp.tool()
    async def webhook_integration(
        action: str,
        webhook_url: str | None = None,
        events: list[str] | None = None,
        webhook_id: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Manage webhook integrations.

        Args:
            action: Action to perform (create, update, delete, list, test)
            webhook_url: Webhook URL (for create/update)
            events: List of events to trigger webhook (for create/update)
            webhook_id: Webhook ID (for update/delete/test)
            user_id: Optional user ID (admin only)

        Returns:
            Webhook operation result
        """
        handler = registry.get_handler("integration", IntegrationsHandler)
        result = await handler.webhook_integration(
            action, webhook_url, events, webhook_id, user_id
        )
        return format_tool_response(result)

    # ==================== SLACK INTEGRATION ====================

    @mcp.tool()
    async def slack_notifications(
        action: str,
        webhook_url: str | None = None,
        channel: str | None = None,
        events: list[str] | None = None,
        user_id: str | None = None
    ) -> dict:
        """Configure Slack notifications.

        Args:
            action: Action to perform (enable, disable, test, configure)
            webhook_url: Slack webhook URL
            channel: Slack channel name
            events: List of events to notify on
            user_id: Optional user ID (admin only)

        Returns:
            Slack integration result
        """
        handler = registry.get_handler("integration", IntegrationsHandler)
        result = await handler.slack_notifications(
            action, webhook_url, channel, events, user_id
        )
        return format_tool_response(result)

    # ==================== JIRA INTEGRATION ====================

    @mcp.tool()
    async def jira_integration(
        action: str,
        jira_url: str | None = None,
        project_key: str | None = None,
        api_token: str | None = None,
        issue_id: str | None = None,
        user_id: str | None = None
    ) -> dict:
        """Integrate with Jira for issue tracking.

        Args:
            action: Action to perform (configure, create_issue, update_issue, link_deployment)
            jira_url: Jira instance URL
            project_key: Jira project key
            api_token: Jira API token
            issue_id: Jira issue ID (for update/link operations)
            user_id: Optional user ID (admin only)

        Returns:
            Jira integration result
        """
        handler = registry.get_handler("integration", IntegrationsHandler)
        result = await handler.jira_integration(
            action, jira_url, project_key, api_token, issue_id, user_id
        )
        return format_tool_response(result)

    # ==================== GIT SYNC ====================

    @mcp.tool()
    async def git_sync(
        action: str,
        repo_url: str | None = None,
        branch: str = "main",
        sync_direction: str = "pull",
        credentials: dict[str, str] | None = None,
        user_id: str | None = None
    ) -> dict:
        """Sync range configurations with Git repository.

        Args:
            action: Action to perform (configure, sync, status)
            repo_url: Git repository URL
            branch: Git branch to sync with
            sync_direction: Sync direction (pull, push, bidirectional)
            credentials: Git credentials (username, password/token)
            user_id: Optional user ID (admin only)

        Returns:
            Git sync result
        """
        handler = registry.get_handler("integration", IntegrationsHandler)
        result = await handler.git_sync(
            action, repo_url, branch, sync_direction, credentials, user_id
        )
        return format_tool_response(result)

    return mcp
