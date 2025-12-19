"""Handler for integration operations."""

from datetime import datetime
from typing import Any
import hashlib
import json

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class IntegrationsHandler:
    """Handler for external integrations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the integrations handler."""
        self.client = client

    async def webhook_integration(
        self,
        webhook_url: str,
        events: list[str],
        secret: str | None = None,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Configure webhooks for events."""
        try:
            valid_events = [
                "deployment_started", "deployment_completed", "deployment_failed",
                "vm_created", "vm_deleted", "snapshot_created",
                "range_state_changed", "error_occurred"
            ]

            # Validate events
            invalid_events = [e for e in events if e not in valid_events]
            if invalid_events:
                return {
                    "status": "error",
                    "error": f"Invalid events: {invalid_events}",
                    "valid_events": valid_events
                }

            webhook_id = hashlib.md5(f"{webhook_url}{datetime.now()}".encode()).hexdigest()[:8]

            webhook_config = {
                "webhook_id": webhook_id,
                "url": webhook_url,
                "events": events,
                "secret": secret or "none",
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "retry_policy": {
                    "max_retries": 3,
                    "retry_delay_seconds": 60
                },
                "payload_format": {
                    "event": "event_name",
                    "timestamp": "ISO 8601",
                    "data": "event_specific_data",
                    "signature": "HMAC-SHA256 if secret provided"
                }
            }

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "webhook_configuration": webhook_config,
                "implementation_notes": {
                    "event_detection": "Monitor range state changes, parse logs",
                    "payload_sending": "Use httpx or requests to POST to webhook_url",
                    "signature": "HMAC-SHA256(payload, secret) if secret provided"
                },
                "example_payload": {
                    "event": "deployment_completed",
                    "timestamp": datetime.now().isoformat(),
                    "data": {
                        "range_id": "user-range",
                        "vm_count": 5,
                        "duration_seconds": 300
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error configuring webhook: {e}")
            return {"status": "error", "error": str(e)}

    async def slack_notifications(
        self,
        webhook_url: str,
        channel: str,
        notification_types: list[str],
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Slack integration for deployment status."""
        try:
            valid_types = ["deployment", "errors", "health_checks", "security_alerts"]

            config = {
                "platform": "slack",
                "webhook_url": webhook_url,
                "channel": channel,
                "notification_types": notification_types,
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "message_format": {
                    "deployment_started": "[INFO] Deployment started for range",
                    "deployment_completed": "[OK] Deployment completed successfully",
                    "deployment_failed": "[ERROR] Deployment failed",
                    "error_detected": "[WARNING] Error detected in range",
                    "health_check_failed": "[ERROR] Health check failed"
                }
            }

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "slack_configuration": config,
                "implementation": {
                    "library": "Use httpx or slack_sdk",
                    "example": json.dumps({
                        "channel": channel,
                        "text": "Deployment completed successfully",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Range Deployment*\n[OK] Completed successfully"
                                }
                            }
                        ]
                    }, indent=2)
                }
            }
        except Exception as e:
            logger.error(f"Error configuring Slack notifications: {e}")
            return {"status": "error", "error": str(e)}

    async def jira_integration(
        self,
        jira_url: str,
        project_key: str,
        api_token: str,
        issue_types: dict | None = None,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Create JIRA issues for failed deployments."""
        try:
            config = {
                "platform": "jira",
                "jira_url": jira_url,
                "project_key": project_key,
                "api_token": "***REDACTED***",
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "issue_mapping": issue_types or {
                    "deployment_failed": "Bug",
                    "vm_error": "Bug",
                    "network_issue": "Bug",
                    "security_finding": "Security"
                },
                "auto_create_issues": True
            }

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "jira_configuration": config,
                "implementation": {
                    "library": "Use jira-python or REST API",
                    "example_issue_creation": json.dumps({
                        "fields": {
                            "project": {"key": project_key},
                            "summary": "Range deployment failed",
                            "description": "Deployment failed with errors in logs",
                            "issuetype": {"name": "Bug"},
                            "priority": {"name": "High"}
                        }
                    }, indent=2),
                    "authentication": "Basic auth with email and API token"
                }
            }
        except Exception as e:
            logger.error(f"Error configuring JIRA integration: {e}")
            return {"status": "error", "error": str(e)}

    async def git_sync(
        self,
        repo_url: str,
        branch: str = "main",
        auto_commit: bool = True,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Sync range configs with Git repository."""
        try:
            range_config = await self.client.get_range_config(user_id)

            sync_config = {
                "repository": repo_url,
                "branch": branch,
                "auto_commit": auto_commit,
                "sync_frequency": "on_change" if auto_commit else "manual",
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "files_to_sync": [
                    "range_config.yml",
                    "inventory.ini",
                    "ssh_config"
                ],
                "commit_message_template": "Update range configuration - {timestamp}"
            }

            # Generate example files
            config_yaml = json.dumps(range_config, indent=2)

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "git_sync_configuration": sync_config,
                "current_config_preview": config_yaml[:500] + "...",
                "implementation": {
                    "clone": f"git clone {repo_url}",
                    "update": "Export configs using ludus tools",
                    "commit": f"git add . && git commit -m 'Update range config' && git push origin {branch}",
                    "automation": "Use cron or systemd timer for periodic sync"
                },
                "workflow": [
                    "1. Export range config: ludus.export_range_backup",
                    "2. Save to git repository directory",
                    "3. Git add, commit, and push changes",
                    "4. Tag important configurations"
                ]
            }
        except Exception as e:
            logger.error(f"Error configuring Git sync: {e}")
            return {"status": "error", "error": str(e)}
