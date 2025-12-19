"""Handler for inventory operations (templates, roles, active ranges)."""

from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.scenarios.role_manager import RoleManager
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class InventoryHandler:
    """Handler for inventory and resource listing operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the inventory handler."""
        self.client = client
        self.role_manager = RoleManager(client)

    async def list_templates(self) -> dict[str, Any]:
        """List all available templates."""
        try:
            templates = await self.client.list_templates()
            return {
                "status": "success",
                "templates": templates if isinstance(templates, list) else [],
                "count": len(templates) if isinstance(templates, list) else 0,
            }
        except Exception as e:
            logger.error(f"Error listing templates: {e}")
            return {
                "status": "error",
                "error": str(e),
                "templates": [],
            }

    async def list_roles(self) -> dict[str, Any]:
        """List all installed Ansible roles."""
        try:
            ansible_resources = await self.client.list_ansible_resources()
            
            # Parse roles from response
            roles = []
            if isinstance(ansible_resources, dict):
                roles = ansible_resources.get("roles", [])
            elif isinstance(ansible_resources, list):
                roles = ansible_resources
            
            # Normalize role format
            normalized_roles = []
            for role in roles:
                if isinstance(role, str):
                    normalized_roles.append({"name": role, "installed": True})
                elif isinstance(role, dict):
                    normalized_roles.append({
                        "name": role.get("name") or role.get("role", "unknown"),
                        "installed": True,
                        **{k: v for k, v in role.items() if k not in ["name", "role"]},
                    })
            
            return {
                "status": "success",
                "roles": normalized_roles,
                "count": len(normalized_roles),
            }
        except Exception as e:
            logger.error(f"Error listing roles: {e}")
            return {
                "status": "error",
                "error": str(e),
                "roles": [],
            }

    async def list_active_ranges(self, user_id: str | None = None) -> dict[str, Any]:
        """List all actively deployed ranges."""
        try:
            # Get current user's range
            current_range = await self.client.get_range(user_id)
            
            # Get all ranges (admin only)
            all_ranges = []
            try:
                all_ranges = await self.client.list_ranges()
            except Exception:
                # If not admin, just return current range
                pass
            
            # Filter active ranges (not deleted, has VMs or is deploying)
            active_ranges = []
            
            # Add current range if it exists and is active
            if current_range and current_range.get("rangeState") not in ["DELETED", None]:
                active_ranges.append({
                    "user_id": current_range.get("userID"),
                    "range_number": current_range.get("rangeNumber"),
                    "state": current_range.get("rangeState"),
                    "number_of_vms": current_range.get("numberOfVMs", 0),
                    "last_deployment": current_range.get("lastDeployment"),
                    "testing_enabled": current_range.get("testingEnabled", False),
                })
            
            # Add other ranges if available
            if isinstance(all_ranges, list):
                for range_info in all_ranges:
                    if range_info.get("rangeState") not in ["DELETED", None]:
                        active_ranges.append({
                            "user_id": range_info.get("userID"),
                            "range_number": range_info.get("rangeNumber"),
                            "state": range_info.get("rangeState"),
                            "number_of_vms": range_info.get("numberOfVMs", 0),
                            "last_deployment": range_info.get("lastDeployment"),
                            "testing_enabled": range_info.get("testingEnabled", False),
                        })
            
            return {
                "status": "success",
                "active_ranges": active_ranges,
                "count": len(active_ranges),
            }
        except Exception as e:
            logger.error(f"Error listing active ranges: {e}")
            return {
                "status": "error",
                "error": str(e),
                "active_ranges": [],
            }

    async def get_inventory_summary(self, user_id: str | None = None) -> dict[str, Any]:
        """Get complete inventory summary (templates, roles, active ranges)."""
        try:
            templates_info = await self.list_templates()
            roles_info = await self.list_roles()
            ranges_info = await self.list_active_ranges(user_id)
            
            return {
                "status": "success",
                "templates": {
                    "count": templates_info.get("count", 0),
                    "list": templates_info.get("templates", []),
                },
                "roles": {
                    "count": roles_info.get("count", 0),
                    "list": roles_info.get("roles", []),
                },
                "active_ranges": {
                    "count": ranges_info.get("count", 0),
                    "list": ranges_info.get("active_ranges", []),
                },
            }
        except Exception as e:
            logger.error(f"Error getting inventory summary: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

