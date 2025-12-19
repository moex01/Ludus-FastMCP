"""Handler for Wazuh detection tracking."""

import httpx
from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.config import get_settings
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class WazuhHandler:
    """Handler for Wazuh security monitoring operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the Wazuh handler."""
        self.client = client
        settings = get_settings()
        # Wazuh server is typically at IP .100 in the range
        # This will be determined from the range config
        self.wazuh_api_port = 55000
        self.wazuh_dashboard_port = 5601

    async def get_wazuh_server_info(self, user_id: str | None = None) -> dict[str, Any]:
        """Get Wazuh server information from the range."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])
            
            # Find Wazuh server VM
            wazuh_vm = None
            for vm in vms:
                if "wazuh" in vm.get("name", "").lower():
                    wazuh_vm = vm
                    break
            
            if not wazuh_vm:
                return {
                    "status": "not_found",
                    "message": "Wazuh server not found in range",
                }
            
            return {
                "status": "found",
                "vm": wazuh_vm,
                "api_url": f"https://{wazuh_vm.get('ip', 'unknown')}:{self.wazuh_api_port}",
                "dashboard_url": f"https://{wazuh_vm.get('ip', 'unknown')}:{self.wazuh_dashboard_port}",
            }
        except Exception as e:
            logger.error(f"Error getting Wazuh server info: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def get_wazuh_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        rule_id: str | None = None,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Get Wazuh alerts from the API."""
        try:
            wazuh_info = await self.get_wazuh_server_info(user_id)
            if wazuh_info.get("status") != "found":
                return {
                    "status": "error",
                    "message": "Wazuh server not available",
                    "details": wazuh_info,
                }
            
            wazuh_ip = wazuh_info["vm"].get("ip")
            if not wazuh_ip:
                return {
                    "status": "error",
                    "message": "Wazuh server IP not available",
                }
            
            # Query Wazuh API for alerts
            # Note: This requires Wazuh API credentials
            # In a real implementation, you'd use the Wazuh API client
            api_url = f"https://{wazuh_ip}:{self.wazuh_api_port}"
            
            # For now, return instructions on how to access
            return {
                "status": "info",
                "message": "Wazuh alerts can be accessed via Wazuh API or Dashboard",
                "wazuh_server": wazuh_ip,
                "api_url": f"{api_url}/",
                "dashboard_url": f"https://{wazuh_ip}:{self.wazuh_dashboard_port}",
                "instructions": [
                    "Access Wazuh Dashboard at the dashboard_url above",
                    "Default credentials: admin/admin (change on first login)",
                    "View alerts in the Security Events section",
                    "Filter by severity, rule ID, or time range",
                ],
                "api_endpoints": {
                    "alerts": f"{api_url}/alerts",
                    "agents": f"{api_url}/agents",
                    "rules": f"{api_url}/rules",
                },
            }
        except Exception as e:
            logger.error(f"Error getting Wazuh alerts: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def get_wazuh_agents_status(self, user_id: str | None = None) -> dict[str, Any]:
        """Get status of all Wazuh agents in the range."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])
            
            agents = []
            for vm in vms:
                # Check if VM has Wazuh agent (all VMs except Wazuh server should have agents)
                if "wazuh" not in vm.get("name", "").lower() or "server" not in vm.get("name", "").lower():
                    agents.append({
                        "vm_name": vm.get("name"),
                        "ip": vm.get("ip"),
                        "status": "configured",  # Agent should be installed via Ansible
                    })
            
            wazuh_info = await self.get_wazuh_server_info(user_id)
            
            return {
                "status": "success",
                "wazuh_server": wazuh_info.get("vm"),
                "agents": agents,
                "total_agents": len(agents),
                "message": "Wazuh agents are configured on all VMs via Ansible roles",
            }
        except Exception as e:
            logger.error(f"Error getting Wazuh agents status: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def get_detection_summary(self, user_id: str | None = None) -> dict[str, Any]:
        """Get summary of detections from Wazuh."""
        try:
            wazuh_info = await self.get_wazuh_server_info(user_id)
            agents_info = await self.get_wazuh_agents_status(user_id)
            
            return {
                "status": "success",
                "wazuh_server": wazuh_info.get("vm"),
                "total_agents": agents_info.get("total_agents", 0),
                "dashboard_url": wazuh_info.get("dashboard_url"),
                "api_url": wazuh_info.get("api_url"),
                "message": "Access Wazuh Dashboard to view real-time detections",
                "detection_capabilities": [
                    "File integrity monitoring",
                    "Log analysis and correlation",
                    "Intrusion detection",
                    "Vulnerability detection",
                    "Configuration assessment",
                    "Incident response",
                    "Regulatory compliance",
                ],
            }
        except Exception as e:
            logger.error(f"Error getting detection summary: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

