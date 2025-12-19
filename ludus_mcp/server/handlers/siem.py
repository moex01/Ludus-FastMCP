"""Handler for SIEM detection tracking (Wazuh, Splunk, Elastic, Security Onion)."""

from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class SIEMHandler:
    """Handler for SIEM security monitoring operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the SIEM handler."""
        self.client = client

    async def get_siem_server_info(
        self, siem_type: str = "wazuh", user_id: str | None = None
    ) -> dict[str, Any]:
        """Get SIEM server information from the range."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])
            
            # Find SIEM server VM based on type
            siem_keywords = {
                "wazuh": "wazuh",
                "splunk": "splunk",
                "elastic": "elastic",
                "security-onion": "security-onion",
            }
            
            siem_keyword = siem_keywords.get(siem_type.lower(), siem_type.lower())
            
            siem_vm = None
            for vm in vms:
                vm_name = vm.get("name", "").lower()
                if siem_keyword in vm_name and ("server" in vm_name or "manager" in vm_name):
                    siem_vm = vm
                    break
            
            if not siem_vm:
                return {
                    "status": "not_found",
                    "message": f"{siem_type} server not found in range",
                    "siem_type": siem_type,
                }
            
            # Get access URLs based on SIEM type
            siem_ip = siem_vm.get("ip", "unknown")
            access_info = self._get_siem_access_info(siem_type, siem_ip)
            
            return {
                "status": "found",
                "vm": siem_vm,
                "siem_type": siem_type,
                **access_info,
            }
        except Exception as e:
            logger.error(f"Error getting SIEM server info: {e}")
            return {
                "status": "error",
                "error": str(e),
                "siem_type": siem_type,
            }

    def _get_siem_access_info(self, siem_type: str, siem_ip: str) -> dict[str, Any]:
        """Get access information for different SIEM types."""
        if siem_type.lower() == "wazuh":
            return {
                "api_url": f"https://{siem_ip}:55000",
                "dashboard_url": f"https://{siem_ip}:5601",
                "default_credentials": "admin/admin",
            }
        elif siem_type.lower() == "splunk":
            return {
                "web_url": f"https://{siem_ip}:8000",
                "management_url": f"https://{siem_ip}:8089",
                "default_credentials": "admin/changeme",
            }
        elif siem_type.lower() == "elastic":
            return {
                "kibana_url": f"https://{siem_ip}:5601",
                "elasticsearch_url": f"https://{siem_ip}:9200",
                "logstash_url": f"https://{siem_ip}:5044",
                "default_credentials": "elastic/elastic",
            }
        elif siem_type.lower() == "security-onion":
            return {
                "web_url": f"https://{siem_ip}",
                "squert_url": f"https://{siem_ip}/squert",
                "capme_url": f"https://{siem_ip}/capme",
                "default_credentials": "admin/admin",
            }
        else:
            return {
                "message": f"Unknown SIEM type: {siem_type}",
            }

    async def get_siem_alerts(
        self,
        siem_type: str = "wazuh",
        limit: int = 100,
        severity: str | None = None,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Get SIEM alerts from the API."""
        try:
            siem_info = await self.get_siem_server_info(siem_type, user_id)
            if siem_info.get("status") != "found":
                return {
                    "status": "error",
                    "message": f"{siem_type} server not available",
                    "details": siem_info,
                }
            
            siem_ip = siem_info["vm"].get("ip")
            if not siem_ip:
                return {
                    "status": "error",
                    "message": f"{siem_type} server IP not available",
                }
            
            # Return access information and instructions
            return {
                "status": "info",
                "message": f"{siem_type} alerts can be accessed via web interface or API",
                "siem_server": siem_ip,
                "siem_type": siem_type,
                "access_urls": {k: v for k, v in siem_info.items() if "url" in k.lower()},
                "instructions": self._get_siem_instructions(siem_type),
            }
        except Exception as e:
            logger.error(f"Error getting SIEM alerts: {e}")
            return {
                "status": "error",
                "error": str(e),
                "siem_type": siem_type,
            }

    def _get_siem_instructions(self, siem_type: str) -> list[str]:
        """Get instructions for accessing different SIEM platforms."""
        if siem_type.lower() == "wazuh":
            return [
                "Access Wazuh Dashboard at the dashboard_url above",
                "Default credentials: admin/admin (change on first login)",
                "View alerts in the Security Events section",
                "Filter by severity, rule ID, or time range",
            ]
        elif siem_type.lower() == "splunk":
            return [
                "Access Splunk Web at the web_url above",
                "Default credentials: admin/changeme (change on first login)",
                "View alerts in Search & Reporting",
                "Use SPL queries to filter and analyze events",
            ]
        elif siem_type.lower() == "elastic":
            return [
                "Access Kibana at the kibana_url above",
                "Default credentials: elastic/elastic (change on first login)",
                "View alerts in Security app or Discover",
                "Use KQL queries to filter and analyze events",
            ]
        elif siem_type.lower() == "security-onion":
            return [
                "Access Security Onion at the web_url above",
                "Default credentials: admin/admin (change on first login)",
                "View alerts in Squert or Kibana",
                "Use CapME for packet analysis",
            ]
        else:
            return [f"Unknown SIEM type: {siem_type}"]

    async def get_siem_agents_status(
        self, siem_type: str = "wazuh", user_id: str | None = None
    ) -> dict[str, Any]:
        """Get status of all SIEM agents in the range."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])
            
            siem_keywords = {
                "wazuh": "wazuh",
                "splunk": "splunk",
                "elastic": "elastic",
                "security-onion": "security-onion",
            }
            
            siem_keyword = siem_keywords.get(siem_type.lower(), siem_type.lower())
            
            agents = []
            for vm in vms:
                # Check if VM has SIEM agent (all VMs except SIEM server should have agents)
                vm_name = vm.get("name", "").lower()
                if siem_keyword not in vm_name or ("server" not in vm_name and "manager" not in vm_name):
                    agents.append({
                        "vm_name": vm.get("name"),
                        "ip": vm.get("ip"),
                        "status": "configured",  # Agent should be installed via Ansible
                    })
            
            siem_info = await self.get_siem_server_info(siem_type, user_id)
            
            return {
                "status": "success",
                "siem_type": siem_type,
                "siem_server": siem_info.get("vm"),
                "agents": agents,
                "total_agents": len(agents),
                "message": f"{siem_type} agents are configured on all VMs via Ansible roles",
            }
        except Exception as e:
            logger.error(f"Error getting SIEM agents status: {e}")
            return {
                "status": "error",
                "error": str(e),
                "siem_type": siem_type,
            }

    async def get_detection_summary(
        self, siem_type: str = "wazuh", user_id: str | None = None
    ) -> dict[str, Any]:
        """Get summary of detections from SIEM."""
        try:
            siem_info = await self.get_siem_server_info(siem_type, user_id)
            agents_info = await self.get_siem_agents_status(siem_type, user_id)
            
            return {
                "status": "success",
                "siem_type": siem_type,
                "siem_server": siem_info.get("vm"),
                "total_agents": agents_info.get("total_agents", 0),
                "access_urls": {k: v for k, v in siem_info.items() if "url" in k.lower()},
                "message": f"Access {siem_type} interface to view real-time detections",
                "detection_capabilities": self._get_detection_capabilities(siem_type),
            }
        except Exception as e:
            logger.error(f"Error getting detection summary: {e}")
            return {
                "status": "error",
                "error": str(e),
                "siem_type": siem_type,
            }

    def _get_detection_capabilities(self, siem_type: str) -> list[str]:
        """Get detection capabilities for different SIEM platforms."""
        if siem_type.lower() == "wazuh":
            return [
                "File integrity monitoring",
                "Log analysis and correlation",
                "Intrusion detection",
                "Vulnerability detection",
                "Configuration assessment",
                "Incident response",
                "Regulatory compliance",
            ]
        elif siem_type.lower() == "splunk":
            return [
                "Real-time log analysis",
                "Security information and event management",
                "Machine learning for anomaly detection",
                "Threat intelligence integration",
                "Incident response automation",
                "Compliance reporting",
            ]
        elif siem_type.lower() == "elastic":
            return [
                "Elasticsearch for log storage and search",
                "Kibana for visualization",
                "Logstash for log processing",
                "Beats for log collection",
                "Security analytics",
                "Threat hunting",
            ]
        elif siem_type.lower() == "security-onion":
            return [
                "Network security monitoring (NSM)",
                "Intrusion detection (IDS/IPS)",
                "Log management",
                "Security analytics",
                "Threat hunting",
                "Packet analysis",
                "Full packet capture",
            ]
        else:
            return [f"Unknown SIEM type: {siem_type}"]

