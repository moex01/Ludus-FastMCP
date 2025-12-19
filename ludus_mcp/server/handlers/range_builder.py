"""Handler for building custom range configurations from natural language descriptions."""

from typing import Any
import re

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.scenarios.custom_scenarios import CustomScenarioBuilder
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class RangeBuilderHandler:
    """Handler for building custom range configurations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the range builder handler."""
        self.client = client

    async def build_range_from_description(
        self,
        description: str,
        siem_type: str = "wazuh",
        resource_profile: str = "recommended",
        include_siem: bool = True,
    ) -> dict[str, Any]:
        """Build a range configuration from a natural language description.

        This method intelligently parses a description and builds a complete
        range configuration with appropriate VMs, network rules, and SIEM.

        Args:
            description: Natural language description of the desired range
            siem_type: SIEM type to include (wazuh, splunk, elastic, security-onion, none)
            resource_profile: Resource allocation profile (minimal, recommended, maximum)
            include_siem: Whether to include SIEM monitoring

        Returns:
            Dictionary with the generated configuration and metadata
        """
        logger.info(f"Building range from description: {description[:100]}...")

        # Create builder
        builder = CustomScenarioBuilder(
            siem_type=siem_type if include_siem else "none",
            resource_profile=resource_profile,
        )

        # Set metadata from description
        builder.set_metadata(
            name="Custom Range",
            description=description,
            author="mcp-user",
            tags=self._extract_tags(description),
        )

        # Parse description and build configuration
        parsed = self._parse_description(description.lower())

        # Check if Exchange requires AD (Exchange always needs AD)
        if parsed.get("needs_exchange") or "exchange" in description.lower():
            parsed["needs_dc"] = True
            parsed["needs_ad"] = True
            parsed["needs_domain"] = True

        # Add VMs based on parsed description
        vlan_counter = 10
        ip_counter = 10

        # Domain Controller (add first if needed)
        if parsed.get("needs_dc") or parsed.get("needs_ad") or parsed.get("needs_domain"):
            domain_name = parsed.get("domain", "corp.local")
            builder.add_domain_controller(
                hostname="DC01",
                domain=domain_name,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        # Workstations
        num_workstations = parsed.get("workstations", 0)
        if num_workstations == 0 and (parsed.get("needs_dc") or parsed.get("needs_ad")):
            num_workstations = 2  # Default to 2 workstations for AD environments

        for i in range(1, num_workstations + 1):
            domain = parsed.get("domain") if parsed.get("needs_dc") else None
            builder.add_workstation(
                hostname=f"WS{i:02d}",
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        # Servers
        if parsed.get("needs_file_server") or "file server" in description.lower():
            domain = parsed.get("domain") if parsed.get("needs_dc") else None
            builder.add_server(
                hostname="FILES01",
                server_type="fileserver",
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        if parsed.get("needs_sql") or "sql server" in description.lower() or "database" in description.lower():
            domain = parsed.get("domain") if parsed.get("needs_dc") else None
            builder.add_server(
                hostname="SQL01",
                server_type="sql",
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        if parsed.get("needs_web") or "web server" in description.lower() or "webapp" in description.lower():
            builder.add_linux_server(
                hostname="WEB01",
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
                template="ubuntu-22-x64-server-template",
            )
            ip_counter += 1

        if parsed.get("needs_exchange") or "exchange" in description.lower():
            domain = parsed.get("domain", "corp.local")
            builder.add_server(
                hostname="EXCH01",
                server_type="exchange",
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        # Attacker/Kali
        if parsed.get("needs_attacker") or "attacker" in description.lower() or "kali" in description.lower() or "pentest" in description.lower():
            attacker_vlan = 99  # Separate VLAN for attacker
            builder.add_kali_attacker(
                hostname="KALI",
                vlan=attacker_vlan,
                ip_last_octet=10,
            )

            # Add network rule to allow attacker to corporate network
            builder.allow_communication(
                name="Allow attacker to corporate network",
                from_vlan=attacker_vlan,
                to_vlan=vlan_counter,
            )

        # SIEM
        if include_siem and siem_type != "none":
            builder.add_monitoring(
                vlan=vlan_counter,
                ip_last_octet=100,
                include_agents=True,
            )

        # Get configuration
        config = builder.to_dict()

        # Generate summary
        vms = config.get("ludus", [])
        network_rules = config.get("network", {}).get("rules", [])

        result = {
            "status": "success",
            "description": description,
            "configuration": config,
            "metadata": {
                "vm_count": len(vms),
                "network_rules_count": len(network_rules),
                "siem_type": siem_type if include_siem else "none",
                "resource_profile": resource_profile,
                "parsed_requirements": parsed,
            },
            "vms": [
                {
                    "hostname": vm.get("hostname", "Unknown"),
                    "template": vm.get("template", "Unknown"),
                    "vlan": vm.get("vlan", "?"),
                }
                for vm in vms
            ],
            "next_steps": [
                "1. Review the configuration to ensure it meets your needs",
                "2. Preview with: ludus.preview_scenario() or get_scenario_config()",
                "3. Deploy with: ludus.deploy_range(config=configuration)",
                "4. Or save as custom scenario for reuse",
            ],
        }

        logger.info(f"Built range config: {len(vms)} VMs, {len(network_rules)} network rules")
        return result

    def _parse_description(self, description: str) -> dict[str, Any]:
        """Parse natural language description to extract requirements.

        Args:
            description: Lowercase description text

        Returns:
            Dictionary with parsed requirements
        """
        parsed = {
            "needs_dc": False,
            "needs_ad": False,
            "needs_domain": False,
            "needs_file_server": False,
            "needs_sql": False,
            "needs_web": False,
            "needs_exchange": False,
            "needs_attacker": False,
            "workstations": 0,
            "domain": "corp.local",
        }

        # Check for AD/Domain requirements
        ad_keywords = ["active directory", "ad", "domain controller", "dc", "domain", "windows domain"]
        if any(keyword in description for keyword in ad_keywords):
            parsed["needs_dc"] = True
            parsed["needs_ad"] = True
            parsed["needs_domain"] = True

        # Extract domain name if specified
        domain_match = re.search(r"domain[:\s]+([a-z0-9\.-]+\.local)", description)
        if domain_match:
            parsed["domain"] = domain_match.group(1)

        # Check for file server
        if "file server" in description or "fileserver" in description or "file share" in description:
            parsed["needs_file_server"] = True

        # Check for SQL/Database
        if "sql" in description or "database" in description or "db server" in description:
            parsed["needs_sql"] = True

        # Check for web server
        if "web server" in description or "webapp" in description or "web app" in description or "apache" in description or "nginx" in description:
            parsed["needs_web"] = True

        # Check for Exchange
        if "exchange" in description or "email server" in description:
            parsed["needs_exchange"] = True

        # Check for attacker
        if "attacker" in description or "kali" in description or "pentest" in description or "red team" in description:
            parsed["needs_attacker"] = True

        # Extract number of workstations
        ws_match = re.search(r"(\d+)\s*(?:workstation|ws|client|desktop)", description)
        if ws_match:
            parsed["workstations"] = int(ws_match.group(1))
        elif "workstation" in description or "client" in description or "desktop" in description:
            parsed["workstations"] = 2  # Default

        return parsed

    def _extract_tags(self, description: str) -> list[str]:
        """Extract tags from description.

        Args:
            description: Description text

        Returns:
            List of tags
        """
        tags = []
        desc_lower = description.lower()

        if "ad" in desc_lower or "active directory" in desc_lower:
            tags.append("ad")
        if "red team" in desc_lower or "pentest" in desc_lower:
            tags.append("red-team")
        if "blue team" in desc_lower or "defense" in desc_lower:
            tags.append("blue-team")
        if "web" in desc_lower:
            tags.append("web")
        if "sql" in desc_lower or "database" in desc_lower:
            tags.append("database")
        if "exchange" in desc_lower:
            tags.append("exchange")

        return tags

