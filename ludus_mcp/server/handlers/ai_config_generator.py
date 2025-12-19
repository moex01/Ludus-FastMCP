"""Enhanced AI-powered configuration generator handler.

This handler provides advanced natural language processing for range configurations,
going beyond simple regex matching to understand complex requirements and generate
comprehensive Ludus configurations.
"""

from typing import Any
import re
import yaml

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.scenarios.custom_scenarios import CustomScenarioBuilder
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class AIConfigGeneratorHandler:
    """Handler for AI-powered range configuration generation."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the AI config generator handler."""
        self.client = client

    async def generate_range_config_from_prompt(
        self,
        prompt: str,
        include_suggestions: bool = True,
        include_clarifications: bool = True,
    ) -> dict[str, Any]:
        """Generate a complete range configuration from a natural language prompt.

        This is an enhanced version of build_range_from_description that provides:
        - Better natural language understanding
        - Clarification requests for ambiguous inputs
        - Multiple configuration suggestions
        - Educational explanations of design decisions

        Args:
            prompt: Natural language description of desired range
            include_suggestions: Whether to include alternative suggestions
            include_clarifications: Whether to request clarifications for missing info

        Returns:
            Dictionary with configuration, suggestions, and clarifications
        """
        logger.info(f"Generating range config from prompt: {prompt[:100]}...")

        # Parse the prompt
        parsed = self._advanced_parse_prompt(prompt)

        # Check for missing critical information
        clarifications_needed = []
        if include_clarifications:
            clarifications_needed = self._identify_clarifications(parsed, prompt)

        # If critical info is missing, return clarification request
        if clarifications_needed and include_clarifications:
            return {
                "status": "needs_clarification",
                "prompt": prompt,
                "clarifications": clarifications_needed,
                "partial_understanding": parsed,
                "message": "I need some additional information to build the perfect range configuration.",
            }

        # Build the configuration
        config_result = await self._build_configuration(parsed, prompt)

        # Generate suggestions if requested
        suggestions = []
        if include_suggestions:
            suggestions = self._generate_suggestions(parsed, config_result["configuration"])

        return {
            "status": "success",
            "prompt": prompt,
            "configuration": config_result["configuration"],
            "metadata": config_result["metadata"],
            "parsed_requirements": parsed,
            "suggestions": suggestions,
            "educational_notes": self._generate_educational_notes(parsed),
            "next_steps": [
                "1. Review the generated configuration",
                "2. Consider the suggested enhancements",
                "3. Deploy with: deploy_range(config=configuration)",
                "4. Or save as custom scenario for reuse",
            ],
        }

    async def _build_configuration(
        self, parsed: dict[str, Any], prompt: str
    ) -> dict[str, Any]:
        """Build the actual configuration from parsed requirements."""
        # Determine resource profile based on complexity
        complexity = self._assess_complexity(parsed)
        resource_profile = {
            "low": "minimal",
            "medium": "recommended",
            "high": "maximum",
        }.get(complexity, "recommended")

        # Determine SIEM type
        siem_type = parsed.get("siem_type", "wazuh")
        include_siem = parsed.get("include_monitoring", True)

        # Create builder
        builder = CustomScenarioBuilder(
            siem_type=siem_type if include_siem else "none",
            resource_profile=resource_profile,
        )

        # Set metadata
        builder.set_metadata(
            name=parsed.get("scenario_name", "AI Generated Range"),
            description=prompt,
            author="ai-generated",
            tags=parsed.get("tags", []),
        )

        # Build VMs
        await self._build_vms(builder, parsed)

        # Get configuration
        config = builder.to_dict()

        # Count VMs and rules
        vms = config.get("ludus", [])
        network_rules = config.get("network", {}).get("rules", [])

        return {
            "configuration": config,
            "metadata": {
                "vm_count": len(vms),
                "network_rules_count": len(network_rules),
                "siem_type": siem_type if include_siem else "none",
                "resource_profile": resource_profile,
                "complexity": complexity,
            },
        }

    async def _build_vms(
        self, builder: CustomScenarioBuilder, parsed: dict[str, Any]
    ) -> None:
        """Build VMs based on parsed requirements."""
        vlan_counter = 10
        ip_counter = 10

        # Domain Controller (if needed)
        if parsed.get("needs_domain_controller"):
            domain = parsed.get("domain_name", "corp.local")
            builder.add_domain_controller(
                hostname=parsed.get("dc_hostname", "DC01"),
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        # Workstations
        for i in range(1, parsed.get("workstation_count", 0) + 1):
            domain = parsed.get("domain_name") if parsed.get("needs_domain_controller") else None
            builder.add_workstation(
                hostname=f"WS{i:02d}",
                domain=domain,
                vlan=vlan_counter,
                ip_last_octet=ip_counter,
            )
            ip_counter += 1

        # Servers
        for server_type in parsed.get("server_types", []):
            if server_type == "file":
                domain = parsed.get("domain_name") if parsed.get("needs_domain_controller") else None
                builder.add_server(
                    hostname="FILES01",
                    server_type="fileserver",
                    domain=domain,
                    vlan=vlan_counter,
                    ip_last_octet=ip_counter,
                )
                ip_counter += 1
            elif server_type == "sql":
                domain = parsed.get("domain_name") if parsed.get("needs_domain_controller") else None
                builder.add_server(
                    hostname="SQL01",
                    server_type="sql",
                    domain=domain,
                    vlan=vlan_counter,
                    ip_last_octet=ip_counter,
                )
                ip_counter += 1
            elif server_type == "web":
                builder.add_linux_server(
                    hostname="WEB01",
                    vlan=vlan_counter,
                    ip_last_octet=ip_counter,
                    template="ubuntu-22-x64-server-template",
                )
                ip_counter += 1
            elif server_type == "exchange":
                domain = parsed.get("domain_name", "corp.local")
                builder.add_server(
                    hostname="EXCH01",
                    server_type="exchange",
                    domain=domain,
                    vlan=vlan_counter,
                    ip_last_octet=ip_counter,
                )
                ip_counter += 1

        # Attacker machine
        if parsed.get("needs_attacker"):
            attacker_vlan = 99
            builder.add_kali_attacker(
                hostname="KALI",
                vlan=attacker_vlan,
                ip_last_octet=10,
            )
            # Allow attacker to corporate network
            builder.allow_communication(
                name="Allow attacker to corporate network",
                from_vlan=attacker_vlan,
                to_vlan=vlan_counter,
            )

        # SIEM monitoring
        if parsed.get("include_monitoring"):
            builder.add_monitoring(
                vlan=vlan_counter,
                ip_last_octet=100,
                include_agents=True,
            )

    def _advanced_parse_prompt(self, prompt: str) -> dict[str, Any]:
        """Advanced parsing of natural language prompts.

        This goes beyond simple regex matching to understand context and intent.
        """
        prompt_lower = prompt.lower()

        parsed = {
            "needs_domain_controller": False,
            "domain_name": "corp.local",
            "workstation_count": 0,
            "server_types": [],
            "needs_attacker": False,
            "include_monitoring": True,
            "siem_type": "wazuh",
            "tags": [],
            "scenario_type": "custom",
        }

        # Detect scenario type
        if any(word in prompt_lower for word in ["red team", "pentest", "penetration", "attack"]):
            parsed["scenario_type"] = "red_team"
            parsed["needs_attacker"] = True
            parsed["tags"].append("red-team")

        if any(word in prompt_lower for word in ["blue team", "defense", "soc", "detection"]):
            parsed["scenario_type"] = "blue_team"
            parsed["include_monitoring"] = True
            parsed["tags"].append("blue-team")

        # Domain Controller detection
        dc_keywords = ["active directory", " ad ", "domain controller", " dc ", "windows domain", "ad environment"]
        if any(keyword in prompt_lower for keyword in dc_keywords):
            parsed["needs_domain_controller"] = True
            parsed["tags"].append("ad")

        # Domain name extraction
        domain_patterns = [
            r"domain[:\s]+([a-z0-9\.-]+\.local)",
            r"domain name[:\s]+([a-z0-9\.-]+\.local)",
            r"ad domain[:\s]+([a-z0-9\.-]+\.local)",
        ]
        for pattern in domain_patterns:
            match = re.search(pattern, prompt_lower)
            if match:
                parsed["domain_name"] = match.group(1)
                break

        # Workstation count
        ws_patterns = [
            r"(\d+)\s+workstation",
            r"(\d+)\s+client",
            r"(\d+)\s+desktop",
            r"(\d+)\s+windows\s+(?:10|11)",
        ]
        for pattern in ws_patterns:
            match = re.search(pattern, prompt_lower)
            if match:
                parsed["workstation_count"] = int(match.group(1))
                break

        # If AD mentioned but no workstation count, default to 2
        if parsed["needs_domain_controller"] and parsed["workstation_count"] == 0:
            if any(word in prompt_lower for word in ["workstation", "client", "desktop"]):
                parsed["workstation_count"] = 2

        # Server types
        if any(word in prompt_lower for word in ["file server", "fileserver", "file share"]):
            parsed["server_types"].append("file")
            parsed["tags"].append("fileserver")

        if any(word in prompt_lower for word in ["sql", "database", "db server", "mssql"]):
            parsed["server_types"].append("sql")
            parsed["tags"].append("database")

        if any(word in prompt_lower for word in ["web server", "webapp", "web app", "apache", "nginx", "iis"]):
            parsed["server_types"].append("web")
            parsed["tags"].append("web")

        if "exchange" in prompt_lower:
            parsed["server_types"].append("exchange")
            parsed["needs_domain_controller"] = True  # Exchange requires AD
            parsed["tags"].append("exchange")

        # Attacker machine
        if any(word in prompt_lower for word in ["attacker", "kali", "parrot", "pentest", "red team"]):
            parsed["needs_attacker"] = True

        # SIEM detection
        if "wazuh" in prompt_lower:
            parsed["siem_type"] = "wazuh"
        elif "splunk" in prompt_lower:
            parsed["siem_type"] = "splunk"
        elif "elastic" in prompt_lower or "elk" in prompt_lower:
            parsed["siem_type"] = "elastic"
        elif any(word in prompt_lower for word in ["no monitoring", "no siem", "without monitoring"]):
            parsed["include_monitoring"] = False

        return parsed

    def _identify_clarifications(
        self, parsed: dict[str, Any], prompt: str
    ) -> list[dict[str, Any]]:
        """Identify what clarifications are needed for better configuration."""
        clarifications = []

        # Check if OS versions mentioned
        if parsed.get("needs_domain_controller") and "windows server" not in prompt.lower():
            clarifications.append({
                "question": "What Windows Server version for the Domain Controller?",
                "options": ["2019", "2022"],
                "default": "2022",
                "field": "dc_os_version",
            })

        # Check if workstation count is ambiguous
        if parsed.get("needs_domain_controller") and parsed.get("workstation_count") == 0:
            if "workstation" in prompt.lower() or "client" in prompt.lower():
                clarifications.append({
                    "question": "How many workstations do you need?",
                    "type": "number",
                    "default": 2,
                    "field": "workstation_count",
                })

        # Check if monitoring type unspecified
        if parsed.get("include_monitoring") and parsed.get("siem_type") == "wazuh":
            if "monitoring" in prompt.lower() or "siem" in prompt.lower():
                if not any(word in prompt.lower() for word in ["wazuh", "splunk", "elastic"]):
                    clarifications.append({
                        "question": "Which SIEM/monitoring solution would you prefer?",
                        "options": ["wazuh", "splunk", "elastic", "none"],
                        "default": "wazuh",
                        "field": "siem_type",
                    })

        return clarifications

    def _assess_complexity(self, parsed: dict[str, Any]) -> str:
        """Assess the complexity of the requested range."""
        vm_count = (
            (1 if parsed.get("needs_domain_controller") else 0)
            + parsed.get("workstation_count", 0)
            + len(parsed.get("server_types", []))
            + (1 if parsed.get("needs_attacker") else 0)
            + (1 if parsed.get("include_monitoring") else 0)
        )

        if vm_count <= 3:
            return "low"
        elif vm_count <= 7:
            return "medium"
        else:
            return "high"

    def _generate_suggestions(
        self, parsed: dict[str, Any], config: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate suggestions for enhancing the configuration."""
        suggestions = []

        # Suggest SIEM if not included
        if not parsed.get("include_monitoring"):
            suggestions.append({
                "type": "enhancement",
                "title": "Add SIEM Monitoring",
                "description": "Consider adding Wazuh or Splunk for security monitoring and log aggregation",
                "benefit": "Enables threat detection, log correlation, and compliance monitoring",
            })

        # Suggest attacker VM for defensive scenarios
        if parsed.get("scenario_type") == "blue_team" and not parsed.get("needs_attacker"):
            suggestions.append({
                "type": "enhancement",
                "title": "Add Attacker Simulation",
                "description": "Include a Kali Linux VM to simulate realistic attack scenarios",
                "benefit": "Test detection capabilities and SOC playbooks with controlled attacks",
            })

        # Suggest additional workstations if count is low
        if parsed.get("needs_domain_controller") and parsed.get("workstation_count") < 3:
            suggestions.append({
                "type": "scaling",
                "title": "Add More Workstations",
                "description": f"Current: {parsed.get('workstation_count')} workstations. Consider 3-5 for more realistic AD environment",
                "benefit": "Better simulates real enterprise networks with multiple endpoints",
            })

        # Suggest web server for comprehensive testing
        if parsed.get("scenario_type") == "red_team" and "web" not in parsed.get("server_types", []):
            suggestions.append({
                "type": "enhancement",
                "title": "Add Web Application Server",
                "description": "Include a vulnerable web application for web exploitation practice",
                "benefit": "Practice OWASP Top 10 vulnerabilities and web application attacks",
            })

        return suggestions

    def _generate_educational_notes(self, parsed: dict[str, Any]) -> list[str]:
        """Generate educational notes explaining design decisions."""
        notes = []

        if parsed.get("needs_domain_controller"):
            notes.append(
                "🏢 Active Directory: The DC is placed on VLAN 10 to isolate corporate resources. "
                "Workstations will automatically join the domain during deployment."
            )

        if parsed.get("needs_attacker"):
            notes.append(
                "⚔️  Attacker Segmentation: The attacker VM is on VLAN 99 (separate from corporate) "
                "with firewall rules allowing access. This simulates external threat actor access."
            )

        if parsed.get("include_monitoring"):
            notes.append(
                f"👁️  SIEM Monitoring: {parsed.get('siem_type', 'Wazuh').title()} will be deployed with agents "
                "on all VMs for centralized logging and threat detection."
            )

        if "exchange" in parsed.get("server_types", []):
            notes.append(
                "📧 Exchange Server: Requires Active Directory. The server will be configured "
                "with mail services and can be used for phishing simulations or email security testing."
            )

        return notes
