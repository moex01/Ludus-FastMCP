"""Adversary/Defender profile transformation tools for Ludus MCP server.

This module provides tools to transform range configurations by:
- Adversary Profile: Injecting realistic vulnerabilities for red team training
- Defender Profile: Adding monitoring and detection capabilities for blue team training
"""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.profile_transformer import ProfileTransformerHandler
from ludus_mcp.server.tools.utils import format_tool_response
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


def create_profile_transformation_tools(client: LudusAPIClient) -> FastMCP:
    """Create adversary/defender profile transformation tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with profile transformation tools registered
    """
    mcp = FastMCP("Adversary/Defender Profiles")

    # ==================== ADVERSARY PROFILE ====================

    @mcp.tool()
    async def apply_adversary_profile(
        config: dict[str, Any],
        threat_level: str = "medium",
        target_vms: list[str] | None = None,
        include_documentation: bool = True,
    ) -> dict:
        """Apply adversary profile to inject realistic vulnerabilities for red team training.

        This tool transforms an existing Ludus configuration by injecting educational
        vulnerabilities that simulate real-world security weaknesses. Perfect for:
        - Red team training and practice
        - Security testing scenarios
        - Learning exploitation techniques
        - Purple team exercises

        Args:
            config: The Ludus range configuration to transform (dict with 'ludus' key)
            threat_level: Level of vulnerabilities to inject
                - "low": Basic weaknesses (weak passwords, open shares)
                - "medium": AD attacks (Kerberoasting, AS-REP roasting, weak GPO)
                - "high": Advanced attacks (unconstrained delegation, certificate vulns)
            target_vms: Optional list of specific VM hostnames to target (None = all VMs)
            include_documentation: Generate educational docs explaining vulnerabilities

        Returns:
            Dictionary containing:
                - status: "success"
                - profile_type: "adversary"
                - threat_level: The applied threat level
                - modified_config: Transformed Ludus configuration
                - vulnerability_injections: List of injected vulnerabilities
                - vulnerabilities_count: Total number of vulnerabilities
                - affected_vms: List of VMs that were modified
                - documentation: Educational documentation (if requested)
                - warnings: Important safety warnings
                - next_steps: What to do next

        Examples:
            # Apply medium-level vulnerabilities to all VMs
            result = await apply_adversary_profile(
                config=my_range_config,
                threat_level="medium"
            )

            # Apply high-level vulnerabilities only to domain controllers
            result = await apply_adversary_profile(
                config=my_range_config,
                threat_level="high",
                target_vms=["DC01", "DC02"]
            )

            # Apply low-level vulnerabilities without documentation
            result = await apply_adversary_profile(
                config=my_range_config,
                threat_level="low",
                include_documentation=False
            )

        Vulnerability Categories:
            Active Directory:
                - Weak domain passwords
                - Kerberoasting opportunities
                - AS-REP roasting
                - Unconstrained delegation
                - DCSyn rights misconfigurations
                - Certificate Services vulnerabilities

            Windows Security:
                - Weak local administrator passwords
                - Unquoted service paths
                - Weak ACLs and permissions
                - AlwaysInstallElevated
                - Cached credentials

            Network Security:
                - Open SMB shares
                - Exposed RDP services
                - LLMNR poisoning opportunities
                - Weak network segmentation

        Notes:
            ⚠️  These vulnerabilities are for EDUCATIONAL PURPOSES ONLY
            ⚠️  Deploy ONLY in isolated lab environments
            ⚠️  NEVER expose these systems to production or the internet

        The modified configuration uses Ansible roles to implement vulnerabilities:
            - ludus_ad_weak_passwords
            - ludus_ad_kerberoast
            - ludus_ad_asreproast
            - ludus_ad_unconstrained_delegation
            - ludus_weak_local_admin
            - ludus_unquoted_service_paths
            - ludus_open_shares
        """
        handler = ProfileTransformerHandler(client)
        result = await handler.apply_adversary_profile(
            config=config,
            threat_level=threat_level,
            target_vms=target_vms,
            include_documentation=include_documentation,
        )
        return format_tool_response(result)

    # ==================== DEFENDER PROFILE ====================

    @mcp.tool()
    async def apply_defender_profile(
        config: dict[str, Any],
        monitoring_level: str = "comprehensive",
        siem_type: str = "wazuh",
        detection_focus: list[str] | None = None,
    ) -> dict:
        """Apply defender profile to add monitoring and detection capabilities for blue team training.

        This tool enhances an existing Ludus configuration with comprehensive security
        monitoring, logging, and detection capabilities. Perfect for:
        - Blue team training and SOC practice
        - SIEM deployment and configuration
        - Threat hunting exercises
        - Purple team defensive exercises
        - Incident detection and response training

        Args:
            config: The Ludus range configuration to enhance (dict with 'ludus' key)
            monitoring_level: Level of monitoring to deploy
                - "basic": SIEM agent + event forwarding
                - "comprehensive": + Sysmon/Auditd + PowerShell logging
                - "advanced": + EDR, process monitoring, FIM, network monitoring
            siem_type: SIEM platform to deploy
                - "wazuh": Wazuh (open source SIEM/XDR)
                - "splunk": Splunk Enterprise
                - "elastic": Elastic Stack (ELK)
            detection_focus: Optional list of specific attack types to focus detection on
                (e.g., ["kerberos_attacks", "lateral_movement", "credential_access"])

        Returns:
            Dictionary containing:
                - status: "success"
                - profile_type: "defender"
                - monitoring_level: The applied monitoring level
                - siem_type: The SIEM platform used
                - modified_config: Enhanced Ludus configuration
                - monitoring_enhancements: List of added monitoring capabilities
                - enhancements_count: Total number of enhancements
                - siem_added: Whether SIEM server was added
                - detection_rules: List of detection rules configured
                - affected_vms: List of VMs that were enhanced
                - documentation: Implementation and usage documentation
                - next_steps: What to do after deployment

        Examples:
            # Add comprehensive Wazuh monitoring to all VMs
            result = await apply_defender_profile(
                config=my_range_config,
                monitoring_level="comprehensive",
                siem_type="wazuh"
            )

            # Add advanced monitoring with Splunk
            result = await apply_defender_profile(
                config=my_range_config,
                monitoring_level="advanced",
                siem_type="splunk"
            )

            # Focus detection on Kerberos attacks and lateral movement
            result = await apply_defender_profile(
                config=my_range_config,
                monitoring_level="comprehensive",
                siem_type="wazuh",
                detection_focus=["kerberos_attacks", "lateral_movement"]
            )

        Monitoring Capabilities:
            Windows Monitoring:
                - SIEM agent (Wazuh/Splunk/Elastic)
                - Event log forwarding
                - Sysmon (process, network, file monitoring)
                - PowerShell script block logging
                - EDR capabilities (advanced level)
                - Process monitoring (advanced level)
                - File integrity monitoring (advanced level)

            Linux Monitoring:
                - SIEM agent (Wazuh/Splunk/Elastic)
                - Syslog forwarding
                - Auditd (system call auditing)
                - OSQuery (endpoint visibility)
                - EDR capabilities (advanced level)
                - Process monitoring (advanced level)
                - File integrity monitoring (advanced level)

            Network Monitoring:
                - NetFlow collection
                - Packet capture
                - Zeek network security monitor (advanced level)
                - Suricata IDS/IPS (advanced level)

        Detection Rules:
            - Kerberoasting detection (Event ID 4769)
            - Lateral movement detection (PsExec, WMI)
            - Credential dumping (LSASS access, Mimikatz)
            - PowerShell obfuscation
            - Suspicious process execution
            - And more based on detection_focus

        Notes:
            - SIEM server will be automatically added if not present
            - All VMs will have monitoring agents installed
            - Detection rules are pre-configured but customizable
            - Dashboard and alerting must be configured post-deployment
        """
        handler = ProfileTransformerHandler(client)
        result = await handler.apply_defender_profile(
            config=config,
            monitoring_level=monitoring_level,
            siem_type=siem_type,
            detection_focus=detection_focus,
        )
        return format_tool_response(result)

    # ==================== PROFILE UTILITIES ====================

    @mcp.tool()
    async def list_available_profiles() -> dict:
        """List all available adversary and defender profiles with descriptions.

        Returns detailed information about all available security profiles,
        their capabilities, and use cases.

        Returns:
            Dictionary containing:
                - adversary_profiles: Available threat levels and capabilities
                - defender_profiles: Available monitoring levels and capabilities
                - siem_types: Supported SIEM platforms
                - use_cases: Common use cases for each profile combination

        Example:
            profiles = await list_available_profiles()
            print(profiles['adversary_profiles']['medium']['capabilities'])
        """
        profiles = {
            "status": "success",
            "adversary_profiles": {
                "low": {
                    "name": "Low Threat Level",
                    "description": "Basic security weaknesses suitable for beginners",
                    "capabilities": [
                        "Weak passwords",
                        "Open SMB shares",
                        "Outdated software",
                        "Weak local admin passwords",
                        "Open RDP exposure",
                    ],
                    "use_cases": [
                        "Beginner red team training",
                        "Basic vulnerability scanning",
                        "Introduction to exploitation",
                    ],
                },
                "medium": {
                    "name": "Medium Threat Level",
                    "description": "Realistic AD and Windows misconfigurations",
                    "capabilities": [
                        "All low-level vulnerabilities",
                        "Kerberoasting opportunities",
                        "AS-REP roasting",
                        "Weak GPO configurations",
                        "Unquoted service paths",
                        "Weak ACLs",
                        "LLMNR poisoning",
                    ],
                    "use_cases": [
                        "Intermediate red team training",
                        "Active Directory exploitation practice",
                        "Lateral movement exercises",
                        "Purple team assessments",
                    ],
                },
                "high": {
                    "name": "High Threat Level",
                    "description": "Advanced attack paths and complex vulnerabilities",
                    "capabilities": [
                        "All medium-level vulnerabilities",
                        "Unconstrained delegation",
                        "DCSyn rights misconfigurations",
                        "Forest trust weaknesses",
                        "Certificate Services vulnerabilities",
                        "Zerologon-vulnerable configurations",
                        "AlwaysInstallElevated",
                        "Cached credentials",
                        "DNS zone transfers",
                        "NTLM relay opportunities",
                    ],
                    "use_cases": [
                        "Advanced red team training",
                        "Complex AD attack path practice",
                        "Enterprise penetration testing simulation",
                        "Advanced purple team exercises",
                    ],
                },
            },
            "defender_profiles": {
                "basic": {
                    "name": "Basic Monitoring",
                    "description": "Fundamental logging and SIEM integration",
                    "capabilities": {
                        "windows": ["SIEM agent", "Event log forwarding"],
                        "linux": ["SIEM agent", "Syslog forwarding"],
                        "network": [],
                    },
                    "use_cases": [
                        "Basic SOC operations",
                        "Log aggregation",
                        "Simple alerting",
                    ],
                },
                "comprehensive": {
                    "name": "Comprehensive Monitoring",
                    "description": "Advanced logging with detailed visibility",
                    "capabilities": {
                        "windows": [
                            "SIEM agent",
                            "Event log forwarding",
                            "Sysmon",
                            "PowerShell logging",
                        ],
                        "linux": [
                            "SIEM agent",
                            "Syslog forwarding",
                            "Auditd",
                            "OSQuery",
                        ],
                        "network": ["NetFlow", "Packet capture"],
                    },
                    "use_cases": [
                        "SOC analyst training",
                        "Threat hunting",
                        "Incident detection",
                        "Purple team defense",
                    ],
                },
                "advanced": {
                    "name": "Advanced Monitoring",
                    "description": "Enterprise-grade SOC stack with comprehensive visibility",
                    "capabilities": {
                        "windows": [
                            "All comprehensive capabilities",
                            "EDR",
                            "Process monitoring",
                            "File integrity monitoring",
                        ],
                        "linux": [
                            "All comprehensive capabilities",
                            "EDR",
                            "Process monitoring",
                            "File integrity monitoring",
                        ],
                        "network": [
                            "All comprehensive capabilities",
                            "Zeek",
                            "Suricata IDS/IPS",
                        ],
                    },
                    "use_cases": [
                        "Advanced SOC operations",
                        "Enterprise threat hunting",
                        "Complex incident response",
                        "Full purple team exercises",
                    ],
                },
            },
            "siem_types": {
                "wazuh": {
                    "name": "Wazuh",
                    "description": "Open-source SIEM and XDR platform",
                    "cost": "Free / Open Source",
                    "features": [
                        "Host-based intrusion detection",
                        "Log analysis",
                        "File integrity monitoring",
                        "Vulnerability detection",
                        "Compliance monitoring",
                    ],
                },
                "splunk": {
                    "name": "Splunk Enterprise",
                    "description": "Enterprise SIEM and data analytics platform",
                    "cost": "Commercial / Free trial",
                    "features": [
                        "Advanced log analysis",
                        "Machine learning",
                        "Custom dashboards",
                        "Extensive app ecosystem",
                        "Advanced correlation",
                    ],
                },
                "elastic": {
                    "name": "Elastic Stack (ELK)",
                    "description": "Elasticsearch, Logstash, Kibana stack",
                    "cost": "Open Source / Commercial features",
                    "features": [
                        "Full-text search",
                        "Real-time analysis",
                        "Custom visualizations",
                        "Scalable architecture",
                        "API-driven",
                    ],
                },
            },
            "purple_team_workflow": {
                "description": "Combine adversary and defender profiles for complete purple team training",
                "steps": [
                    "1. Generate base configuration with generate_config_from_description()",
                    "2. Apply adversary profile to inject vulnerabilities",
                    "3. Apply defender profile to add monitoring",
                    "4. Deploy the purple team range",
                    "5. Practice: Red team attacks → Blue team detects → Improve defenses",
                ],
            },
        }

        return format_tool_response(profiles)

    @mcp.tool()
    async def preview_profile_changes(
        config: dict[str, Any],
        profile_type: str,
        profile_level: str,
    ) -> dict:
        """Preview changes that would be made by applying a profile without modifying the config.

        This is a dry-run tool that shows what would happen if you applied a profile,
        without actually modifying the configuration. Useful for understanding the
        impact before committing to changes.

        Args:
            config: The Ludus range configuration to analyze
            profile_type: Type of profile to preview ("adversary" or "defender")
            profile_level: Level to preview (threat level for adversary, monitoring level for defender)

        Returns:
            Dictionary containing:
                - status: "success"
                - profile_type: The profile type previewed
                - profile_level: The level previewed
                - affected_vms: List of VMs that would be modified
                - changes_summary: Summary of changes
                - ansible_roles_added: List of Ansible roles that would be added
                - estimated_impact: Estimated resource and complexity impact
                - recommendations: Recommendations based on the preview

        Examples:
            # Preview medium adversary profile
            preview = await preview_profile_changes(
                config=my_config,
                profile_type="adversary",
                profile_level="medium"
            )

            # Preview advanced defender profile
            preview = await preview_profile_changes(
                config=my_config,
                profile_type="defender",
                profile_level="advanced"
            )
        """
        vms = config.get("ludus", [])
        vm_names = [vm.get("hostname", "Unknown") for vm in vms]

        if profile_type == "adversary":
            changes = {
                "low": ["Weak passwords on all domain-joined systems", "Open SMB shares"],
                "medium": [
                    "Weak passwords",
                    "Kerberoasting on service accounts",
                    "AS-REP roasting opportunities",
                    "Unquoted service paths on workstations",
                ],
                "high": [
                    "All medium-level vulnerabilities",
                    "Unconstrained delegation on specific computers",
                    "DCSyn rights for specific users",
                    "Advanced AD misconfigurations",
                ],
            }
            roles = {
                "low": ["ludus_ad_weak_passwords", "ludus_open_shares"],
                "medium": [
                    "ludus_ad_weak_passwords",
                    "ludus_ad_kerberoast",
                    "ludus_ad_asreproast",
                    "ludus_unquoted_service_paths",
                ],
                "high": [
                    "ludus_ad_weak_passwords",
                    "ludus_ad_kerberoast",
                    "ludus_ad_asreproast",
                    "ludus_ad_unconstrained_delegation",
                    "ludus_unquoted_service_paths",
                    "ludus_weak_local_admin",
                ],
            }
        else:  # defender
            changes = {
                "basic": ["SIEM agent on all VMs", "Event log forwarding"],
                "comprehensive": [
                    "SIEM agents",
                    "Sysmon on Windows VMs",
                    "Auditd on Linux VMs",
                    "PowerShell logging",
                ],
                "advanced": [
                    "All comprehensive monitoring",
                    "EDR on all endpoints",
                    "File integrity monitoring",
                    "Network flow monitoring",
                    "Zeek and Suricata",
                ],
            }
            roles = {
                "basic": ["ludus_wazuh_agent"],
                "comprehensive": [
                    "ludus_wazuh_agent",
                    "ludus_sysmon",
                    "ludus_auditd",
                    "ludus_powershell_logging",
                ],
                "advanced": [
                    "ludus_wazuh_agent",
                    "ludus_sysmon",
                    "ludus_auditd",
                    "ludus_powershell_logging",
                    "ludus_edr",
                    "ludus_fim",
                ],
            }

        result = {
            "status": "success",
            "profile_type": profile_type,
            "profile_level": profile_level,
            "affected_vms": vm_names,
            "vm_count": len(vms),
            "changes_summary": changes.get(profile_level, []),
            "ansible_roles_added": roles.get(profile_level, []),
            "estimated_impact": {
                "resource_increase": "low" if profile_level in ["low", "basic"] else "medium" if profile_level in ["medium", "comprehensive"] else "high",
                "deployment_time_increase": "5-10 minutes" if profile_level in ["low", "basic"] else "10-20 minutes" if profile_level in ["medium", "comprehensive"] else "20-30 minutes",
                "complexity": profile_level,
            },
            "recommendations": [
                f"This will modify all {len(vms)} VMs in your configuration",
                f"Estimated additional deployment time: {5 if profile_level in ['low', 'basic'] else 15 if profile_level in ['medium', 'comprehensive'] else 25} minutes",
                "Review the changes_summary and ansible_roles_added before applying",
                f"Use apply_{profile_type}_profile() to apply these changes",
            ],
        }

        return format_tool_response(result)

    return mcp
