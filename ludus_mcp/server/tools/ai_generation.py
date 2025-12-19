"""AI-powered configuration generation tools for Ludus MCP server.

This module provides advanced natural language processing tools for generating
Ludus range configurations from conversational prompts.
"""

from typing import Any
from fastmcp import FastMCP
from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.ai_config_generator import AIConfigGeneratorHandler
from ludus_mcp.server.tools.utils import LazyHandlerRegistry, format_tool_response
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


def create_ai_config_tools(client: LudusAPIClient) -> FastMCP:
    """Create AI-powered configuration generation tools.

    Args:
        client: Ludus API client

    Returns:
        FastMCP instance with AI config tools registered
    """
    mcp = FastMCP("AI Configuration Generation")
    registry = LazyHandlerRegistry(client)

    # ==================== AI CONFIG GENERATION ====================

    @mcp.tool()
    async def generate_config_from_description(
        description: str,
        include_suggestions: bool = True,
        include_clarifications: bool = True,
    ) -> dict:
        """Generate a complete Ludus range configuration from natural language description.

        This is an enhanced AI-powered version of build_range_from_description that provides:
        - Better natural language understanding beyond simple regex matching
        - Intelligent clarification requests for ambiguous or incomplete inputs
        - Multiple configuration suggestions and alternatives
        - Educational explanations of design decisions and best practices

        Args:
            description: Natural language description of the desired cyber range.
                Can be conversational and doesn't need to follow strict formatting.
            include_suggestions: Whether to include enhancement suggestions (default: True)
            include_clarifications: Whether to request clarifications for missing info (default: True)

        Returns:
            Dictionary containing:
                - status: "success" or "needs_clarification"
                - configuration: Complete Ludus YAML configuration dict
                - metadata: VM count, complexity, resource profile info
                - parsed_requirements: Structured understanding of the prompt
                - suggestions: Optional enhancements (if include_suggestions=True)
                - educational_notes: Explanations of design choices
                - clarifications: Questions to ask if critical info missing
                - next_steps: What to do with the generated config

        Examples:
            # Simple Active Directory lab
            result = await generate_config_from_description(
                "I need an Active Directory lab with a domain controller "
                "and 3 Windows 10 workstations for practicing lateral movement"
            )

            # Red team training environment
            result = await generate_config_from_description(
                "Build a red team training lab with:
                - AD domain corp.local
                - 2 domain controllers for redundancy
                - 5 workstations (Windows 10 and 11)
                - SQL server with database
                - File server with shares
                - Exchange server for email
                - Kali Linux attacker machine
                - Wazuh SIEM for blue team practice"
            )

            # Web application security lab
            result = await generate_config_from_description(
                "Create a web app pentest lab with Ubuntu web server, "
                "MySQL database, and Kali for attacking. Include Splunk "
                "for monitoring the attacks."
            )

            # Blue team SOC lab
            result = await generate_config_from_description(
                "I want to build a SOC training lab with multiple endpoints "
                "to monitor, a SIEM (preferably Wazuh), and an attacker VM "
                "to simulate threats"
            )

        Notes:
            - If the description is ambiguous or missing critical info,
              status will be "needs_clarification" with specific questions
            - You can then provide answers and call this function again with
              more details added to the description
            - The generated config is ready to deploy with deploy_range()
            - Consider reviewing suggestions for additional capabilities
        """
        handler = AIConfigGeneratorHandler(client)
        result = await handler.generate_range_config_from_prompt(
            prompt=description,
            include_suggestions=include_suggestions,
            include_clarifications=include_clarifications,
        )
        return format_tool_response(result)

    @mcp.tool()
    async def explain_range_design_decisions(
        prompt: str,
    ) -> dict:
        """Explain the design decisions and best practices for a range configuration request.

        This tool helps users understand WHY certain choices are made when building
        a cyber range, providing educational value beyond just generating configs.

        Args:
            prompt: The range description or scenario you want explained

        Returns:
            Dictionary with:
                - design_rationale: Why specific VMs/networks are suggested
                - best_practices: Industry best practices applied
                - learning_objectives: What skills can be practiced
                - alternative_approaches: Other ways to achieve similar goals
                - security_considerations: Security implications of design choices

        Examples:
            # Understand AD design
            result = await explain_range_design_decisions(
                "Why do I need a domain controller AND workstations "
                "for an AD lab?"
            )

            # Network segmentation rationale
            result = await explain_range_design_decisions(
                "Explain why the attacker VM should be on a separate VLAN"
            )

            # SIEM placement
            result = await explain_range_design_decisions(
                "Where should I place the SIEM server and why?"
            )
        """
        handler = AIConfigGeneratorHandler(client)

        # Generate config to understand the design
        config_result = await handler.generate_range_config_from_prompt(
            prompt=prompt,
            include_suggestions=True,
            include_clarifications=False,
        )

        # Extract educational content
        educational_notes = config_result.get("educational_notes", [])
        suggestions = config_result.get("suggestions", [])
        parsed = config_result.get("parsed_requirements", {})

        explanation = {
            "status": "success",
            "prompt": prompt,
            "design_rationale": educational_notes,
            "best_practices": [
                "🔒 Network Segmentation: Separate VLANs isolate different security zones",
                "👁️  Monitoring: SIEM placement for comprehensive visibility",
                "⚔️  Attacker Isolation: Dedicated VLAN simulates external threats",
                "🏢 AD Architecture: Domain structure mirrors real enterprise networks",
                "📊 Resource Allocation: Balanced VM sizing for performance and cost",
            ],
            "learning_objectives": {
                "red_team": parsed.get("scenario_type") == "red_team",
                "blue_team": parsed.get("scenario_type") == "blue_team",
                "skills_developed": []
            },
            "alternative_approaches": suggestions,
            "security_considerations": [
                "Ensure attacker VM cannot access management network",
                "SIEM should have read-only access to all VLANs",
                "Domain controllers should be properly segmented",
                "Consider network ACLs for realistic access control",
            ],
            "next_steps": [
                "Review the educational notes for specific design decisions",
                "Consider the suggestions for alternative approaches",
                "Generate the actual config with generate_config_from_description()",
            ],
        }

        # Add skill development based on scenario type
        if parsed.get("needs_domain_controller"):
            explanation["learning_objectives"]["skills_developed"].extend([
                "Active Directory exploitation and hardening",
                "Kerberos attacks (Kerberoasting, AS-REP roasting)",
                "Lateral movement in domain environments",
            ])

        if parsed.get("needs_attacker"):
            explanation["learning_objectives"]["skills_developed"].extend([
                "Network reconnaissance and scanning",
                "Vulnerability exploitation",
                "Post-exploitation techniques",
            ])

        if parsed.get("include_monitoring"):
            explanation["learning_objectives"]["skills_developed"].extend([
                "SIEM log analysis",
                "Threat detection and hunting",
                "Incident response procedures",
            ])

        return format_tool_response(explanation)

    @mcp.tool()
    async def suggest_range_enhancements(
        current_description: str,
        enhancement_focus: str = "comprehensive",
    ) -> dict:
        """Suggest enhancements to improve a range configuration.

        Given a basic range description, this tool suggests additional components,
        capabilities, and improvements to make the range more realistic, educational,
        or aligned with specific training goals.

        Args:
            current_description: The current range description or configuration intent
            enhancement_focus: What to focus on for enhancements
                Options: "comprehensive", "realism", "security", "learning", "performance"

        Returns:
            Dictionary with:
                - original_config: Parsed understanding of current description
                - suggested_additions: New VMs, services, or capabilities to add
                - configuration_improvements: Better network topology, resource allocation
                - learning_enhancements: Additional training scenarios enabled
                - implementation_notes: How to implement the suggestions

        Examples:
            # Enhance basic AD lab
            result = await suggest_range_enhancements(
                "Simple AD lab with DC and 2 workstations",
                enhancement_focus="comprehensive"
            )
            # Might suggest: file server, SQL server, SIEM, attacker VM, etc.

            # Make lab more realistic
            result = await suggest_range_enhancements(
                "Red team lab with AD and Kali",
                enhancement_focus="realism"
            )
            # Might suggest: multiple DCs, realistic AD misconfigs, segmentation

            # Focus on learning value
            result = await suggest_range_enhancements(
                "Web app testing lab",
                enhancement_focus="learning"
            )
            # Might suggest: vulnerable apps, varied web servers, WAF bypass scenarios
        """
        handler = AIConfigGeneratorHandler(client)

        # Generate config to understand current state
        current_result = await handler.generate_range_config_from_prompt(
            prompt=current_description,
            include_suggestions=True,
            include_clarifications=False,
        )

        parsed = current_result.get("parsed_requirements", {})
        suggestions = current_result.get("suggestions", [])
        current_config = current_result.get("configuration", {})

        # Generate additional suggestions based on focus
        focus_enhancements = {
            "comprehensive": [
                "Add SIEM for comprehensive monitoring",
                "Include multiple workstation types (Win10, Win11)",
                "Add vulnerable web application for practice",
                "Include network packet capture capabilities",
            ],
            "realism": [
                "Deploy multiple domain controllers for redundancy",
                "Add realistic AD misconfigurations",
                "Implement multi-tier network architecture",
                "Include endpoint security solutions to bypass",
            ],
            "security": [
                "Add EDR/AV solutions for blue team practice",
                "Implement network segmentation with firewalls",
                "Include security monitoring and alerting",
                "Add honeypots and deception technology",
            ],
            "learning": [
                "Include intentionally vulnerable services",
                "Add CTF-style challenges",
                "Provide multiple attack paths",
                "Include both Windows and Linux targets",
            ],
            "performance": [
                "Optimize resource allocation",
                "Use minimal templates where appropriate",
                "Implement snapshot strategy for quick resets",
                "Balance VM distribution across hosts",
            ],
        }

        enhancements = focus_enhancements.get(enhancement_focus, focus_enhancements["comprehensive"])

        result = {
            "status": "success",
            "original_description": current_description,
            "enhancement_focus": enhancement_focus,
            "current_config_summary": {
                "vm_count": current_result.get("metadata", {}).get("vm_count", 0),
                "has_domain": parsed.get("needs_domain_controller", False),
                "has_monitoring": parsed.get("include_monitoring", False),
                "has_attacker": parsed.get("needs_attacker", False),
                "complexity": current_result.get("metadata", {}).get("complexity", "unknown"),
            },
            "suggested_additions": suggestions,
            "focus_specific_enhancements": enhancements,
            "implementation_notes": [
                f"Current complexity level: {current_result.get('metadata', {}).get('complexity', 'unknown')}",
                "Adding suggested components will increase resource requirements",
                "Consider your hardware capacity before implementing all suggestions",
                "You can generate a new config incorporating these suggestions",
            ],
            "next_steps": [
                "Review the suggested additions",
                "Update your description to include desired enhancements",
                "Call generate_config_from_description() with updated description",
                "Or manually add components using add_vm/add_server tools",
            ],
        }

        return format_tool_response(result)

    return mcp
