"""Scenario deployment handlers."""

from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.scenarios.scenario_manager import ScenarioManager
from ludus_mcp.schemas.validation import PreviewResult
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.visualization import (
    format_scenario_preview,
    generate_ascii_topology,
    estimate_deployment_time,
    estimate_resources,
)

logger = get_logger(__name__)


class ScenarioHandler:
    """Handler for scenario operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the scenario handler."""
        self.client = client
        self.manager = ScenarioManager(client)

    async def list_scenarios(self) -> dict[str, str]:
        """List all available scenarios."""
        logger.debug("Listing available scenarios")
        return await self.manager.list_scenarios()

    async def deploy_scenario(
        self,
        scenario_key: str,
        user_id: str | None = None,
        ensure_roles: bool = True,
        siem_type: str = "wazuh",
        resource_profile: str = "recommended",
        customize: bool = False,
        randomize: bool = False,
        custom_users: list[dict[str, Any]] | None = None,
        vulnerability_config: dict[str, Any] | None = None,
        network_customizations: dict[str, Any] | None = None,
        vm_customizations: dict[str, Any] | None = None,
    ) -> dict:
        """Deploy a scenario.
        
        Args:
            scenario_key: Scenario identifier
            user_id: Optional user ID (admin only)
            ensure_roles: Ensure required Ansible roles are installed
            siem_type: SIEM type (wazuh, splunk, elastic, security-onion, none)
            resource_profile: Resource allocation profile (minimal, recommended, maximum)
            customize: Enable customization mode (use provided customizations)
            randomize: Enable randomization mode (generate random customizations)
            custom_users: List of custom user dictionaries (username, password, groups, etc.)
            vulnerability_config: Custom vulnerability configuration dict
            network_customizations: Network customization dict (VLAN changes, firewall rules)
            vm_customizations: VM customization dict (count overrides, resource changes)
        """
        logger.info(f"Deploying scenario: {scenario_key} with SIEM: {siem_type}, Profile: {resource_profile}, Customize: {customize}, Randomize: {randomize}")
        return await self.manager.deploy_scenario(
            scenario_key,
            user_id,
            ensure_roles,
            siem_type,
            resource_profile,
            customize,
            randomize,
            custom_users,
            vulnerability_config,
            network_customizations,
            vm_customizations,
        )

    async def get_scenario_config(
        self, scenario_key: str, siem_type: str = "wazuh", resource_profile: str = "recommended"
    ) -> dict:
        """Get scenario configuration.
        
        Args:
            scenario_key: Scenario identifier
            siem_type: SIEM type to include
            resource_profile: Resource allocation profile (minimal, recommended, maximum)
        """
        logger.debug(f"Getting config for scenario: {scenario_key} with SIEM: {siem_type}, Profile: {resource_profile}")
        return await self.manager.get_scenario_config(scenario_key, siem_type=siem_type, resource_profile=resource_profile)

    async def get_scenario_yaml(
        self, scenario_key: str, siem_type: str = "wazuh"
    ) -> str:
        """Get scenario configuration as YAML."""
        logger.debug(f"Getting YAML for scenario: {scenario_key} with SIEM: {siem_type}")
        return await self.manager.get_scenario_yaml(scenario_key, siem_type=siem_type)

    async def preview_scenario(
        self, 
        scenario_key: str, 
        siem_type: str = "wazuh",
        resource_profile: str = "recommended"
    ) -> PreviewResult:
        """
        Preview a scenario before deployment with detailed information.

        Args:
            scenario_key: Scenario identifier
            siem_type: SIEM type to include
            resource_profile: Resource allocation profile (minimal, recommended, maximum)

        Returns:
            PreviewResult with configuration, visualization, and estimates
        """
        logger.info(f"Previewing scenario: {scenario_key} with SIEM: {siem_type}, Profile: {resource_profile}")

        # Get scenario configuration
        config = await self.get_scenario_config(scenario_key, siem_type, resource_profile)

        # Generate enhanced visualization
        visualization = format_scenario_preview(scenario_key, config, siem_type, resource_profile)

        # Extract VMs for estimation
        # Note: config["ludus"] is an array of VMs, not a dict with "vms" key
        vms = config.get("ludus", [])
        if not isinstance(vms, list):
            vms = []

        # Calculate actual resources from config
        total_ram = sum(vm.get("ram_gb", 0) for vm in vms)
        total_cpus = sum(vm.get("cpus", 0) for vm in vms)

        # Estimate resources
        vm_count = len(vms)
        estimated_time = estimate_deployment_time(vm_count)
        estimated_memory_gb, estimated_disk_gb = estimate_resources(vms)

        # Build deploy command with all parameters
        deploy_command = f"ludus.deploy_scenario(scenario_key='{scenario_key}', siem_type='{siem_type}', resource_profile='{resource_profile}')"

        result = PreviewResult(
            scenario_key=scenario_key,
            siem_type=siem_type,
            config=config,
            visualization=visualization,
            vm_count=vm_count,
            estimated_time=estimated_time,
            estimated_memory_gb=estimated_memory_gb,
            estimated_disk_gb=estimated_disk_gb,
            deploy_command=deploy_command,
        )

        logger.debug(f"Preview complete: {vm_count} VMs, {total_ram}GB RAM, {total_cpus} CPUs, estimated time: {estimated_time}")
        return result

