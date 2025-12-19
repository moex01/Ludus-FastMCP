"""Configuration validation handler for Ludus ranges."""

import ipaddress
from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.schemas.validation import ValidationError, ValidationResult
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class ValidationHandler:
    """Handler for validating Ludus range configurations."""

    def __init__(self, client: LudusAPIClient):
        """
        Initialize validation handler.

        Args:
            client: Ludus API client
        """
        self.client = client

    async def validate_config(self, config: dict) -> ValidationResult:
        """
        Validate a Ludus range configuration.

        Args:
            config: Range configuration dictionary

        Returns:
            ValidationResult with errors, warnings, and recommendations
        """
        logger.info("Validating range configuration")

        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []
        recommendations: list[str] = []

        # Extract ludus config - handle both formats:
        # Format 1: {"ludus": [vm1, vm2, ...]} - scenario builder format (list directly)
        # Format 2: {"ludus": {"vms": [vm1, vm2, ...], "networks": [...]}} - alternative format
        ludus_config = config.get("ludus", {})
        
        # Determine if ludus is a list (scenario format) or dict (alternative format)
        if isinstance(ludus_config, list):
            # Scenario builder format: ludus is a list of VMs directly
            vms = ludus_config
            networks = []  # Networks are at root level in scenario format
        elif isinstance(ludus_config, dict):
            # Alternative format: ludus is a dict with vms and networks inside
            vms = ludus_config.get("vms", [])
            networks = ludus_config.get("networks", [])
        else:
            vms = []
            networks = []

        # Validate VMs
        if not vms:
            errors.append(
                ValidationError(
                    field="ludus",
                    message="No VMs defined in configuration",
                    severity="error"
                )
            )
        else:
            await self._validate_vms(vms, errors, warnings, recommendations)

        # Validate networks (if provided in ludus config, otherwise check root level)
        if not networks:
            # Check if networks are at root level (scenario format)
            networks = config.get("network", {}).get("rules", []) if isinstance(config.get("network"), dict) else []
        if networks:
            self._validate_networks(networks, errors, warnings)

        # Validate network assignments
        if vms and networks:
            self._validate_network_assignments(vms, networks, errors, warnings)

        # Validate resources
        self._validate_resources(vms, warnings, recommendations)

        # Additional recommendations
        self._generate_recommendations(config, recommendations)

        result = ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            recommendations=recommendations
        )

        logger.info(f"Validation complete: valid={result.valid}, errors={len(errors)}, warnings={len(warnings)}")
        return result

    async def _validate_vms(
        self,
        vms: list[dict],
        errors: list[ValidationError],
        warnings: list[ValidationError],
        recommendations: list[str]
    ) -> None:
        """Validate VM configurations."""
        # Get available templates
        try:
            templates_response = await self.client.list_templates()
            available_templates = [t.get("name", "") for t in templates_response.get("templates", [])]
        except Exception as e:
            logger.warning(f"Could not fetch templates: {e}")
            available_templates = []

        # Get installed roles
        try:
            roles_response = await self.client.list_roles()
            installed_roles = roles_response.get("roles", [])
        except Exception as e:
            logger.warning(f"Could not fetch roles: {e}")
            installed_roles = []

        vm_names = set()

        for i, vm in enumerate(vms):
            vm_name = vm.get("hostname", vm.get("name", f"vm-{i}"))

            # Check for duplicate names
            if vm_name in vm_names:
                errors.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].hostname",
                        message=f"Duplicate VM name: {vm_name}",
                        severity="error"
                    )
                )
            vm_names.add(vm_name)

            # Check template exists
            template = vm.get("template", "")
            if not template:
                errors.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].template",
                        message=f"VM '{vm_name}' has no template specified",
                        severity="error"
                    )
                )
            elif available_templates and template not in available_templates:
                errors.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].template",
                        message=f"Template '{template}' not found for VM '{vm_name}'. Available templates: {', '.join(available_templates[:5])}",
                        severity="error"
                    )
                )

            # Check roles
            vm_roles = vm.get("roles", [])
            for role in vm_roles:
                if installed_roles and role not in installed_roles:
                    warnings.append(
                        ValidationError(
                            field=f"ludus.vms[{i}].roles",
                            message=f"Role '{role}' not installed for VM '{vm_name}' (will auto-install if available)",
                            severity="warning"
                        )
                    )

            # Validate resource specs
            ram_mb = vm.get("ram_mb", 0)
            if ram_mb > 0 and ram_mb < 1024:
                warnings.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].ram_mb",
                        message=f"VM '{vm_name}' has very low RAM ({ram_mb}MB). Minimum recommended: 2048MB",
                        severity="warning"
                    )
                )

            disk_gb = vm.get("disk_size_gb", 0)
            if disk_gb > 0 and disk_gb < 20:
                warnings.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].disk_size_gb",
                        message=f"VM '{vm_name}' has very small disk ({disk_gb}GB). Minimum recommended: 30GB",
                        severity="warning"
                    )
                )

    def _validate_networks(
        self,
        networks: list[dict],
        errors: list[ValidationError],
        warnings: list[ValidationError]
    ) -> None:
        """Validate network configurations."""
        network_names = set()
        cidrs = []

        for i, network in enumerate(networks):
            net_name = network.get("name", f"network-{i}")

            # Check for duplicate names
            if net_name in network_names:
                errors.append(
                    ValidationError(
                        field=f"ludus.networks[{i}].name",
                        message=f"Duplicate network name: {net_name}",
                        severity="error"
                    )
                )
            network_names.add(net_name)

            # Validate CIDR
            cidr = network.get("cidr", "")
            if not cidr:
                errors.append(
                    ValidationError(
                        field=f"ludus.networks[{i}].cidr",
                        message=f"Network '{net_name}' has no CIDR specified",
                        severity="error"
                    )
                )
            else:
                try:
                    network_obj = ipaddress.ip_network(cidr, strict=False)
                    cidrs.append(network_obj)

                    # Check if it's a private network
                    if not network_obj.is_private:
                        warnings.append(
                            ValidationError(
                                field=f"ludus.networks[{i}].cidr",
                                message=f"Network '{net_name}' uses public IP space ({cidr})",
                                severity="warning"
                            )
                        )
                except ValueError as e:
                    errors.append(
                        ValidationError(
                            field=f"ludus.networks[{i}].cidr",
                            message=f"Invalid CIDR '{cidr}' for network '{net_name}': {e}",
                            severity="error"
                        )
                    )

        # Check for overlapping CIDRs
        for i, cidr1 in enumerate(cidrs):
            for j, cidr2 in enumerate(cidrs[i + 1:], start=i + 1):
                if cidr1.overlaps(cidr2):
                    warnings.append(
                        ValidationError(
                            field=f"ludus.networks",
                            message=f"Networks {networks[i].get('name')} and {networks[j].get('name')} have overlapping CIDRs",
                            severity="warning"
                        )
                    )

    def _validate_network_assignments(
        self,
        vms: list[dict],
        networks: list[dict],
        errors: list[ValidationError],
        warnings: list[ValidationError]
    ) -> None:
        """Validate that VMs are assigned to valid networks."""
        network_names = {net.get("name") for net in networks}

        for i, vm in enumerate(vms):
            vm_name = vm.get("hostname", vm.get("name", f"vm-{i}"))
            vm_network = vm.get("network", "")

            if vm_network and vm_network not in network_names:
                errors.append(
                    ValidationError(
                        field=f"ludus.vms[{i}].network",
                        message=f"VM '{vm_name}' assigned to non-existent network '{vm_network}'",
                        severity="error"
                    )
                )

    def _validate_resources(
        self,
        vms: list[dict],
        warnings: list[ValidationError],
        recommendations: list[str]
    ) -> None:
        """Validate total resource requirements."""
        total_ram_gb = 0
        total_disk_gb = 0

        for vm in vms:
            # RAM
            ram_mb = vm.get("ram_mb", 0)
            if ram_mb == 0:
                # Estimate based on template
                template = vm.get("template", "").lower()
                if "server" in template or "windows" in template:
                    ram_mb = 4096
                else:
                    ram_mb = 2048

            total_ram_gb += ram_mb / 1024

            # Disk
            disk_gb = vm.get("disk_size_gb", 0)
            if disk_gb == 0:
                # Estimate based on template
                template = vm.get("template", "").lower()
                if "windows" in template:
                    disk_gb = 60
                else:
                    disk_gb = 30

            total_disk_gb += disk_gb

        # Warn about high resource usage
        if total_ram_gb > 32:
            warnings.append(
                ValidationError(
                    field="ludus.vms",
                    message=f"High total RAM requirement: {int(total_ram_gb)}GB. Ensure your host has sufficient resources.",
                    severity="warning"
                )
            )

        if total_disk_gb > 500:
            warnings.append(
                ValidationError(
                    field="ludus.vms",
                    message=f"High total disk requirement: {int(total_disk_gb)}GB. Ensure sufficient disk space.",
                    severity="warning"
                )
            )

        recommendations.append(f"Total estimated resources: {int(total_ram_gb)}GB RAM, {int(total_disk_gb)}GB disk")

    def _generate_recommendations(self, config: dict, recommendations: list[str]) -> None:
        """Generate general recommendations."""
        ludus_config = config.get("ludus", {})
        vms = ludus_config.get("vms", [])

        # Check for SIEM
        has_siem = any("siem" in vm.get("role", "").lower() or "wazuh" in vm.get("hostname", "").lower() for vm in vms)
        if not has_siem and len(vms) > 2:
            recommendations.append("Consider adding a SIEM server for monitoring (Wazuh, Splunk, Elastic)")

        # Check for attacker VM
        has_attacker = any("kali" in vm.get("template", "").lower() or "attacker" in vm.get("role", "").lower() for vm in vms)
        if not has_attacker:
            recommendations.append("Consider adding an attacker VM (Kali Linux) for security testing")

        # Check for domain controller
        has_dc = any("dc" in vm.get("hostname", "").lower() or "domain controller" in vm.get("role", "").lower() for vm in vms)
        if has_dc:
            recommendations.append("Domain controller detected - allow 10-15 minutes for AD services to fully initialize")
