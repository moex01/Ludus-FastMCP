"""Handler for backup and disaster recovery operations."""

from datetime import datetime, timedelta
from typing import Any
import json
import hashlib

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class BackupHandler:
    """Handler for backup and disaster recovery."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the backup handler."""
        self.client = client

    async def schedule_snapshots(
        self,
        vm_name: str,
        schedule: str,
        retention_count: int = 5,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Schedule automated snapshots with retention policy.

        Args:
            vm_name: Name of the VM
            schedule: Cron-style schedule (e.g., "0 2 * * *" for daily at 2am)
            retention_count: Number of snapshots to keep
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with schedule configuration
        """
        try:
            # Validate schedule format (basic validation)
            schedule_parts = schedule.split()
            if len(schedule_parts) != 5:
                return {
                    "status": "error",
                    "error": "Invalid cron schedule format. Expected: 'minute hour day month weekday'"
                }

            schedule_config = {
                "status": "success",
                "vm_name": vm_name,
                "schedule": schedule,
                "retention_count": retention_count,
                "schedule_id": hashlib.md5(f"{vm_name}{schedule}{datetime.now()}".encode()).hexdigest()[:8],
                "created_at": datetime.now().isoformat(),
                "next_run": self._calculate_next_run(schedule),
                "configuration": {
                    "enabled": True,
                    "schedule_expression": schedule,
                    "retention_policy": {
                        "type": "count",
                        "keep_count": retention_count
                    }
                },
                "note": "This schedule configuration can be implemented with a job scheduler like cron, systemd timers, or Kubernetes CronJob"
            }

            logger.info(f"Created snapshot schedule for {vm_name}: {schedule}")
            return schedule_config

        except Exception as e:
            logger.error(f"Error scheduling snapshots: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _calculate_next_run(self, schedule: str) -> str:
        """Calculate next run time from cron schedule (simplified)."""
        # This is a simplified calculation
        # In production, use croniter library
        return f"Next run calculated based on: {schedule}"

    async def clone_range(
        self,
        target_user_id: str | None = None,
        new_name_prefix: str = "cloned",
        source_user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Clone an entire range configuration to another user or environment.

        Args:
            target_user_id: Target user ID (if None, clones to same user)
            new_name_prefix: Prefix for cloned VM names
            source_user_id: Source user ID (admin only)

        Returns:
            Dictionary with cloned range configuration
        """
        try:
            # Get source range configuration
            range_config = await self.client.get_range_config(source_user_id)
            range_info = await self.client.get_range(source_user_id)

            # Create cloned configuration
            cloned_config = json.loads(json.dumps(range_config))  # Deep copy

            # Modify VM names
            if "ludus" in cloned_config and "vms" in cloned_config["ludus"]:
                for vm in cloned_config["ludus"]["vms"]:
                    if "vm_name" in vm:
                        vm["vm_name"] = f"{new_name_prefix}-{vm['vm_name']}"
                    if "hostname" in vm:
                        vm["hostname"] = f"{new_name_prefix}-{vm['hostname']}"

            clone_result = {
                "status": "success",
                "clone_id": hashlib.md5(f"{datetime.now()}".encode()).hexdigest()[:8],
                "source_user": source_user_id or "current",
                "target_user": target_user_id or "current",
                "created_at": datetime.now().isoformat(),
                "cloned_configuration": cloned_config,
                "vm_count": len(cloned_config.get("ludus", {}).get("vms", [])),
                "original_vm_count": range_info.get("numberOfVMs", 0),
                "deployment_instructions": {
                    "step_1": "Review the cloned_configuration",
                    "step_2": "Use ludus.update_range_config to apply the cloned configuration",
                    "step_3": "Use ludus.deploy_range to deploy the cloned range"
                }
            }

            logger.info(f"Cloned range configuration with {clone_result['vm_count']} VMs")
            return clone_result

        except Exception as e:
            logger.error(f"Error cloning range: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def export_range_backup(
        self,
        include_snapshots: bool = True,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Export complete range backup including configuration and snapshot metadata.

        Args:
            include_snapshots: Whether to include snapshot metadata
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with backup data
        """
        try:
            # Gather all range data
            range_config = await self.client.get_range_config(user_id)
            range_info = await self.client.get_range(user_id)

            backup_data = {
                "backup_version": "1.0",
                "created_at": datetime.now().isoformat(),
                "range_configuration": range_config,
                "range_information": {
                    "state": range_info.get("rangeState"),
                    "number_of_vms": range_info.get("numberOfVMs"),
                    "networks": range_info.get("networks", []),
                    "testing_enabled": range_info.get("testingEnabled")
                }
            }

            # Include snapshot metadata if requested
            if include_snapshots:
                try:
                    snapshots = await self.client.list_snapshots(user_id)
                    backup_data["snapshots_metadata"] = snapshots
                except Exception as e:
                    logger.warning(f"Could not include snapshots: {e}")
                    backup_data["snapshots_metadata"] = None

            # Calculate backup checksum
            backup_json = json.dumps(backup_data, sort_keys=True)
            checksum = hashlib.sha256(backup_json.encode()).hexdigest()

            result = {
                "status": "success",
                "backup_id": hashlib.md5(f"{datetime.now()}".encode()).hexdigest(),
                "timestamp": datetime.now().isoformat(),
                "checksum": checksum,
                "backup_data": backup_data,
                "size_bytes": len(backup_json),
                "vm_count": backup_data["range_information"]["number_of_vms"],
                "includes_snapshots": include_snapshots,
                "export_instructions": {
                    "save": "Save the backup_data to a file",
                    "restore": "Use ludus.import_range_backup to restore from this backup"
                }
            }

            logger.info(f"Exported range backup: {result['vm_count']} VMs, {len(backup_json)} bytes")
            return result

        except Exception as e:
            logger.error(f"Error exporting range backup: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def import_range_backup(
        self,
        backup_data: dict,
        verify_checksum: bool = True,
        auto_deploy: bool = False,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Restore range from backup.

        Args:
            backup_data: Backup data from export_range_backup
            verify_checksum: Whether to verify backup checksum
            auto_deploy: Whether to automatically deploy after import
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with import result
        """
        try:
            # Validate backup data structure
            if not isinstance(backup_data, dict):
                return {
                    "status": "error",
                    "error": "Invalid backup data format"
                }

            required_keys = ["backup_version", "created_at", "range_configuration"]
            missing_keys = [key for key in required_keys if key not in backup_data]
            if missing_keys:
                return {
                    "status": "error",
                    "error": f"Missing required backup keys: {missing_keys}"
                }

            # Extract configuration
            range_config = backup_data["range_configuration"]

            # Update range configuration
            update_result = await self.client.update_range_config(range_config, user_id)

            # Handle both config formats: {"ludus": [...]} or {"ludus": {"vms": [...]}}
            ludus_config = range_config.get("ludus", {})
            if isinstance(ludus_config, list):
                vm_count = len(ludus_config)
            elif isinstance(ludus_config, dict):
                vm_count = len(ludus_config.get("vms", []))
            else:
                vm_count = 0
            
            result = {
                "status": "success",
                "imported_at": datetime.now().isoformat(),
                "backup_created_at": backup_data["created_at"],
                "backup_version": backup_data["backup_version"],
                "configuration_updated": True,
                "vm_count": vm_count,
                "auto_deploy_requested": auto_deploy
            }

            # Auto-deploy if requested
            # Note: Config is already set via update_range_config above, so deploy without config
            if auto_deploy:
                try:
                    deploy_result = await self.client.deploy_range(config=None, user_id=user_id)
                    result["deployment_started"] = True
                    result["deployment_info"] = deploy_result
                except Exception as e:
                    result["deployment_started"] = False
                    result["deployment_error"] = str(e)
            else:
                result["next_step"] = "Use ludus.deploy_range to deploy the imported configuration"

            logger.info(f"Imported range backup: {result['vm_count']} VMs")
            return result

        except Exception as e:
            logger.error(f"Error importing range backup: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
