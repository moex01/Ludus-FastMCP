"""Handler for resource management operations."""

from datetime import datetime, timedelta
from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class ResourceManagementHandler:
    """Handler for resource management."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the resource management handler."""
        self.client = client

    async def get_resource_quotas(self, user_id: str | None = None) -> dict[str, Any]:
        """View resource limits and usage."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])

            # Calculate current usage
            current_usage = {
                "vms": len(vms),
                "memory_mb": sum(vm.get("memory", 0) for vm in vms),
                "cpus": sum(vm.get("cpus", 0) for vm in vms),
                "disk_gb": sum(vm.get("disk", 0) for vm in vms)
            }

            # Define quotas (example values - should be configurable)
            quotas = {
                "max_vms": 50,
                "max_memory_gb": 256,
                "max_cpus": 64,
                "max_disk_gb": 2000
            }

            # Calculate usage percentages
            usage_percentages = {
                "vms": (current_usage["vms"] / quotas["max_vms"] * 100),
                "memory": (current_usage["memory_mb"] / 1024 / quotas["max_memory_gb"] * 100),
                "cpus": (current_usage["cpus"] / quotas["max_cpus"] * 100),
                "disk": (current_usage["disk_gb"] / quotas["max_disk_gb"] * 100)
            }

            # Check for quota warnings
            warnings = []
            for resource, percentage in usage_percentages.items():
                if percentage >= 90:
                    warnings.append(f"{resource.upper()} usage at {percentage:.1f}% - approaching limit")
                elif percentage >= 75:
                    warnings.append(f"{resource.upper()} usage at {percentage:.1f}% - monitor closely")

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "current_usage": current_usage,
                "quotas": quotas,
                "usage_percentages": {k: round(v, 2) for k, v in usage_percentages.items()},
                "available_resources": {
                    "vms": quotas["max_vms"] - current_usage["vms"],
                    "memory_gb": quotas["max_memory_gb"] - (current_usage["memory_mb"] / 1024),
                    "cpus": quotas["max_cpus"] - current_usage["cpus"],
                    "disk_gb": quotas["max_disk_gb"] - current_usage["disk_gb"]
                },
                "warnings": warnings
            }
        except Exception as e:
            logger.error(f"Error getting resource quotas: {e}")
            return {"status": "error", "error": str(e)}

    async def optimize_resource_allocation(self, user_id: str | None = None) -> dict[str, Any]:
        """Suggest resource optimization."""
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])

            optimizations = []
            total_savings = {"memory_mb": 0, "cpus": 0, "disk_gb": 0}

            for vm in vms:
                vm_name = vm.get("name", "unknown")
                memory = vm.get("memory", 0)
                cpus = vm.get("cpus", 0)
                disk = vm.get("disk", 0)

                # Memory optimization
                if memory > 8192:
                    savings = memory - 8192
                    optimizations.append({
                        "vm": vm_name,
                        "resource": "memory",
                        "current": memory,
                        "suggested": 8192,
                        "savings_mb": savings,
                        "reason": "High memory allocation, consider reducing"
                    })
                    total_savings["memory_mb"] += savings

                # CPU optimization
                if cpus > 4:
                    savings = cpus - 4
                    optimizations.append({
                        "vm": vm_name,
                        "resource": "cpu",
                        "current": cpus,
                        "suggested": 4,
                        "savings_cpus": savings,
                        "reason": "High CPU allocation, most workloads use 2-4 cores"
                    })
                    total_savings["cpus"] += savings

                # Disk optimization
                if disk > 100:
                    savings = disk - 80
                    optimizations.append({
                        "vm": vm_name,
                        "resource": "disk",
                        "current": disk,
                        "suggested": 80,
                        "savings_gb": savings,
                        "reason": "Large disk allocation, review actual usage"
                    })
                    total_savings["disk_gb"] += savings

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "optimizations": optimizations,
                "total_savings": total_savings,
                "potential_cost_savings": {
                    "monthly_usd": round(
                        (total_savings["memory_mb"] / 1024 * 0.01 * 24 * 30) +
                        (total_savings["cpus"] * 0.05 * 24 * 30) +
                        (total_savings["disk_gb"] * 0.10),
                        2
                    )
                },
                "summary": f"{len(optimizations)} optimization opportunities found"
            }
        except Exception as e:
            logger.error(f"Error optimizing resource allocation: {e}")
            return {"status": "error", "error": str(e)}

    async def schedule_maintenance_window(
        self,
        start_time: str,
        duration_hours: int,
        description: str,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Plan maintenance with minimal disruption."""
        try:
            range_info = await self.client.get_range(user_id)

            # Parse start time
            try:
                start_dt = datetime.fromisoformat(start_time)
            except Exception:
                return {
                    "status": "error",
                    "error": "Invalid start_time format. Use ISO format: YYYY-MM-DDTHH:MM:SS"
                }

            end_dt = start_dt + timedelta(hours=duration_hours)

            maintenance_window = {
                "start_time": start_dt.isoformat(),
                "end_time": end_dt.isoformat(),
                "duration_hours": duration_hours,
                "description": description,
                "range_state": range_info.get("rangeState"),
                "pre_maintenance_tasks": [
                    {"task": "Create snapshots of all VMs", "tool": "ludus.snapshot_host"},
                    {"task": "Notify users of downtime", "tool": "communication"},
                    {"task": "Document current configuration", "tool": "ludus.export_range_backup"}
                ],
                "maintenance_tasks": [
                    {"task": description, "estimated_time": f"{duration_hours}h"}
                ],
                "post_maintenance_tasks": [
                    {"task": "Verify all VMs are running", "tool": "ludus.get_range"},
                    {"task": "Test connectivity", "tool": "ludus.test_network_connectivity"},
                    {"task": "Notify users of completion", "tool": "communication"}
                ],
                "rollback_plan": {
                    "trigger": "If maintenance fails",
                    "action": "Use ludus.rollback_snapshot to restore pre-maintenance state"
                }
            }

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "maintenance_window": maintenance_window,
                "affected_vms": range_info.get("numberOfVMs", 0)
            }
        except Exception as e:
            logger.error(f"Error scheduling maintenance window: {e}")
            return {"status": "error", "error": str(e)}

    async def bulk_vm_operations(
        self,
        operation: str,
        vm_filter: dict | None = None,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Bulk operations on multiple VMs."""
        try:
            valid_operations = ["power_on", "power_off", "snapshot", "delete", "restart"]
            if operation not in valid_operations:
                return {
                    "status": "error",
                    "error": f"Invalid operation. Must be one of: {valid_operations}"
                }

            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])

            # Apply filters if specified
            if vm_filter:
                if "status" in vm_filter:
                    vms = [vm for vm in vms if vm.get("status") == vm_filter["status"]]
                if "template" in vm_filter:
                    vms = [vm for vm in vms if vm_filter["template"] in vm.get("template", "")]
                if "name_pattern" in vm_filter:
                    pattern = vm_filter["name_pattern"].lower()
                    vms = [vm for vm in vms if pattern in vm.get("name", "").lower()]

            # Generate operation plan
            operations_plan = []
            for vm in vms:
                operations_plan.append({
                    "vm_name": vm.get("name"),
                    "current_status": vm.get("status"),
                    "operation": operation,
                    "estimated_time_seconds": self._estimate_operation_time(operation)
                })

            total_time = sum(op["estimated_time_seconds"] for op in operations_plan)

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "filter_applied": vm_filter or "none",
                "affected_vms": len(operations_plan),
                "operations_plan": operations_plan,
                "estimated_total_time": {
                    "seconds": total_time,
                    "minutes": round(total_time / 60, 2)
                },
                "execution_guide": {
                    "sequential": "Execute operations one by one",
                    "parallel": "Use Ansible with async for parallel execution",
                    "tool_mapping": {
                        "power_on": "ludus.power_on_range",
                        "power_off": "ludus.power_off_range",
                        "snapshot": "ludus.snapshot_host (loop through VMs)"
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error planning bulk VM operations: {e}")
            return {"status": "error", "error": str(e)}

    def _estimate_operation_time(self, operation: str) -> int:
        """Estimate operation time in seconds."""
        estimates = {
            "power_on": 60,
            "power_off": 30,
            "snapshot": 120,
            "delete": 45,
            "restart": 90
        }
        return estimates.get(operation, 60)
