"""Handler for metrics and analytics operations."""

from datetime import datetime, timedelta
from typing import Any
import json

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.utils.logging import get_logger

logger = get_logger(__name__)


class MetricsHandler:
    """Handler for metrics and analytics."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the metrics handler."""
        self.client = client

    async def get_range_metrics(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Get comprehensive range metrics including VM resource utilization.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with range metrics
        """
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])

            # Calculate VM statistics
            total_vms = len(vms)
            running_vms = sum(1 for vm in vms if vm.get("status") == "running")
            stopped_vms = sum(1 for vm in vms if vm.get("status") == "stopped")

            # Calculate resource allocations
            total_memory_mb = sum(vm.get("memory", 0) for vm in vms)
            total_cpus = sum(vm.get("cpus", 0) for vm in vms)
            total_disk_gb = sum(vm.get("disk", 0) for vm in vms)

            # VM distribution by OS
            os_distribution = {}
            for vm in vms:
                os_name = vm.get("template", "unknown")
                os_distribution[os_name] = os_distribution.get(os_name, 0) + 1

            metrics = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "range_state": range_info.get("rangeState", "UNKNOWN"),
                "vm_statistics": {
                    "total_vms": total_vms,
                    "running_vms": running_vms,
                    "stopped_vms": stopped_vms,
                    "utilization_percentage": (running_vms / total_vms * 100) if total_vms > 0 else 0
                },
                "resource_allocation": {
                    "total_memory_mb": total_memory_mb,
                    "total_memory_gb": round(total_memory_mb / 1024, 2),
                    "total_cpus": total_cpus,
                    "total_disk_gb": total_disk_gb,
                    "average_memory_per_vm": round(total_memory_mb / total_vms, 2) if total_vms > 0 else 0,
                    "average_cpus_per_vm": round(total_cpus / total_vms, 2) if total_vms > 0 else 0
                },
                "os_distribution": os_distribution,
                "network_count": len(range_info.get("networks", [])),
                "testing_enabled": range_info.get("testingEnabled", False),
                "last_deployment": range_info.get("lastDeployment")
            }

            logger.info(f"Retrieved metrics for range: {total_vms} VMs, {running_vms} running")
            return metrics

        except Exception as e:
            logger.error(f"Error getting range metrics: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def get_deployment_metrics(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Get deployment statistics and patterns.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with deployment metrics
        """
        try:
            range_info = await self.client.get_range(user_id)
            logs = await self.client.get_range_logs(user_id)

            # Parse deployment state
            range_state = range_info.get("rangeState", "UNKNOWN")
            last_deployment = range_info.get("lastDeployment")

            # Analyze logs for deployment patterns
            log_lines = logs.split("\n") if logs else []
            error_count = sum(1 for line in log_lines if "error" in line.lower() or "failed" in line.lower())
            warning_count = sum(1 for line in log_lines if "warning" in line.lower())

            # Calculate deployment success
            deployment_successful = range_state == "SUCCESS"

            metrics = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "current_deployment": {
                    "state": range_state,
                    "successful": deployment_successful,
                    "last_deployment_time": last_deployment,
                    "vm_count": range_info.get("numberOfVMs", 0)
                },
                "log_analysis": {
                    "total_lines": len(log_lines),
                    "error_count": error_count,
                    "warning_count": warning_count,
                    "has_errors": error_count > 0
                },
                "health_score": self._calculate_health_score(
                    range_state, error_count, warning_count, range_info
                )
            }

            logger.info(f"Retrieved deployment metrics: state={range_state}, health={metrics['health_score']}")
            return metrics

        except Exception as e:
            logger.error(f"Error getting deployment metrics: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _calculate_health_score(
        self,
        range_state: str,
        error_count: int,
        warning_count: int,
        range_info: dict
    ) -> dict[str, Any]:
        """Calculate a health score for the range."""
        score = 100.0
        issues = []

        # Deduct points for state
        if range_state == "FAILED":
            score -= 50
            issues.append("Deployment failed")
        elif range_state == "DEPLOYING":
            score -= 10
            issues.append("Deployment in progress")
        elif range_state == "DELETED":
            score = 0
            issues.append("Range deleted")

        # Deduct points for errors and warnings
        score -= min(error_count * 5, 30)
        score -= min(warning_count * 2, 15)

        if error_count > 0:
            issues.append(f"{error_count} errors in logs")
        if warning_count > 0:
            issues.append(f"{warning_count} warnings in logs")

        # Check VM health
        vms = range_info.get("VMs", [])
        if vms:
            running = sum(1 for vm in vms if vm.get("status") == "running")
            if running < len(vms):
                ratio = running / len(vms)
                score -= (1 - ratio) * 20
                issues.append(f"Only {running}/{len(vms)} VMs running")

        score = max(0, min(100, score))

        return {
            "score": round(score, 2),
            "grade": self._score_to_grade(score),
            "issues": issues
        }

    def _score_to_grade(self, score: float) -> str:
        """Convert health score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    async def get_cost_estimation(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Estimate resource costs based on VM configurations.

        Args:
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with cost estimations
        """
        try:
            range_info = await self.client.get_range(user_id)
            vms = range_info.get("VMs", [])

            # Cost calculation constants (example rates - adjust as needed)
            COST_PER_GB_RAM_HOUR = 0.01  # $0.01 per GB RAM per hour
            COST_PER_CPU_HOUR = 0.05  # $0.05 per CPU per hour
            COST_PER_GB_DISK_MONTH = 0.10  # $0.10 per GB disk per month

            # Calculate costs
            total_memory_gb = sum(vm.get("memory", 0) for vm in vms) / 1024
            total_cpus = sum(vm.get("cpus", 0) for vm in vms)
            total_disk_gb = sum(vm.get("disk", 0) for vm in vms)

            # Hourly costs
            hourly_ram_cost = total_memory_gb * COST_PER_GB_RAM_HOUR
            hourly_cpu_cost = total_cpus * COST_PER_CPU_HOUR
            hourly_total = hourly_ram_cost + hourly_cpu_cost

            # Monthly costs
            monthly_ram_cost = hourly_ram_cost * 24 * 30
            monthly_cpu_cost = hourly_cpu_cost * 24 * 30
            monthly_disk_cost = total_disk_gb * COST_PER_GB_DISK_MONTH
            monthly_total = monthly_ram_cost + monthly_cpu_cost + monthly_disk_cost

            estimation = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "disclaimer": "These are estimated costs. Actual costs may vary based on your infrastructure provider.",
                "resource_summary": {
                    "total_memory_gb": round(total_memory_gb, 2),
                    "total_cpus": total_cpus,
                    "total_disk_gb": total_disk_gb,
                    "vm_count": len(vms)
                },
                "hourly_costs": {
                    "ram": round(hourly_ram_cost, 4),
                    "cpu": round(hourly_cpu_cost, 4),
                    "total": round(hourly_total, 4)
                },
                "daily_costs": {
                    "total": round(hourly_total * 24, 2)
                },
                "monthly_costs": {
                    "ram": round(monthly_ram_cost, 2),
                    "cpu": round(monthly_cpu_cost, 2),
                    "disk": round(monthly_disk_cost, 2),
                    "total": round(monthly_total, 2)
                },
                "cost_breakdown_per_vm": self._calculate_per_vm_costs(vms)
            }

            logger.info(f"Cost estimation: ${monthly_total:.2f}/month for {len(vms)} VMs")
            return estimation

        except Exception as e:
            logger.error(f"Error calculating cost estimation: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _calculate_per_vm_costs(self, vms: list[dict]) -> list[dict]:
        """Calculate cost breakdown per VM."""
        COST_PER_GB_RAM_HOUR = 0.01
        COST_PER_CPU_HOUR = 0.05

        vm_costs = []
        for vm in vms:
            memory_gb = vm.get("memory", 0) / 1024
            cpus = vm.get("cpus", 0)

            hourly_cost = (memory_gb * COST_PER_GB_RAM_HOUR) + (cpus * COST_PER_CPU_HOUR)
            monthly_cost = hourly_cost * 24 * 30

            vm_costs.append({
                "name": vm.get("name", "unknown"),
                "template": vm.get("template", "unknown"),
                "hourly_cost": round(hourly_cost, 4),
                "monthly_cost": round(monthly_cost, 2)
            })

        return vm_costs

    async def export_metrics(
        self,
        format: str = "json",
        user_id: str | None = None
    ) -> dict[str, Any]:
        """
        Export metrics in various formats (json, prometheus, csv).

        Args:
            format: Export format (json, prometheus, csv)
            user_id: Optional user ID (admin only)

        Returns:
            Dictionary with exported metrics
        """
        try:
            # Gather all metrics
            range_metrics = await self.get_range_metrics(user_id)
            deployment_metrics = await self.get_deployment_metrics(user_id)
            cost_metrics = await self.get_cost_estimation(user_id)

            combined_metrics = {
                "export_timestamp": datetime.now().isoformat(),
                "range_metrics": range_metrics,
                "deployment_metrics": deployment_metrics,
                "cost_metrics": cost_metrics
            }

            if format.lower() == "json":
                return {
                    "status": "success",
                    "format": "json",
                    "data": json.dumps(combined_metrics, indent=2)
                }

            elif format.lower() == "prometheus":
                prometheus_data = self._convert_to_prometheus(combined_metrics)
                return {
                    "status": "success",
                    "format": "prometheus",
                    "data": prometheus_data
                }

            elif format.lower() == "csv":
                csv_data = self._convert_to_csv(combined_metrics)
                return {
                    "status": "success",
                    "format": "csv",
                    "data": csv_data
                }

            else:
                return {
                    "status": "error",
                    "error": f"Unsupported format: {format}. Supported formats: json, prometheus, csv"
                }

        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _convert_to_prometheus(self, metrics: dict) -> str:
        """Convert metrics to Prometheus format."""
        lines = []
        lines.append("# HELP ludus_range_vms_total Total number of VMs in range")
        lines.append("# TYPE ludus_range_vms_total gauge")

        if metrics.get("range_metrics", {}).get("status") == "success":
            rm = metrics["range_metrics"]
            vm_stats = rm.get("vm_statistics", {})

            lines.append(f"ludus_range_vms_total {vm_stats.get('total_vms', 0)}")
            lines.append(f"ludus_range_vms_running {vm_stats.get('running_vms', 0)}")
            lines.append(f"ludus_range_vms_stopped {vm_stats.get('stopped_vms', 0)}")

            res_alloc = rm.get("resource_allocation", {})
            lines.append(f"ludus_range_memory_gb_total {res_alloc.get('total_memory_gb', 0)}")
            lines.append(f"ludus_range_cpus_total {res_alloc.get('total_cpus', 0)}")
            lines.append(f"ludus_range_disk_gb_total {res_alloc.get('total_disk_gb', 0)}")

        if metrics.get("deployment_metrics", {}).get("status") == "success":
            dm = metrics["deployment_metrics"]
            health = dm.get("health_score", {})
            lines.append(f"ludus_range_health_score {health.get('score', 0)}")

        return "\n".join(lines)

    def _convert_to_csv(self, metrics: dict) -> str:
        """Convert metrics to CSV format."""
        lines = []
        lines.append("metric_name,value,unit,timestamp")

        timestamp = metrics.get("export_timestamp", "")

        if metrics.get("range_metrics", {}).get("status") == "success":
            rm = metrics["range_metrics"]
            vm_stats = rm.get("vm_statistics", {})

            lines.append(f"total_vms,{vm_stats.get('total_vms', 0)},count,{timestamp}")
            lines.append(f"running_vms,{vm_stats.get('running_vms', 0)},count,{timestamp}")
            lines.append(f"stopped_vms,{vm_stats.get('stopped_vms', 0)},count,{timestamp}")

            res_alloc = rm.get("resource_allocation", {})
            lines.append(f"total_memory,{res_alloc.get('total_memory_gb', 0)},GB,{timestamp}")
            lines.append(f"total_cpus,{res_alloc.get('total_cpus', 0)},count,{timestamp}")
            lines.append(f"total_disk,{res_alloc.get('total_disk_gb', 0)},GB,{timestamp}")

        return "\n".join(lines)
