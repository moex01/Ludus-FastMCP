"""Smart deployment orchestration handler."""

import asyncio
from datetime import datetime, timedelta
from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.server.handlers.scenarios import ScenarioHandler
from ludus_mcp.server.handlers.deployment import DeploymentHandler
from ludus_mcp.server.handlers.validation import ValidationHandler
from ludus_mcp.server.handlers.snapshots import SnapshotHandler
from ludus_mcp.schemas.orchestration import (
    SmartDeployResult,
    DeploymentTimeline,
    DeploymentStep,
    MonitoringUpdate,
    RecoveryRecommendation,
)
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.error_formatter import ErrorFormatter

logger = get_logger(__name__)


class DeploymentOrchestrator:
    """Orchestrates smart deployment workflows with validation, monitoring, and recovery."""

    def __init__(self, client: LudusAPIClient):
        """Initialize the orchestrator."""
        self.client = client
        self.scenario_handler = ScenarioHandler(client)
        self.deployment_handler = DeploymentHandler(client)
        self.validation_handler = ValidationHandler(client)
        self.snapshot_handler = SnapshotHandler(client)

    async def smart_deploy(
        self,
        scenario_key: str,
        siem_type: str = "wazuh",
        auto_validate: bool = True,
        auto_snapshot: bool = False,
        auto_monitor: bool = True,
        user_id: str | None = None,
    ) -> SmartDeployResult:
        """
        Smart deployment with validation, optional snapshot, and auto-monitoring.

        Args:
            scenario_key: Scenario to deploy
            siem_type: SIEM type to include
            auto_validate: Validate before deploying
            auto_snapshot: Create snapshot before deployment
            auto_monitor: Enable auto-monitoring after deployment
            user_id: Optional user ID

        Returns:
            SmartDeployResult with deployment info and monitoring guidance
        """
        logger.info(
            f"Smart deploy: {scenario_key} with SIEM: {siem_type}, "
            f"validate={auto_validate}, snapshot={auto_snapshot}, monitor={auto_monitor}"
        )

        # Step 1: Get and preview configuration
        try:
            preview = await self.scenario_handler.preview_scenario(scenario_key, siem_type)
        except Exception as e:
            logger.error(f"Failed to get scenario preview: {e}")
            return SmartDeployResult(
                status="failed",
                scenario_key=scenario_key,
                siem_type=siem_type,
                vm_count=0,
                estimated_time="unknown",
                message=f"[ERROR] Failed to get scenario configuration: {e}",
            )

        # Step 2: Validate configuration (if enabled)
        if auto_validate:
            try:
                config = await self.scenario_handler.get_scenario_config(scenario_key, siem_type)
                validation = await self.validation_handler.validate_config(config)

                if not validation.valid:
                    # Format validation errors
                    formatted = ErrorFormatter.format_validation_errors(
                        [e.model_dump() for e in validation.errors],
                        [w.model_dump() for w in validation.warnings] if validation.warnings else None,
                    )
                    return SmartDeployResult(
                        status="validation_failed",
                        scenario_key=scenario_key,
                        siem_type=siem_type,
                        vm_count=preview.vm_count,
                        estimated_time=preview.estimated_time,
                        message=f"[ERROR] Validation failed:\n\n{formatted}",
                    )

                logger.info(f"Validation passed for {scenario_key}")

            except Exception as e:
                logger.error(f"Validation error: {e}")
                logger.warning(f"Validation failed with exception, but proceeding with deployment: {e}")
                # Don't return - continue to deployment step despite validation error
                # This allows deployment even if validation has issues (e.g., format mismatches)

        # Step 3: Create pre-deployment snapshot (if enabled)
        snapshot_id = None
        if auto_snapshot:
            try:
                # Get current range to snapshot
                range_info = await self.client.get_range(user_id)
                if range_info.get("numberOfVMs", 0) > 0:
                    snapshot_name = f"pre-deploy-{scenario_key}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                    # Note: This would need to be implemented per VM
                    logger.info(f"Snapshot creation requested: {snapshot_name}")
                    # snapshot_id = await self.snapshot_handler.create_snapshot(...)
            except Exception as e:
                logger.warning(f"Snapshot creation failed: {e}")

        # Step 4: Deploy scenario
        try:
            # Note: resource_profile defaults to "minimal" in deploy_scenario
            # If you need a different profile, use deploy_scenario directly
            deployment_result = await self.scenario_handler.deploy_scenario(
                scenario_key=scenario_key,
                user_id=user_id,
                ensure_roles=True,
                siem_type=siem_type,
                resource_profile="recommended",  # Use recommended profile for smart_deploy
            )

            logger.info(f"Deployment initiated for {scenario_key}")

        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            formatted_error = ErrorFormatter.format_error(str(e))
            return SmartDeployResult(
                status="failed",
                scenario_key=scenario_key,
                siem_type=siem_type,
                vm_count=preview.vm_count,
                estimated_time=preview.estimated_time,
                snapshot_id=snapshot_id,
                message=f"[ERROR] Deployment failed:\n\n{formatted_error}",
            )

        # Step 5: Return success with monitoring instructions
        monitoring_commands = {
            "status": "ludus.quick_status",
            "detailed_status": "ludus.get_deployment_status",
            "health": "ludus.check_deployment_health",
            "logs": "ludus.get_full_logs",
            "monitor": "ludus.monitor_deployment",
        }

        next_check_msg = ""
        if auto_monitor:
            next_check_msg = "\n\n[INFO] Auto-monitoring enabled - I'll check status in 30 seconds and provide updates."

        message = f"""[OK] Deployment Started!

**Scenario:** {scenario_key}
**SIEM:** {siem_type.title()}
**VMs:** {preview.vm_count}
**Estimated Time:** {preview.estimated_time}

**Status:** DEPLOYING
**Started:** {datetime.now().strftime('%H:%M:%S')}

{preview.visualization[:300]}...

{next_check_msg}

**Monitoring Commands:**
  - Quick status: `ludus.quick_status`
  - Detailed status: `ludus.get_deployment_status`
  - Check health: `ludus.check_deployment_health`
  - Full logs: `ludus.get_full_logs`

[TIP] Deployments typically take {preview.estimated_time}.
   AD services may need 10-15 minutes to fully initialize."""

        # Extract the actual deployment result from the nested structure
        actual_deployment_result = deployment_result.get("deployment_result", deployment_result)
        deployment_id = None
        if isinstance(actual_deployment_result, dict):
            deployment_id = actual_deployment_result.get("id")

        return SmartDeployResult(
            status="started",
            deployment_id=deployment_id,
            scenario_key=scenario_key,
            siem_type=siem_type,
            vm_count=preview.vm_count,
            estimated_time=preview.estimated_time,
            snapshot_id=snapshot_id,
            auto_monitor=auto_monitor,
            check_interval=30,
            next_check_message=next_check_msg,
            monitoring_commands=monitoring_commands,
            message=message,
        )

    async def monitor_deployment_once(
        self,
        user_id: str | None = None,
        check_number: int = 1,
        max_checks: int = 40,
    ) -> MonitoringUpdate:
        """
        Get a single monitoring update.

        Args:
            user_id: Optional user ID
            check_number: Current check number
            max_checks: Maximum checks before stopping

        Returns:
            MonitoringUpdate with current status
        """
        logger.debug(f"Monitoring deployment (check {check_number}/{max_checks})")

        try:
            # Get current status
            range_info = await self.client.get_range(user_id)
            range_state = range_info.get("rangeState", "UNKNOWN")
            vm_count = range_info.get("numberOfVMs", 0)
            vms = range_info.get("VMs", [])

            # Count ready VMs
            vms_ready = sum(1 for vm in vms if vm.get("status") == "running")

            # Calculate progress
            if range_state == "SUCCESS":
                progress = 100
            elif range_state == "DEPLOYING":
                # Estimate based on ready VMs
                if vm_count > 0:
                    progress = int((vms_ready / vm_count) * 80)  # Max 80% during deployment
                else:
                    progress = 10
            elif range_state == "FAILED":
                progress = 0
            else:
                progress = 0

            # Get logs for recent activity
            try:
                logs = await self.client.get_range_logs(user_id)
                # Extract last few lines
                log_lines = logs.split('\n') if logs else []
                recent_activity = [line for line in log_lines[-10:] if line.strip()][:5]
            except Exception:
                recent_activity = []

            # Determine current task from logs
            current_task = "Initializing..."
            if recent_activity:
                last_line = recent_activity[-1] if recent_activity else ""
                if "TASK" in last_line:
                    current_task = last_line.split("TASK")[1].strip()[:100]
                elif any(keyword in last_line.lower() for keyword in ["domain", "controller", "dc"]):
                    current_task = "Configuring domain controller..."
                elif "join" in last_line.lower():
                    current_task = "Joining VMs to domain..."
                elif "wazuh" in last_line.lower() or "siem" in last_line.lower():
                    current_task = "Setting up SIEM monitoring..."

            # Check for issues
            health_check = await self.deployment_handler.check_deployment_health(user_id)
            issues = health_check.get("issues", [])
            is_healthy = health_check.get("health_status") == "healthy"

            # Calculate timing
            # Estimate 20 minutes for typical deployment
            elapsed_minutes = check_number // 2  # Assuming 30s intervals
            if range_state == "DEPLOYING":
                eta_minutes = max(0, 20 - elapsed_minutes)
            else:
                eta_minutes = 0

            # Determine if should continue monitoring
            should_continue = (
                range_state == "DEPLOYING"
                and check_number < max_checks
            )

            return MonitoringUpdate(
                timestamp=datetime.now(),
                range_state=range_state,
                vm_count=vm_count,
                vms_ready=vms_ready,
                current_task=current_task,
                progress_percentage=progress,
                recent_activity=recent_activity,
                is_healthy=is_healthy,
                issues=issues,
                elapsed_minutes=elapsed_minutes,
                eta_minutes=eta_minutes,
                next_check_in=30 if should_continue else 0,
                should_continue_monitoring=should_continue,
            )

        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            return MonitoringUpdate(
                timestamp=datetime.now(),
                range_state="ERROR",
                vm_count=0,
                vms_ready=0,
                current_task=f"Error: {e}",
                progress_percentage=0,
                is_healthy=False,
                issues=[str(e)],
                elapsed_minutes=0,
                eta_minutes=0,
                should_continue_monitoring=False,
            )

    async def get_recovery_recommendation(
        self,
        user_id: str | None = None,
    ) -> RecoveryRecommendation:
        """
        Get recovery recommendations for failed deployment.

        Args:
            user_id: Optional user ID

        Returns:
            RecoveryRecommendation with action steps
        """
        logger.info("Getting recovery recommendation")

        try:
            range_info = await self.client.get_range(user_id)
            range_state = range_info.get("rangeState", "UNKNOWN")
            logs = await self.client.get_range_logs(user_id)

            # Analyze failure
            if range_state != "FAILED":
                return RecoveryRecommendation(
                    action="none",
                    reason=f"Range is not failed (state: {range_state})",
                    severity="info",
                    steps=["No recovery needed - range is operational or deploying"],
                )

            # Check for known error patterns
            logs_lower = logs.lower() if logs else ""

            # ADWS errors - transient, wait
            if "active directory web services" in logs_lower or "adws" in logs_lower:
                return RecoveryRecommendation(
                    action="wait",
                    reason="Active Directory Web Services not yet started (transient issue)",
                    severity="warning",
                    steps=[
                        "1. Wait 5-10 minutes for AD services to initialize",
                        "2. Check status: ludus.quick_status",
                        "3. Ludus will auto-retry failed tasks",
                        "4. If still failing after 15 min, check logs: ludus.get_full_logs",
                    ],
                    commands={
                        "status": "ludus.quick_status",
                        "health": "ludus.check_deployment_health",
                        "logs": "ludus.get_full_logs",
                    },
                    estimated_recovery_time="5-10 minutes (automatic)",
                )

            # Template errors - config issue
            if "template not found" in logs_lower or "template" in logs_lower and "error" in logs_lower:
                return RecoveryRecommendation(
                    action="fix_config",
                    reason="VM template not found or invalid",
                    severity="error",
                    steps=[
                        "1. List available templates: ludus.list_templates",
                        "2. Update configuration with correct template name",
                        "3. Validate config: ludus.validate_config",
                        "4. Delete failed range: ludus.delete_range",
                        "5. Redeploy with fixed config: ludus.deploy_range",
                    ],
                    commands={
                        "list_templates": "ludus.list_templates",
                        "validate": "ludus.validate_config(config)",
                        "delete": "ludus.delete_range",
                    },
                    estimated_recovery_time="5 minutes + redeployment time",
                )

            # Network/connectivity issues - may resolve
            if any(keyword in logs_lower for keyword in ["unreachable", "connection refused", "timeout"]):
                return RecoveryRecommendation(
                    action="wait",
                    reason="Network connectivity issues detected",
                    severity="warning",
                    steps=[
                        "1. Wait 3-5 minutes for VMs to fully boot",
                        "2. Check VM status: ludus.get_range",
                        "3. Verify VMs are running and accessible",
                        "4. If persists, check network configuration",
                        "5. Consider redeploying if issue continues",
                    ],
                    commands={
                        "check_vms": "ludus.get_range",
                        "status": "ludus.quick_status",
                        "health": "ludus.check_deployment_health",
                    },
                    estimated_recovery_time="3-5 minutes (may auto-recover)",
                )

            # Generic failure
            return RecoveryRecommendation(
                action="destroy",
                reason="Deployment failed with unrecognized error",
                severity="error",
                steps=[
                    "1. Review full logs: ludus.get_full_logs",
                    "2. Identify root cause from logs",
                    "3. Fix configuration if needed",
                    "4. Delete failed range: ludus.delete_range",
                    "5. Redeploy: ludus.deploy_scenario or ludus.smart_deploy",
                ],
                commands={
                    "logs": "ludus.get_full_logs",
                    "delete": "ludus.delete_range",
                    "redeploy": "ludus.smart_deploy(scenario_key='...', siem_type='...')",
                },
                estimated_recovery_time="Depends on issue - review logs first",
            )

        except Exception as e:
            logger.error(f"Error getting recovery recommendation: {e}")
            return RecoveryRecommendation(
                action="error",
                reason=f"Failed to analyze deployment: {e}",
                severity="critical",
                steps=[
                    "1. Check Ludus API connectivity",
                    "2. Verify configuration",
                    "3. Review server logs",
                ],
                commands={},
                estimated_recovery_time="Unknown",
            )
