"""Handler for deployment status, logs, and recovery operations."""

from datetime import datetime, timedelta
from typing import Any

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.schemas.orchestration import DeploymentTimeline, DeploymentStep
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.visualization import format_deployment_status

logger = get_logger(__name__)


class DeploymentHandler:
    """Handler for deployment monitoring and recovery."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the deployment handler."""
        self.client = client

    async def quick_status(self, user_id: str | None = None) -> str:
        """
        Get one-line deployment status with emoji indicators.

        Args:
            user_id: Optional user ID

        Returns:
            Formatted status string
        """
        try:
            range_info = await self.client.get_range(user_id)
            state = range_info.get("rangeState", "UNKNOWN")
            vm_count = range_info.get("numberOfVMs", 0)

            # Status indicator
            status_indicator = {
                "SUCCESS": "[OK]",
                "DEPLOYING": "[...]",
                "FAILED": "[ERROR]",
                "DELETED": "[DELETED]",
                "UNKNOWN": "[?]"
            }

            indicator = status_indicator.get(state, "[?]")

            # Build status line
            status_line = f"{indicator} Range Status: {state}"

            if vm_count > 0:
                status_line += f" | VMs: {vm_count}"

                # If deploying, try to estimate progress
                if state == "DEPLOYING":
                    # Count ready VMs
                    vms = range_info.get("VMs", [])
                    ready_count = sum(1 for vm in vms if vm.get("status") == "running")
                    if ready_count > 0:
                        status_line += f" ({ready_count}/{vm_count} ready)"

            # Add deployment time if available
            last_deployment = range_info.get("lastDeployment")
            if last_deployment:
                status_line += f" | Deployed: {last_deployment}"

            logger.debug(f"Quick status: {status_line}")
            return status_line

        except Exception as e:
            logger.error(f"Error getting quick status: {e}")
            return f"[ERROR] Error getting status: {str(e)}"

    async def get_deployment_status(self, user_id: str | None = None) -> dict[str, Any]:
        """Get current deployment status with detailed information."""
        try:
            range_info = await self.client.get_range(user_id)
            range_config = await self.client.get_range_config(user_id)
            logs = await self.client.get_range_logs(user_id)
            
            return {
                "status": "success",
                "range": range_info,
                "config": range_config,
                "range_state": range_info.get("rangeState", "UNKNOWN"),
                "number_of_vms": range_info.get("numberOfVMs", 0),
                "vms": range_info.get("VMs", []),
                "last_deployment": range_info.get("lastDeployment"),
                "testing_enabled": range_info.get("testingEnabled", False),
                "logs_preview": logs[:2000] if logs else "No logs available",  # First 2000 chars
                "has_logs": bool(logs),
            }
        except Exception as e:
            logger.error(f"Error getting deployment status: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def get_full_logs(self, user_id: str | None = None) -> dict[str, Any]:
        """Get full deployment logs."""
        try:
            logs = await self.client.get_range_logs(user_id)
            range_info = await self.client.get_range(user_id)
            
            return {
                "status": "success",
                "range_state": range_info.get("rangeState", "UNKNOWN"),
                "logs": logs,
                "log_length": len(logs) if logs else 0,
            }
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def check_deployment_health(self, user_id: str | None = None) -> dict[str, Any]:
        """Check deployment health and identify issues."""
        try:
            range_info = await self.client.get_range(user_id)
            logs = await self.client.get_range_logs(user_id)
            
            range_state = range_info.get("rangeState", "UNKNOWN")
            issues = []
            warnings = []
            recommendations = []
            
            # Check range state
            if range_state == "FAILED":
                issues.append("Range deployment has failed")
                recommendations.append("Check logs for specific errors")
                recommendations.append("Consider aborting and redeploying")
            elif range_state == "DEPLOYING":
                # Check for common issues in logs
                if logs:
                    log_lower = logs.lower()
                    
                    # Check for AD Web Services issues
                    if "active directory web services" in log_lower or "adws" in log_lower or "unable to find a default server with active directory web services" in log_lower:
                        issues.append("Active Directory Web Services (ADWS) not running")
                        recommendations.append("This is normal during initial DC setup - ADWS starts after domain promotion")
                        recommendations.append("Wait 5-10 minutes for AD services to fully initialize")
                        recommendations.append("Ludus will automatically retry - no action needed")
                        recommendations.append("Check if DC VM is fully booted: ludus.get_range()")
                        warnings.append("ADWS startup can take several minutes - deployment may still succeed")
                    
                    # Check for Ansible failures
                    if "failed:" in log_lower:
                        # Check if it's a recoverable failure (like ADWS)
                        if "active directory web services" not in log_lower:
                            issues.append("Ansible playbook failures detected")
                            recommendations.append("Review Ansible errors in logs")
                            recommendations.append("Check VM connectivity and services")
                            if "unreachable" in log_lower:
                                recommendations.append("VMs may not be fully booted - wait and retry")
                                recommendations.append("Check VM power state: ludus.get_range()")
                    
                    # Check for timeout issues
                    if "timeout" in log_lower or "timed out" in log_lower:
                        warnings.append("Timeouts detected in deployment")
                        recommendations.append("Deployment may be slow but still progressing")
                    
                    # Check for network issues
                    if "connection refused" in log_lower or "no route to host" in log_lower:
                        issues.append("Network connectivity issues detected")
                        recommendations.append("Check network configuration and VM networking")
            
            health_status = "healthy"
            if issues:
                health_status = "unhealthy"
            elif warnings:
                health_status = "degraded"
            
            return {
                "status": "success",
                "health_status": health_status,
                "range_state": range_state,
                "issues": issues,
                "warnings": warnings,
                "recommendations": recommendations,
                "number_of_vms": range_info.get("numberOfVMs", 0),
                "expected_vms": len(range_info.get("VMs", [])),
            }
        except Exception as e:
            logger.error(f"Error checking deployment health: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def resume_deployment(self, user_id: str | None = None) -> dict[str, Any]:
        """Attempt to resume a failed or stuck deployment.
        
        Note: Ludus handles deployment resumption automatically. This function
        checks if deployment can be resumed and provides guidance.
        """
        try:
            range_info = await self.client.get_range(user_id)
            range_state = range_info.get("rangeState", "UNKNOWN")
            
            if range_state == "SUCCESS":
                return {
                    "status": "info",
                    "message": "Range deployment is already successful",
                    "range_state": range_state,
                }
            
            if range_state == "DEPLOYING":
                return {
                    "status": "info",
                    "message": "Deployment is already in progress. Ludus will automatically retry failed tasks.",
                    "range_state": range_state,
                    "note": "Ludus automatically resumes deployment. No action needed.",
                }
            
            if range_state == "FAILED":
                # Get current config and logs to analyze
                try:
                    config = await self.client.get_range_config(user_id)
                    logs = await self.client.get_range_logs(user_id)
                    
                    # Check if failure is recoverable
                    recoverable = False
                    recovery_note = ""
                    
                    if logs:
                        log_lower = logs.lower()
                        # ADWS failures are often recoverable - just need to wait
                        if "active directory web services" in log_lower:
                            recoverable = True
                            recovery_note = "AD Web Services issue - can be resolved by waiting or retrying"
                    
                    options = [
                        "1. Review logs: ludus.get_full_logs",
                        "2. Check deployment health: ludus.check_deployment_health",
                    ]
                    
                    if recoverable:
                        options.append("3. Wait for services to start, then retry deployment")
                        options.append("4. Or redeploy with current config: ludus.deploy_range")
                    else:
                        options.append("3. Fix configuration if needed")
                        options.append("4. Redeploy with updated config: ludus.deploy_range")
                    
                    options.append("5. Or delete and recreate the range: ludus.delete_range")
                    
                    return {
                        "status": "action_required",
                        "message": "Deployment has failed. Options:",
                        "range_state": range_state,
                        "recoverable": recoverable,
                        "recovery_note": recovery_note,
                        "options": options,
                        "current_config_available": bool(config),
                        "note": "Ludus will decide if range should be destroyed. Check should_destroy_range for recommendations.",
                    }
                except Exception as e:
                    return {
                        "status": "error",
                        "message": "Failed to get range config for recovery",
                        "error": str(e),
                    }
            
            return {
                "status": "unknown",
                "message": f"Unknown range state: {range_state}",
                "range_state": range_state,
            }
        except Exception as e:
            logger.error(f"Error resuming deployment: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def should_destroy_range(self, user_id: str | None = None) -> dict[str, Any]:
        """Analyze if range should be destroyed based on deployment state.
        
        This provides recommendations - Ludus will handle actual destruction decisions.
        """
        try:
            range_info = await self.client.get_range(user_id)
            logs = await self.client.get_range_logs(user_id)
            
            range_state = range_info.get("rangeState", "UNKNOWN")
            recommendations = []
            should_destroy = False
            reason = ""
            
            if range_state == "FAILED":
                # Check if failure is recoverable
                if logs:
                    log_lower = logs.lower()
                    
                    # Check for critical failures
                    if "fatal" in log_lower or "critical error" in log_lower:
                        should_destroy = True
                        reason = "Critical fatal errors detected in deployment"
                        recommendations.append("Destroy and redeploy with corrected configuration")
                    elif "unrecoverable" in log_lower:
                        should_destroy = True
                        reason = "Unrecoverable errors detected"
                        recommendations.append("Destroy and start fresh")
                    else:
                        # Check if it's a transient issue
                        if "timeout" in log_lower or "connection" in log_lower:
                            should_destroy = False
                            reason = "Transient errors detected - may be recoverable"
                            recommendations.append("Wait and monitor - Ludus may auto-retry")
                            recommendations.append("Check if VMs are accessible")
                        else:
                            should_destroy = True
                            reason = "Deployment failed with errors"
                            recommendations.append("Review logs to identify root cause")
                            recommendations.append("Fix configuration and redeploy")
                else:
                    should_destroy = True
                    reason = "Deployment failed - no logs available for analysis"
                    recommendations.append("Destroy and redeploy")
            
            elif range_state == "DEPLOYING":
                should_destroy = False
                reason = "Deployment in progress - do not destroy"
                recommendations.append("Monitor deployment status")
                recommendations.append("Check logs for progress")
            
            elif range_state == "SUCCESS":
                should_destroy = False
                reason = "Deployment successful - range is operational"
            
            else:
                should_destroy = False
                reason = f"Unknown state: {range_state}"
                recommendations.append("Check range status manually")
            
            return {
                "status": "success",
                "should_destroy": should_destroy,
                "reason": reason,
                "range_state": range_state,
                "recommendations": recommendations,
                "note": "Ludus will make the final decision on range lifecycle. This is advisory only.",
            }
        except Exception as e:
            logger.error(f"Error analyzing range destruction: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    async def get_deployment_timeline(self, user_id: str | None = None) -> DeploymentTimeline:
        """
        Get deployment timeline with progress tracking.

        Args:
            user_id: Optional user ID

        Returns:
            DeploymentTimeline with progress information
        """
        logger.debug("Getting deployment timeline")

        try:
            range_info = await self.client.get_range(user_id)
            range_state = range_info.get("rangeState", "UNKNOWN")
            vms = range_info.get("VMs", [])
            vm_count = len(vms)

            # Get logs to parse timeline
            logs = await self.client.get_range_logs(user_id)

            # Build timeline steps from logs and current state
            steps = []
            started_at = datetime.now() - timedelta(minutes=10)  # Estimate

            # Parse logs for timeline events
            if logs:
                # Step 1: VMs created
                if "creating" in logs.lower() or vm_count > 0:
                    steps.append(DeploymentStep(
                        name="VMs Created",
                        status="completed",
                        started_at=started_at,
                        completed_at=started_at + timedelta(minutes=2),
                        message=f"{vm_count} VMs created"
                    ))

                # Step 2: Networks configured
                if "network" in logs.lower():
                    steps.append(DeploymentStep(
                        name="Networks Configured",
                        status="completed" if range_state != "DEPLOYING" else "completed",
                        started_at=started_at + timedelta(minutes=2),
                        completed_at=started_at + timedelta(minutes=4),
                        message="Network topology configured"
                    ))

                # Step 3: VM provisioning
                vms_ready = sum(1 for vm in vms if vm.get("status") == "running")
                if vms_ready > 0:
                    status = "completed" if vms_ready == vm_count else "in_progress"
                    steps.append(DeploymentStep(
                        name="VM Provisioning",
                        status=status,
                        started_at=started_at + timedelta(minutes=4),
                        completed_at=started_at + timedelta(minutes=10) if status == "completed" else None,
                        message=f"{vms_ready}/{vm_count} VMs provisioned"
                    ))

                # Step 4: Domain controller setup (if AD lab)
                if "domain" in logs.lower() or "dc" in logs.lower():
                    dc_complete = "successfully" in logs.lower() and "domain" in logs.lower()
                    steps.append(DeploymentStep(
                        name="Domain Controller Setup",
                        status="completed" if dc_complete else "in_progress",
                        started_at=started_at + timedelta(minutes=6),
                        completed_at=started_at + timedelta(minutes=12) if dc_complete else None,
                        message="Configuring Active Directory"
                    ))

                # Step 5: Domain join (if applicable)
                if "join" in logs.lower():
                    join_complete = range_state == "SUCCESS"
                    steps.append(DeploymentStep(
                        name="Domain Join",
                        status="completed" if join_complete else "in_progress",
                        started_at=started_at + timedelta(minutes=12),
                        completed_at=started_at + timedelta(minutes=15) if join_complete else None,
                        message="Joining VMs to domain"
                    ))

                # Step 6: SIEM setup (if applicable)
                if "wazuh" in logs.lower() or "siem" in logs.lower():
                    siem_complete = range_state == "SUCCESS"
                    steps.append(DeploymentStep(
                        name="SIEM Setup",
                        status="completed" if siem_complete else "in_progress",
                        started_at=started_at + timedelta(minutes=14),
                        completed_at=started_at + timedelta(minutes=18) if siem_complete else None,
                        message="Configuring SIEM monitoring"
                    ))

            # Calculate progress
            if range_state == "SUCCESS":
                progress = 100
                current_step = "Deployment Complete"
            elif range_state == "FAILED":
                progress = 0
                current_step = "Deployment Failed"
            elif steps:
                completed_steps = sum(1 for s in steps if s.status == "completed")
                progress = int((completed_steps / len(steps)) * 100) if steps else 0
                in_progress_steps = [s for s in steps if s.status == "in_progress"]
                current_step = in_progress_steps[0].name if in_progress_steps else "Initializing..."
            else:
                progress = 5
                current_step = "Initializing..."

            # Calculate timing
            elapsed_minutes = 10  # Estimate
            if range_state == "DEPLOYING":
                # Estimate 20 minutes total for typical deployment
                remaining_minutes = max(0, 20 - elapsed_minutes)
                estimated_completion = datetime.now() + timedelta(minutes=remaining_minutes)
            else:
                remaining_minutes = 0
                estimated_completion = None

            return DeploymentTimeline(
                started_at=started_at,
                steps=steps,
                current_step=current_step,
                progress_percentage=progress,
                estimated_completion=estimated_completion,
                elapsed_minutes=elapsed_minutes,
                remaining_minutes=remaining_minutes,
            )

        except Exception as e:
            logger.error(f"Error getting deployment timeline: {e}")
            # Return minimal timeline on error
            return DeploymentTimeline(
                started_at=datetime.now(),
                steps=[],
                current_step=f"Error: {e}",
                progress_percentage=0,
                estimated_completion=None,
                elapsed_minutes=0,
                remaining_minutes=0,
            )

