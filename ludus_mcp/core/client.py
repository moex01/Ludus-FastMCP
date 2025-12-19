"""Ludus REST API client wrapper using httpx."""

import httpx
import uuid
import time
import yaml
import io
from typing import Any
import logging

from ludus_mcp.utils.config import get_settings
from ludus_mcp.utils.retry import async_retry
from ludus_mcp.utils.rate_limit import get_rate_limiter
from ludus_mcp.exceptions import (
    LudusAPIError,
    LudusConnectionError,
    LudusAuthenticationError,
    LudusNotFoundError,
    LudusPermissionError,
    LudusServerError,
    LudusTimeoutError,
    LudusRateLimitError,
)

logger = logging.getLogger(__name__)


class LudusAPIClient:
    """Async HTTP client for Ludus API.

    This is the core Ludus API client with no MCP dependencies.
    It provides direct access to the Ludus REST API.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        """Initialize the Ludus client."""
        settings = get_settings()
        self.base_url = (base_url or settings.ludus_api_url).rstrip("/")
        self.api_key = api_key or settings.ludus_api_key

        # Initialize rate limiter
        self.rate_limiter = get_rate_limiter(max_requests=100, window_seconds=60)

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            verify=settings.ludus_ssl_verify,  # Configurable via LUDUS_SSL_VERIFY env var (default: False for lab environments)
            headers={
                "X-API-KEY": self.api_key,  # Ludus uses X-API-KEY header, not Authorization Bearer
            },
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20
            )
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()

    async def __aenter__(self) -> "LudusAPIClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    @async_retry(
        max_attempts=3,
        backoff_factor=2.0,
        exceptions=(httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Make an HTTP request to the Ludus API with retry logic and error handling."""
        # Generate request ID for tracing
        request_id = str(uuid.uuid4())[:8]

        # Apply rate limiting
        await self.rate_limiter.acquire()

        # Log request (debug level)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"[{request_id}] → {method} {endpoint}")
            if json_data:
                logger.debug(f"[{request_id}] Request body: {json_data}")

        start_time = time.time()

        try:
            # Ludus API uses X-API-KEY header (already set in client)
            # Just add Content-Type if needed
            headers = {}
            if json_data:
                headers["Content-Type"] = "application/json"

            response = await self.client.request(
                method=method,
                url=endpoint,
                json=json_data,
                params=params,
                headers=headers,
            )

            duration = time.time() - start_time

            # Log response (debug level)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"[{request_id}] ← {response.status_code} ({duration:.2f}s)"
                )
                if response.content:
                    content_preview = response.text[:500]
                    logger.debug(f"[{request_id}] Response: {content_preview}")

            response.raise_for_status()

            if response.content:
                return response.json()
            return {}

        except httpx.TimeoutException as e:
            logger.error(f"[{request_id}] [ERROR] Request timed out after {time.time() - start_time:.2f}s")
            raise LudusTimeoutError(
                f"Request to {endpoint} timed out after 30 seconds"
            ) from e

        except httpx.ConnectError as e:
            logger.error(f"[{request_id}] [ERROR] Connection failed: {e}")
            raise LudusConnectionError(
                f"Cannot connect to Ludus server at {self.base_url}. "
                f"Please check your LUDUS_API_URL and network connectivity."
            ) from e

        except httpx.NetworkError as e:
            logger.error(f"[{request_id}] [ERROR] Network error: {e}")
            raise LudusConnectionError(
                f"Network error connecting to {self.base_url}: {e}"
            ) from e

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            error_text = e.response.text[:200] if e.response.text else "No error details"

            logger.error(f"[{request_id}] [ERROR] HTTP {status}: {error_text}")

            if status == 401:
                raise LudusAuthenticationError(
                    "Authentication failed. Please check your LUDUS_API_KEY."
                ) from e
            elif status == 403:
                raise LudusPermissionError(
                    f"Permission denied for {endpoint}. "
                    "You may not have the required admin privileges."
                ) from e
            elif status == 404:
                raise LudusNotFoundError(
                    f"Resource not found: {endpoint}"
                ) from e
            elif status == 429:
                retry_after = e.response.headers.get("Retry-After")
                raise LudusRateLimitError(
                    retry_after=int(retry_after) if retry_after else None
                ) from e
            elif status >= 500:
                raise LudusServerError(
                    f"Ludus API server error ({status}). Please try again later."
                ) from e
            else:
                raise LudusAPIError(
                    status_code=status,
                    message=error_text,
                    details={"endpoint": endpoint, "method": method}
                ) from e

    # Range operations
    # Note: Ludus API uses /range/config for range configuration
    # Ranges are deployed via POST /range/deploy with a config
    async def get_range(self, user_id: str | None = None) -> dict[str, Any]:
        """Get the current user's range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/range", params=params)

    async def list_ranges(self) -> list[dict[str, Any]]:
        """List all ranges (admin only)."""
        result = await self._request("GET", "/range/all")
        return result if isinstance(result, list) else []

    async def delete_range(self, user_id: str | None = None, require_explicit_user: bool = True) -> dict[str, Any]:
        """Delete a range.
        
        **CRITICAL SAFETY**: This function will ONLY delete the range for the specified user_id.
        It will NEVER affect other users' ranges or system settings.
        
        Args:
            user_id: User ID whose range to delete. If None, defaults to current API key's user.
            require_explicit_user: If True (default), requires user_id to be explicitly provided.
                                  Set to False only if you're certain you want to delete the current user's range.
        
        Raises:
            ValueError: If require_explicit_user=True and user_id is None (safety check)
        """
        # CRITICAL SAFETY CHECK: Prevent accidental system-wide operations
        if require_explicit_user and user_id is None:
            raise ValueError(
                "SAFETY CHECK FAILED: delete_range() requires explicit user_id to prevent accidental deletions. "
                "If you want to delete the current user's range, pass user_id explicitly or set require_explicit_user=False. "
                "This safeguard prevents accidental deletion of other users' ranges or system settings."
            )
        
        # Get current user from API key to ensure we're only deleting our own range
        current_user_id = None
        try:
            current_user_info = await self.get_user()
            current_user_id = current_user_info.get("userID") or current_user_info.get("user_id")
            logger.info(f"[SAFETY] Current API key user: {current_user_id}")
        except Exception as e:
            logger.warning(f"[SAFETY] Could not verify current user (this is OK): {e}")
        
        # Use explicit user_id if provided, otherwise use current user
        target_user_id = user_id or current_user_id
        
        if not target_user_id:
            raise ValueError(
                "SAFETY CHECK FAILED: Cannot determine target user for range deletion. "
                "Please provide user_id explicitly."
            )
        
        # Log the deletion operation for audit trail
        logger.warning(
            f"[DESTRUCTIVE OPERATION] Deleting range for user: {target_user_id}. "
            f"This will permanently delete all VMs, snapshots, and data for this user's range only."
        )
        
        params = {}
        if target_user_id:
            params["userID"] = target_user_id
            logger.info(f"[SAFETY] Using explicit userID parameter: {target_user_id}")
        
        return await self._request("DELETE", "/range", params=params)

    async def get_range_config(self, user_id: str | None = None) -> dict[str, Any]:
        """Get range configuration.
        
        The Ludus API returns the configuration as a YAML string in the 'result' field.
        This method parses the YAML string into a dictionary.
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/range/config", params=params)
        
        # Ludus API returns YAML as a string in the 'result' field
        if isinstance(result, dict) and "result" in result:
            yaml_str = result["result"]
            if isinstance(yaml_str, str):
                return yaml.safe_load(yaml_str) or {}
        
        return result if isinstance(result, dict) else {}

    async def update_range_config(
        self, config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Update range configuration.
        
        The Ludus API requires the configuration to be sent as a YAML file via multipart/form-data.
        This method converts the config dict to YAML and sends it as a file upload.
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        
        # Remove 'name' field if present - Ludus API doesn't accept it in config
        config_copy = config.copy()
        if "name" in config_copy:
            del config_copy["name"]
        
        # Convert config to YAML string
        yaml_str = yaml.dump(config_copy, default_flow_style=False, sort_keys=False)
        
        # Create multipart form data with YAML file
        files = {
            "file": ("config.yml", io.BytesIO(yaml_str.encode("utf-8")), "application/x-yaml")
        }
        
        # Make request with multipart form data
        request_id = str(uuid.uuid4())[:8]
        await self.rate_limiter.acquire()
        
        try:
            response = await self.client.request(
                method="PUT",
                url="/range/config",
                params=params,
                files=files,
            )
            
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            error_text = e.response.text[:200] if e.response.text else "No error details"
            
            logger.error(f"[{request_id}] [ERROR] HTTP {status}: {error_text}")
            
            if status == 401:
                raise LudusAuthenticationError(
                    "Authentication failed. Please check your LUDUS_API_KEY."
                ) from e
            elif status >= 500:
                raise LudusServerError(
                    f"Ludus API server error ({status}). Please try again later."
                ) from e
            else:
                raise LudusAPIError(
                    status_code=status,
                    message=error_text,
                    details={"endpoint": "/range/config", "method": "PUT"}
                ) from e

    async def deploy_range(
        self,
        config: dict[str, Any] | None = None,
        user_id: str | None = None,
        tags: str | None = None,
        limit: str | None = None,
        only_roles: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Deploy a range from configuration.

        Args:
            config: Range configuration (optional if resuming with tags/limit)
            user_id: User ID for admin impersonation
            tags: Ansible tags to run (comma-separated, e.g., "user,domain")
            limit: Limit deployment to VMs matching pattern (e.g., "DC*")
            only_roles: Limit user-defined roles (comma-separated)
            force: Force deployment if testing is enabled

        Returns:
            Deployment result

        Examples:
            # Full deployment
            deploy_range(config=config_dict)

            # Resume with specific tags (e.g., after role installation)
            deploy_range(tags="user,domain")

            # Deploy only to specific VMs
            deploy_range(limit="DC*")

            # Combine filters
            deploy_range(tags="user", limit="WS*")
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        if tags:
            params["tags"] = tags
        if limit:
            params["limit"] = limit
        if only_roles:
            params["onlyRoles"] = only_roles
        if force:
            params["force"] = "true"

        return await self._request("POST", "/range/deploy", json_data=config, params=params)

    # Range Management - Additional endpoints
    async def abort_range_deployment(self, user_id: str | None = None, require_explicit_user: bool = True) -> dict[str, Any]:
        """Abort a range deployment.
        
        **CRITICAL SAFETY**: This function will ONLY abort the deployment for the specified user_id.
        It will NEVER affect other users' deployments or system settings.
        
        Args:
            user_id: User ID whose deployment to abort. If None, defaults to current API key's user.
            require_explicit_user: If True (default), requires user_id to be explicitly provided.
        
        Raises:
            ValueError: If require_explicit_user=True and user_id is None (safety check)
        """
        # CRITICAL SAFETY CHECK: Prevent accidental system-wide operations
        if require_explicit_user and user_id is None:
            # Get current user from API key
            try:
                current_user_info = await self.get_user()
                user_id = current_user_info.get("userID") or current_user_info.get("user_id")
                if user_id:
                    logger.info(f"[SAFETY] Using current API key user for abort: {user_id}")
                else:
                    raise ValueError(
                        "SAFETY CHECK FAILED: abort_range_deployment() requires explicit user_id. "
                        "Cannot determine current user from API key."
                    )
            except Exception as e:
                raise ValueError(
                    f"SAFETY CHECK FAILED: abort_range_deployment() requires explicit user_id. "
                    f"Could not determine current user: {e}"
                )
        
        params = {}
        if user_id:
            params["userID"] = user_id
            logger.info(f"[SAFETY] Aborting deployment for user: {user_id}")
        return await self._request("POST", "/range/abort", params=params)

    async def get_range_tags(self) -> list[str]:
        """Get range tags."""
        result = await self._request("GET", "/range/tags")
        return result if isinstance(result, list) else []

    async def get_range_config_example(self) -> dict[str, Any]:
        """Get example range configuration."""
        return await self._request("GET", "/range/config/example")

    async def get_range_logs(self, user_id: str | None = None) -> str:
        """Get range deployment logs."""
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/range/logs", params=params)
        return result.get("result", "") if isinstance(result, dict) else str(result)

    async def get_range_etchosts(self, user_id: str | None = None) -> str:
        """Get /etc/hosts file for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/range/etchosts", params=params)
        return result.get("result", "") if isinstance(result, dict) else str(result)

    async def get_range_sshconfig(self, user_id: str | None = None) -> str:
        """Get SSH config for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/range/sshconfig", params=params)
        return result.get("result", "") if isinstance(result, dict) else str(result)

    async def get_range_rdpconfigs(self, user_id: str | None = None) -> dict[str, Any]:
        """Get RDP configurations for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/range/rdpconfigs", params=params)

    async def get_range_ansible_inventory(self, user_id: str | None = None) -> str:
        """Get Ansible inventory for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/range/ansibleinventory", params=params)
        return result.get("result", "") if isinstance(result, dict) else str(result)

    async def get_range_access(self, user_id: str | None = None) -> dict[str, Any]:
        """Get range access configuration."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/range/access", params=params)

    async def update_range_access(
        self, access_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Update range access configuration."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/range/access", json_data=access_config, params=params)

    # Power State Management
    async def power_on_range(self, user_id: str | None = None) -> dict[str, Any]:
        """Power on all VMs in the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("PUT", "/range/poweron", params=params)

    async def power_off_range(self, user_id: str | None = None) -> dict[str, Any]:
        """Power off all VMs in the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("PUT", "/range/poweroff", params=params)

    # Testing State Management
    async def start_testing(self, user_id: str | None = None) -> dict[str, Any]:
        """Start testing state for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("PUT", "/testing/start", params=params)

    async def stop_testing(self, user_id: str | None = None) -> dict[str, Any]:
        """Stop testing state for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("PUT", "/testing/stop", params=params)

    async def allow_testing(
        self, allowed_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Allow testing from specific IPs/domains."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/testing/allow", json_data=allowed_config, params=params)

    async def deny_testing(
        self, denied_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Deny testing from specific IPs/domains."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/testing/deny", json_data=denied_config, params=params)

    async def update_testing(
        self, testing_config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Update testing configuration."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/testing/update", json_data=testing_config, params=params)

    # Host operations
    async def create_host(
        self,
        range_id: str,
        name: str,
        network_id: str | None = None,
        template: str | None = None,
        cpu: int | None = None,
        memory: int | None = None,
        disk: int | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Create a new host in a range."""
        payload: dict[str, Any] = {"name": name}
        if network_id:
            payload["network_id"] = network_id
        if template:
            payload["template"] = template
        if cpu:
            payload["cpu"] = cpu
        if memory:
            payload["memory"] = memory
        if disk:
            payload["disk"] = disk
        if description:
            payload["description"] = description

        return await self._request(
            "POST",
            f"/ranges/{range_id}/hosts",
            json_data=payload,
        )

    async def get_host(self, range_id: str, host_id: str) -> dict[str, Any]:
        """Get a host by ID."""
        return await self._request("GET", f"/ranges/{range_id}/hosts/{host_id}")

    async def list_hosts(self, range_id: str) -> list[dict[str, Any]]:
        """List all hosts in a range."""
        result = await self._request("GET", f"/ranges/{range_id}/hosts")
        return result if isinstance(result, list) else []

    async def start_host(self, range_id: str, host_id: str) -> dict[str, Any]:
        """Start a host."""
        return await self._request(
            "POST", f"/ranges/{range_id}/hosts/{host_id}/start"
        )

    async def stop_host(self, range_id: str, host_id: str) -> dict[str, Any]:
        """Stop a host."""
        return await self._request(
            "POST", f"/ranges/{range_id}/hosts/{host_id}/stop"
        )

    async def delete_host(self, range_id: str, host_id: str) -> dict[str, Any]:
        """Delete a host."""
        return await self._request(
            "DELETE", f"/ranges/{range_id}/hosts/{host_id}"
        )

    # Snapshot Management (Ludus API format)
    async def list_snapshots(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List all snapshots for the range."""
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/snapshots/list", params=params)
        return result if isinstance(result, list) else []

    async def create_snapshot(
        self,
        snapshot_config: dict[str, Any],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a snapshot."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/snapshots/create", json_data=snapshot_config, params=params)

    async def rollback_snapshot(
        self,
        snapshot_config: dict[str, Any],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Rollback to a snapshot."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/snapshots/rollback", json_data=snapshot_config, params=params)

    async def remove_snapshot(
        self,
        snapshot_config: dict[str, Any],
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Remove a snapshot."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/snapshots/remove", json_data=snapshot_config, params=params)

    # Template Management
    async def list_templates(self) -> list[dict[str, Any]]:
        """List available templates."""
        result = await self._request("GET", "/templates")
        return result if isinstance(result, list) else []

    async def create_template(
        self, template_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a new template."""
        return await self._request("POST", "/templates", json_data=template_config)

    async def update_template(
        self, template_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a template."""
        return await self._request("PUT", "/templates", json_data=template_config)

    async def delete_template(self, template_name: str, user_id: str | None = None) -> dict[str, Any]:
        """Delete a template."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("DELETE", f"/template/{template_name}", params=params)

    async def abort_template_operation(self, user_id: str | None = None) -> dict[str, Any]:
        """Abort template operation."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/templates/abort", params=params)

    async def get_template_logs(self, user_id: str | None = None, tail: int | None = None) -> str:
        """Get template operation logs."""
        params = {}
        if user_id:
            params["userID"] = user_id
        if tail is not None:
            params["tail"] = tail
        result = await self._request("GET", "/templates/logs", params=params)
        return result.get("result", "") if isinstance(result, dict) else str(result)

    async def get_template_status(self, user_id: str | None = None) -> dict[str, Any]:
        """Get template operation status."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/templates/status", params=params)

    async def add_template(
        self,
        template_data: dict[str, Any],
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Add a template to Ludus.

        Args:
            template_data: Template configuration including files/directory content
            user_id: Optional user ID (admin only)

        Returns:
            API response with template add status
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/templates/add", json_data=template_data, params=params)

    async def build_template(
        self,
        template_name: str | None = None,
        parallel: int = 1,
        user_id: str | None = None
    ) -> dict[str, Any]:
        """Build a template or all templates.

        Args:
            template_name: Name of template to build, or None for all templates
            parallel: Number of templates to build in parallel (default: 1)
            user_id: Optional user ID (admin only)

        Returns:
            API response with build status
        """
        payload = {
            "parallel": parallel
        }
        if template_name:
            payload["template_name"] = template_name

        params = {}
        if user_id:
            params["userID"] = user_id

        return await self._request("POST", "/templates/build", json_data=payload, params=params)

    # Host Management
    async def get_host_info(self) -> dict[str, Any]:
        """Get Ludus host information."""
        return await self._request("GET", "/")

    # Ansible Management
    async def list_ansible_resources(self) -> dict[str, Any]:
        """List Ansible roles and collections."""
        return await self._request("GET", "/ansible")

    async def install_ansible_role(
        self, role_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Install an Ansible role.
        
        Args:
            role_config: Role configuration dict with:
                - "action": "install"
                - "name": role name
                - "url": optional URL for Galaxy roles
                - "directory": optional path for local directory installation
        """
        return await self._request("POST", "/ansible/role", json_data=role_config)

    async def install_ansible_role_from_tar(
        self, role_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Install an Ansible role from tar file."""
        return await self._request("PUT", "/ansible/role/fromtar", json_data=role_config)

    async def install_ansible_collection(
        self, collection_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Install an Ansible collection."""
        return await self._request("POST", "/ansible/collection", json_data=collection_config)

    # Anti-Sandbox Management
    async def enable_antisandbox(
        self, config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Enable anti-sandbox plugin."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/antisandbox/enable", json_data=config, params=params)

    async def install_antisandbox_custom(
        self, config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Install custom anti-sandbox plugin."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/antisandbox/install-custom", json_data=config, params=params)

    async def install_antisandbox_standard(
        self, user_id: str | None = None
    ) -> dict[str, Any]:
        """Install standard anti-sandbox plugin."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/antisandbox/install-standard", params=params)

    # KMS Management
    async def install_kms(
        self, config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """Install Key Management Service."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/kms/install", json_data=config, params=params)

    async def license_kms(
        self, config: dict[str, Any], user_id: str | None = None
    ) -> dict[str, Any]:
        """License KMS server."""
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("POST", "/kms/license", json_data=config, params=params)

    # User Management (Admin only)
    async def list_users(self) -> list[dict[str, Any]]:
        """List all users (admin only)."""
        result = await self._request("GET", "/user/all")
        return result if isinstance(result, list) else []

    async def get_user(self, user_id: str | None = None) -> dict[str, Any]:
        """Get user information.
        
        Args:
            user_id: Optional user ID (defaults to caller's user if not specified)
                    Use query parameter userID, not path parameter
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/user", params=params)

    async def add_user(
        self,
        user_id: str,
        name: str,
        is_admin: bool = False,
        proxmox_username: str | None = None,
        proxmox_password: str | None = None,
    ) -> dict[str, Any]:
        """Add a new user (admin only).
        
        Args:
            user_id: User ID (1-20 character alphanumeric)
            name: User's full name
            is_admin: Whether user is an admin
            proxmox_username: Optional Proxmox username
            proxmox_password: Optional Proxmox password
        """
        payload: dict[str, Any] = {
            "userID": user_id,
            "name": name,
            "isAdmin": is_admin,
        }
        if proxmox_username:
            payload["proxmoxUsername"] = proxmox_username
        if proxmox_password:
            payload["proxmoxPassword"] = proxmox_password

        return await self._request("POST", "/user", json_data=payload)

    async def remove_user(self, user_id: str, require_confirmation: bool = True) -> dict[str, Any]:
        """Remove a user (admin only).
        
        **CRITICAL SAFETY**: This function permanently deletes a user and all their data.
        This operation CANNOT be undone.
        
        Args:
            user_id: User ID to remove
            require_confirmation: If True (default), raises ValueError if user_id is empty or looks like a wildcard.
        
        Raises:
            ValueError: If require_confirmation=True and user_id appears unsafe (empty, wildcard, etc.)
        """
        # CRITICAL SAFETY CHECK: Prevent accidental deletion of all users
        if require_confirmation:
            if not user_id or not user_id.strip():
                raise ValueError(
                    "SAFETY CHECK FAILED: remove_user() requires a non-empty user_id. "
                    "This prevents accidental deletion of all users."
                )
            if user_id in ["*", "all", "ALL", "%", "?"]:
                raise ValueError(
                    f"SAFETY CHECK FAILED: remove_user() does not accept wildcard user_id '{user_id}'. "
                    "This prevents accidental deletion of multiple users. "
                    "You must specify an exact user_id."
                )
        
        logger.critical(
            f"[DESTRUCTIVE OPERATION] Removing user: {user_id}. "
            f"This will permanently delete the user, their API keys, ranges, and all associated data. "
            f"This operation CANNOT be undone."
        )
        
        return await self._request("DELETE", f"/user/{user_id}")

    async def reset_user_proxmox_password(self, user_id: str) -> dict[str, Any]:
        """Reset a user's Proxmox password (admin only)."""
        payload = {"userID": user_id}
        return await self._request("POST", "/user/passwordreset", json_data=payload)

    async def get_user_proxmox_credentials(self, user_id: str | None = None) -> dict[str, Any]:
        """Get Proxmox credentials for a user.
        
        Args:
            user_id: Optional user ID (defaults to caller's user if not specified)
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/user/credentials", params=params)

    async def set_user_proxmox_credentials(
        self,
        proxmox_password: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Set the Proxmox password for a user.
        
        Args:
            proxmox_password: New Proxmox password
            user_id: Optional user ID (defaults to caller's user if not specified)
                    Admins can set other users' passwords
        """
        payload = {"proxmoxPassword": proxmox_password}
        if user_id:
            payload["userID"] = user_id
        return await self._request("POST", "/user/credentials", json_data=payload)

    async def get_user_apikey(self, user_id: str | None = None) -> dict[str, Any]:
        """Get or regenerate user API key (admin only).
        
        Args:
            user_id: Optional user ID (defaults to caller's user if not specified)
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        return await self._request("GET", "/user/apikey", params=params)

    async def get_user_wireguard(self, user_id: str | None = None) -> str:
        """Get user WireGuard configuration.
        
        Args:
            user_id: Optional user ID (defaults to caller's user if not specified)
        """
        params = {}
        if user_id:
            params["userID"] = user_id
        result = await self._request("GET", "/user/wireguard", params=params)
        return result.get("result", {}).get("wireGuardConfig", "") if isinstance(result, dict) else str(result)

    async def update_user_proxmox_creds(
        self,
        user_id: str,
        proxmox_username: str,
        proxmox_password: str,
    ) -> dict[str, Any]:
        """Update user's Proxmox credentials (admin only).
        
        Note: This is a convenience method that calls set_user_proxmox_credentials.
        The API only supports setting the password, not the username.
        """
        return await self.set_user_proxmox_credentials(proxmox_password, user_id)

