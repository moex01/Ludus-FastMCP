"""Shared utilities for FastMCP tool modules."""

from typing import Any, Callable, TypeVar
from ludus_mcp.core.client import LudusAPIClient

T = TypeVar("T")


class LazyHandlerRegistry:
    """Registry for lazy handler initialization."""

    def __init__(self, client: LudusAPIClient):
        """Initialize the registry with a client.

        Args:
            client: The Ludus API client to pass to handlers
        """
        self.client = client
        self._handlers: dict[str, Any] = {}

    def get_handler(self, name: str, handler_class: Callable[..., T]) -> T:
        """Get or create a handler instance.

        Args:
            name: Unique name for the handler
            handler_class: Handler class to instantiate

        Returns:
            Handler instance
        """
        if name not in self._handlers:
            self._handlers[name] = handler_class(self.client)
        return self._handlers[name]


def format_tool_response(data: Any) -> dict | list | str:
    """Format a tool response for MCP.

    Args:
        data: Data to format (Pydantic model, dict, list, or primitive)

    Returns:
        Formatted response suitable for MCP
    """
    # Handle Pydantic models
    if hasattr(data, "model_dump"):
        return data.model_dump()

    # Handle lists of Pydantic models
    if isinstance(data, list) and data and hasattr(data[0], "model_dump"):
        return [item.model_dump() for item in data]

    # Return as-is for dicts, lists, and primitives
    return data
