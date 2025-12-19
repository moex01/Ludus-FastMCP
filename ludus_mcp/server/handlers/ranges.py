"""Range operation handlers."""

from ludus_mcp.core.client import LudusAPIClient
from ludus_mcp.schemas.ranges import Range, RangeCreate
from ludus_mcp.utils.logging import get_logger
from ludus_mcp.utils.validation import validate_range_name

logger = get_logger(__name__)


class RangeHandler:
    """Handler for range operations."""

    def __init__(self, client: LudusAPIClient) -> None:
        """Initialize the range handler."""
        self.client = client

    async def create_range(self, data: RangeCreate) -> Range:
        """Create a new range."""
        name = validate_range_name(data.name)
        logger.debug(f"Creating range: {name}")

        result = await self.client.create_range(name, data.description)
        return Range(**result)

    async def get_range(self, range_id: str) -> Range:
        """Get a range by ID."""
        logger.debug(f"Getting range: {range_id}")
        result = await self.client.get_range(range_id)
        # Map API response fields to Range model
        mapped_range = {
            "id": result.get("userID") or result.get("id") or range_id,
            "name": result.get("rangeNumber") or result.get("name") or f"Range-{result.get('userID', range_id)}",
            "description": result.get("description"),
            "status": result.get("rangeState") or result.get("status"),
            "created_at": result.get("lastDeployment") or result.get("created_at"),
            "updated_at": result.get("lastDeployment") or result.get("updated_at"),
        }
        try:
            return Range(**mapped_range)
        except Exception as e:
            logger.warning(f"Failed to parse range data: {e}. Raw data: {result}")
            # Return a minimal valid Range if parsing fails
            return Range(
                id=str(result.get("userID", range_id)),
                name=result.get("rangeNumber") or f"Range-{result.get('userID', range_id)}",
                description=None,
                status=result.get("rangeState"),
                created_at=None,
                updated_at=None,
            )

    async def list_ranges(self) -> list[Range]:
        """List all ranges."""
        logger.debug("Listing all ranges")
        results = await self.client.list_ranges()
        ranges = []
        for r in results:
            # Map API response fields to Range model
            # API returns: userID, rangeState, rangeNumber, etc.
            # Range model expects: id, name, status, etc.
            mapped_range = {
                "id": r.get("userID") or r.get("id"),
                "name": r.get("rangeNumber") or r.get("name") or f"Range-{r.get('userID', 'unknown')}",
                "description": r.get("description"),
                "status": r.get("rangeState") or r.get("status"),
                "created_at": r.get("lastDeployment") or r.get("created_at"),
                "updated_at": r.get("lastDeployment") or r.get("updated_at"),
            }
            try:
                ranges.append(Range(**mapped_range))
            except Exception as e:
                logger.warning(f"Failed to parse range data: {e}. Raw data: {r}")
                # Return a minimal valid Range if parsing fails
                ranges.append(Range(
                    id=str(r.get("userID", "")),
                    name=r.get("rangeNumber") or f"Range-{r.get('userID', 'unknown')}",
                    description=None,
                    status=r.get("rangeState"),
                    created_at=None,
                    updated_at=None,
                ))
        return ranges

    async def delete_range(self, range_id: str) -> dict:
        """Delete a range."""
        logger.debug(f"Deleting range: {range_id}")
        return await self.client.delete_range(range_id)

