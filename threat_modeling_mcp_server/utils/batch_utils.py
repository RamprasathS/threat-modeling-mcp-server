"""Batch operation utilities for the Threat Modeling MCP Server.

This module provides helper functions for batch operations across all tools.
Batch operations allow multiple items to be added, updated, or deleted in a single
tool call while maintaining backwards compatibility with single-item operations.
"""

from typing import Any, Callable, Dict, List, Optional
from loguru import logger


async def batch_add(
    ctx: Any,
    items: Optional[List[Dict[str, Any]]],
    single_item_kwargs: Dict[str, Any],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single add operations.
    
    If `items` is provided, iterates over the list and calls impl_fn for each item.
    Otherwise, calls impl_fn with the single_item_kwargs (original single-item behavior).
    
    Args:
        ctx: MCP context
        items: Optional list of dicts, each containing the fields for one item
        single_item_kwargs: The individual field parameters (used when items is None)
        impl_fn: The implementation function to call for each item
        entity_name: Name of the entity type for logging (e.g., "component")
        
    Returns:
        A confirmation message (single result or batch summary)
    """
    if items is not None:
        if not items:
            return f"No {entity_name}s provided in batch."
        
        logger.debug(f'Batch adding {len(items)} {entity_name}(s)')
        results = []
        errors = []
        
        for i, item in enumerate(items):
            try:
                result = await impl_fn(ctx, **item)
                results.append(result)
            except Exception as e:
                errors.append(f"Item {i + 1}: {str(e)}")
        
        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully added {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to add {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")
        
        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        return await impl_fn(ctx, **single_item_kwargs)


async def batch_update(
    ctx: Any,
    items: Optional[List[Dict[str, Any]]],
    single_item_kwargs: Dict[str, Any],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single update operations.
    
    If `items` is provided, iterates over the list and calls impl_fn for each item.
    Each item in the list must contain an 'id' field.
    Otherwise, calls impl_fn with the single_item_kwargs (original single-item behavior).
    
    Args:
        ctx: MCP context
        items: Optional list of dicts, each containing 'id' and fields to update
        single_item_kwargs: The individual field parameters (used when items is None)
        impl_fn: The implementation function to call for each item
        entity_name: Name of the entity type for logging
        
    Returns:
        A confirmation message (single result or batch summary)
    """
    if items is not None:
        if not items:
            return f"No {entity_name}s provided in batch."
        
        logger.debug(f'Batch updating {len(items)} {entity_name}(s)')
        results = []
        errors = []
        
        for i, item in enumerate(items):
            try:
                result = await impl_fn(ctx, **item)
                results.append(result)
            except Exception as e:
                errors.append(f"Item {i + 1}: {str(e)}")
        
        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully updated {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to update {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")
        
        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        return await impl_fn(ctx, **single_item_kwargs)


async def batch_delete(
    ctx: Any,
    ids: Optional[List[str]],
    single_id: Optional[str],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single delete operations.
    
    If `ids` is provided, iterates over the list and calls impl_fn for each id.
    Otherwise, calls impl_fn with the single_id (original single-item behavior).
    
    Args:
        ctx: MCP context
        ids: Optional list of IDs to delete
        single_id: The single ID parameter (used when ids is None)
        impl_fn: The implementation function to call for each id
        entity_name: Name of the entity type for logging
        
    Returns:
        A confirmation message (single result or batch summary)
    """
    if ids is not None:
        if not ids:
            return f"No {entity_name} IDs provided in batch."
        
        logger.debug(f'Batch deleting {len(ids)} {entity_name}(s)')
        results = []
        errors = []
        
        for item_id in ids:
            try:
                result = await impl_fn(ctx, item_id)
                results.append(result)
            except Exception as e:
                errors.append(f"ID {item_id}: {str(e)}")
        
        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully deleted {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to delete {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")
        
        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        if single_id is None:
            return f"No {entity_name} ID provided."
        return await impl_fn(ctx, single_id)
