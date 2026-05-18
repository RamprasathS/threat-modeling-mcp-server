"""Integration test that simulates real MCP tool calls end-to-end.

This script tests both single-item (backwards compat) and batch modes
by calling the _impl functions through the batch_utils layer, exactly
as the registered tools do internally.
"""

import asyncio
import sys
from unittest.mock import AsyncMock

from threat_modeling_mcp_server.tools.architecture_analyzer import (
    add_component_impl, update_component_impl, delete_component_impl,
    list_components_impl, components, connections, data_stores, architecture,
    add_connection_impl, add_data_store_impl
)
from threat_modeling_mcp_server.tools.assumption_manager import (
    add_assumption_impl, update_assumption_impl, delete_assumption_impl,
    assumptions
)
from threat_modeling_mcp_server.tools.threat_actor_analyzer import (
    add_threat_actor_impl, delete_threat_actor_impl,
    threat_actors, initialize_threat_actors
)
from threat_modeling_mcp_server.tools.threat_generator import (
    add_threat_impl, update_threat_impl, delete_threat_impl,
    add_mitigation_impl, delete_mitigation_impl,
    threats, mitigations
)
from threat_modeling_mcp_server.tools.asset_flow_analyzer import (
    add_asset_impl, delete_asset_impl, assets, flows
)
from threat_modeling_mcp_server.tools.trust_boundary_analyzer import (
    add_trust_zone_impl, delete_trust_zone_impl,
    initialize_trust_boundaries
)
import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
from threat_modeling_mcp_server.utils.batch_utils import batch_add, batch_update, batch_delete


async def run_integration_tests():
    ctx = AsyncMock()
    passed = 0
    failed = 0
    
    def check(test_name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            print(f"  ✅ {test_name}")
            passed += 1
        else:
            print(f"  ❌ {test_name} — {detail}")
            failed += 1

    # Clear state
    components.clear()
    architecture.components = []
    architecture.connections = []
    architecture.data_stores = []
    assumptions.clear()
    threats.clear()
    mitigations.clear()
    assets.clear()
    flows.clear()

    # ============================================================
    print("\n🔧 ARCHITECTURE: Components")
    print("=" * 50)
    
    # Single item mode (backwards compat)
    result = await batch_add(
        ctx, None,
        {"name": "API Gateway", "type": "Network"},
        add_component_impl, "component"
    )
    check("Single add_component", "Component added with ID:" in result, result)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"name": "Lambda Function", "type": "Compute", "service_provider": "AWS", "specific_service": "Lambda"},
            {"name": "DynamoDB Table", "type": "Storage", "service_provider": "AWS", "specific_service": "DynamoDB"},
            {"name": "S3 Bucket", "type": "Storage", "service_provider": "AWS", "specific_service": "S3"},
        ],
        {},
        add_component_impl, "component"
    )
    check("Batch add_component (3 items)", "Successfully added 3 component(s)" in result, result)
    
    # List to verify
    result = await list_components_impl(ctx)
    check("list_components shows all 4", "API Gateway" in result and "Lambda Function" in result and "S3 Bucket" in result, result[:200])
    
    # Batch update
    result = await batch_update(
        ctx,
        [
            {"id": "C001", "description": "Main entry point"},
            {"id": "C002", "description": "Auth handler"},
        ],
        {},
        update_component_impl, "component"
    )
    check("Batch update_component (2 items)", "Successfully updated 2 component(s)" in result, result)
    
    # Single update (backwards compat)
    result = await batch_update(
        ctx, None,
        {"id": "C003", "description": "Primary data store"},
        update_component_impl, "component"
    )
    check("Single update_component", "updated successfully" in result, result)
    
    # Batch delete
    result = await batch_delete(ctx, ["C003", "C004"], None, delete_component_impl, "component")
    check("Batch delete_component (2 items)", "Successfully deleted 2 component(s)" in result, result)
    
    # Single delete (backwards compat)
    result = await batch_delete(ctx, None, "C002", delete_component_impl, "component")
    check("Single delete_component", "deleted successfully" in result, result)

    # ============================================================
    print("\n🔧 ASSUMPTIONS")
    print("=" * 50)
    
    # Single mode
    result = await batch_add(
        ctx, None,
        {"description": "Network is internal", "category": "Network", "impact": "Low risk", "rationale": "VPC only"},
        add_assumption_impl, "assumption"
    )
    check("Single add_assumption", "Assumption added with ID:" in result, result)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"description": "All data encrypted at rest", "category": "Data", "impact": "Reduces breach impact", "rationale": "AWS KMS"},
            {"description": "MFA enforced", "category": "Authentication", "impact": "Prevents credential theft", "rationale": "Company policy"},
        ],
        {},
        add_assumption_impl, "assumption"
    )
    check("Batch add_assumption (2 items)", "Successfully added 2 assumption(s)" in result, result)

    # ============================================================
    print("\n🔧 THREATS")
    print("=" * 50)
    
    # Single mode
    result = await batch_add(
        ctx, None,
        {"threat_source": "external attacker", "prerequisites": "network access", "threat_action": "SQL injection", "threat_impact": "data breach"},
        add_threat_impl, "threat"
    )
    check("Single add_threat", "Threat added with ID:" in result, result)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"threat_source": "insider", "prerequisites": "valid credentials", "threat_action": "data exfiltration", "threat_impact": "IP theft", "severity": "High"},
            {"threat_source": "script kiddie", "prerequisites": "public endpoint", "threat_action": "DDoS attack", "threat_impact": "service unavailability", "severity": "Medium"},
            {"threat_source": "nation state", "prerequisites": "supply chain access", "threat_action": "backdoor installation", "threat_impact": "persistent access", "severity": "Critical"},
        ],
        {},
        add_threat_impl, "threat"
    )
    check("Batch add_threat (3 items)", "Successfully added 3 threat(s)" in result, result)

    # ============================================================
    print("\n🔧 MITIGATIONS")
    print("=" * 50)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"content": "Implement WAF rules for SQL injection"},
            {"content": "Enable DDoS protection via AWS Shield"},
            {"content": "Implement supply chain security scanning"},
        ],
        {},
        add_mitigation_impl, "mitigation"
    )
    check("Batch add_mitigation (3 items)", "Successfully added 3 mitigation(s)" in result, result)

    # ============================================================
    print("\n🔧 ASSETS")
    print("=" * 50)
    
    # Single mode
    result = await batch_add(
        ctx, None,
        {"name": "Customer PII", "type": "Data", "classification": "Confidential"},
        add_asset_impl, "asset"
    )
    check("Single add_asset", "Asset added with ID:" in result, result)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"name": "API Keys", "type": "Credential", "classification": "Restricted", "sensitivity": 5},
            {"name": "Audit Logs", "type": "Data", "classification": "Internal", "criticality": 4},
        ],
        {},
        add_asset_impl, "asset"
    )
    check("Batch add_asset (2 items)", "Successfully added 2 asset(s)" in result, result)

    # ============================================================
    print("\n🔧 TRUST ZONES")
    print("=" * 50)
    
    tba.initialize_trust_boundaries()
    initial_tz_count = len(tba.trust_zones)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"name": "Public Internet", "trust_level": "Untrusted"},
            {"name": "DMZ", "trust_level": "Low"},
            {"name": "Internal Network", "trust_level": "High"},
        ],
        {},
        add_trust_zone_impl, "trust zone"
    )
    check("Batch add_trust_zone (3 items)", "Successfully added 3 trust zone(s)" in result, result)
    check("Trust zones count increased by 3", len(tba.trust_zones) == initial_tz_count + 3, f"expected {initial_tz_count + 3}, got {len(tba.trust_zones)}")

    # ============================================================
    print("\n🔧 THREAT ACTORS")
    print("=" * 50)
    
    initialize_threat_actors()
    initial_ta_count = len(threat_actors)
    
    # Batch mode
    result = await batch_add(
        ctx,
        [
            {"name": "Hacktivist Group", "type": "Hacktivist", "capability_level": "Medium", "motivations": ["Political"], "resources": "Moderate"},
            {"name": "Competitor", "type": "Competitor", "capability_level": "High", "motivations": ["Financial", "Espionage"], "resources": "Extensive"},
        ],
        {},
        add_threat_actor_impl, "threat actor"
    )
    check("Batch add_threat_actor (2 items)", "Successfully added 2 threat actor(s)" in result, result)

    # ============================================================
    print("\n🔧 ERROR HANDLING")
    print("=" * 50)
    
    # Batch with one invalid item
    result = await batch_add(
        ctx,
        [
            {"name": "Good Component", "type": "Compute"},
            {"name": "Bad Component", "type": "TotallyInvalidType"},
        ],
        {},
        add_component_impl, "component"
    )
    check("Batch with invalid item (partial success)", "Successfully added 1" in result and "Failed to add 1" in result, result)
    
    # Empty batch
    result = await batch_add(ctx, [], {}, add_component_impl, "component")
    check("Empty batch returns message", "No components provided" in result, result)
    
    # Batch delete with nonexistent IDs
    result = await batch_delete(ctx, ["NONEXISTENT1", "NONEXISTENT2"], None, delete_component_impl, "component")
    check("Batch delete nonexistent (graceful)", "not found" in result.lower(), result)

    # ============================================================
    print("\n" + "=" * 50)
    print(f"📊 RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 50)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_integration_tests())
    sys.exit(0 if success else 1)
