# Shodan integration patches

Each section below is a copy-pasteable change to an existing shared file.

---

## models/shared.py

Add `shodan_result` field to `PipelineState` after `ghunt_result`:

```python
# existing line:
    ghunt_result: ToolResult | None = None
# add after it:
    shodan_result: ToolResult | None = None
```

---

## agent/nodes.py

### 1. Add import at top (alongside the other model imports)

```python
from models.shodan import ShodanInput
```

### 2. Add `shodan_node` function (insert before `ai_audit_node`)

```python
def shodan_node(state: PipelineState) -> PipelineState:
    from tools import shodan as shodan_tool
    from models.shared import ToolResult
    from models.shodan import ShodanOutput
    from datetime import datetime, timezone

    if not state.spiderfoot_result or not state.spiderfoot_result.success:
        logger.info("shodan_node: no spiderfoot_result, skipping")
        return state

    elements = state.spiderfoot_result.data.get("elements", [])
    ips = [
        el["data"]
        for el in elements
        if el.get("type") == "IP_ADDRESS" and el.get("data")
    ][:5]  # cap at 5 IPs

    if not ips:
        logger.info("shodan_node: no IP_ADDRESS elements in spiderfoot_result, skipping")
        return state

    logger.info("shodan_node: scanning %d IPs: %s", len(ips), ips)

    all_hosts = []
    for ip in ips:
        inp = ShodanInput(ip=ip)
        result = shodan_tool.run(inp)
        if result.success:
            all_hosts.extend(result.data.get("hosts", []))
        else:
            logger.warning("shodan_node: failed for ip=%s — %s", ip, result.error)

    total_open_ports = sum(len(h.get("ports", [])) for h in all_hosts)
    total_vulns = sum(len(h.get("vulns", [])) for h in all_hosts)
    high_risk_ips = [h["ip"] for h in all_hosts if h.get("vulns")]

    output = ShodanOutput(
        ips_checked=len(ips),
        hosts=[],  # placeholder; hosts are dicts from model_dump()
        total_open_ports=total_open_ports,
        total_vulns=total_vulns,
        high_risk_ips=high_risk_ips,
    )
    aggregated_data = output.model_dump()
    aggregated_data["hosts"] = all_hosts  # re-inject raw dicts

    primary = state.classifications[0] if state.classifications else None
    aggregated = ToolResult(
        success=True,
        tool="shodan",
        input_type=primary.type if primary else "org",
        input_value=primary.value if primary else "",
        timestamp=datetime.now(timezone.utc),
        data=aggregated_data,
    )

    logger.info(
        "shodan_node: OK — ips_checked=%d open_ports=%d vulns=%d",
        len(ips), total_open_ports, total_vulns,
    )
    return state.model_copy(update={"shodan_result": aggregated})
```

---

## agent/graph.py

### 1. Add `shodan_node` to imports

```python
# existing import block — add shodan_node:
from agent.nodes import (
    intake_node,
    breach_check_node,
    broker_scan_node,
    surface_map_node,
    holehe_node,
    leakradar_node,
    blackbird_node,
    maigret_node,
    ghunt_node,
    shodan_node,       # ← add this line
    ai_audit_node,
    analysis_node,
    report_node,
)
```

### 2. Register the node and insert into the edge chain

```python
# After: builder.add_node("ghunt", ghunt_node)
builder.add_node("shodan", shodan_node)

# Replace:
#   builder.add_edge("broker_scan", "ai_audit")
# With:
builder.add_edge("broker_scan", "shodan")
builder.add_edge("shodan", "ai_audit")
```

Full updated edge sequence (broker_scan onward):
```
builder.add_edge("ghunt", "broker_scan")
builder.add_edge("broker_scan", "shodan")
builder.add_edge("shodan", "ai_audit")
builder.add_edge("ai_audit", "analysis")
```

---

## agent/report.py

In `_write_pdf`, inside the tool summary block after the `_tr("Broker scan", ...)` line, add:

```python
    _tr("Shodan", state.shodan_result, lambda d: f"{d.get('ips_checked',0)} IPs, {d.get('total_open_ports',0)} open ports, {d.get('total_vulns',0)} CVEs")
```

The surrounding context for placement:

```python
    _tr("Broker scan",state.broker_result,     lambda d: f"{d.get('brokers_found_count',0)} brokers, score {d.get('exposure_score',0)}/100")
    _tr("Shodan",     state.shodan_result,      lambda d: f"{d.get('ips_checked',0)} IPs, {d.get('total_open_ports',0)} open ports, {d.get('total_vulns',0)} CVEs")
    _tr("AI Audit",   state.ai_audit_result,   lambda d: f"{d.get('high_risk_count',0)} high-risk platforms")
```

---

## config.py

Add `SHODAN_API_KEY` to `OPTIONAL_VARS_WITH_DEFAULTS`:

```python
OPTIONAL_VARS_WITH_DEFAULTS = {
    "TEST_MODE": "false",
    "RESULTS_OUTPUT_PATH": "output/",
    "LEAKRADAR_API_KEY": "",
    "SHODAN_API_KEY": "",   # ← add this line
}
```

---

## pyproject.toml

Add `shodan>=1.31.0` to the `dependencies` list:

```toml
dependencies = [
    ...
    "shodan>=1.31.0",
]
```
