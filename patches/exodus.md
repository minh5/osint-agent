# Exodus Privacy — Integration Patches

These are copy-pasteable patches to wire `exodus` into the shared pipeline files.
Apply them after all parallel agents have finished writing their own patches.

---

## 1. models/shared.py

Add `exodus_result` to `PipelineState`. Insert after `ai_audit_result`:

```python
    ai_audit_result: ToolResult | None = None
    exodus_result: ToolResult | None = None   # ← add this line
    analysis_result: dict | None = None
```

---

## 2. agent/nodes.py — new exodus_node function

Add the following imports near the top with the other model imports:

```python
from models.exodus import ExodusInput
```

Add the following function after `blackbird_node` and before `maigret_node`:

```python
def exodus_node(state: PipelineState) -> PipelineState:
    from tools import exodus as exodus_tool

    platforms: list[str] = []

    if state.holehe_result and state.holehe_result.success:
        for match in state.holehe_result.data.get("platforms_found", []):
            name = match.get("platform", "")
            if name:
                platforms.append(name)

    if state.blackbird_result and state.blackbird_result.success:
        for account in state.blackbird_result.data.get("accounts_found", []):
            name = account.get("platform", "")
            if name and name not in platforms:
                platforms.append(name)

    if not platforms:
        logger.info("exodus_node: no platforms found in holehe/blackbird results, skipping")
        return state

    logger.info("exodus_node: checking %d platforms for tracker SDKs", len(platforms))
    inp = ExodusInput(platforms=platforms)
    result = exodus_tool.run(inp)
    if result.success:
        logger.info(
            "exodus_node: OK — apps_checked=%s high_risk_count=%s",
            result.data.get("apps_checked", 0),
            result.data.get("high_risk_count", 0),
        )
    else:
        logger.error("exodus_node: FAILED — %s", result.error)
    return state.model_copy(update={"exodus_result": result})
```

---

## 2b. agent/nodes.py — _build_analysis_digest Exodus section

In `_build_analysis_digest`, after the AI audit section block (ending with `lines.append("")`), add:

```python
    # ── Exodus tracker audit ──────────────────────────────────────────────────
    if state.exodus_result and state.exodus_result.success:
        d = state.exodus_result.data
        lines.append(f"EXODUS TRACKER AUDIT: {d.get('apps_checked', 0)} apps checked, "
                     f"{d.get('apps_with_trackers', 0)} with trackers, "
                     f"{d.get('high_risk_count', 0)} high-risk trackers")
        for app in (d.get("results") or []):
            if app.get("tracker_count", 0) > 0:
                high_risk = app.get("high_risk_trackers", [])
                all_trackers = [t.get("name") if isinstance(t, dict) else t
                                for t in app.get("trackers", [])]
                hr_str = f" [HIGH RISK: {', '.join(high_risk)}]" if high_risk else ""
                lines.append(f"  - {app['platform']} ({app['package']}): "
                             f"{', '.join(all_trackers)}{hr_str}")
        lines.append("")
```

---

## 3. agent/graph.py

Add `exodus_node` to the import list:

```python
from agent.nodes import (
    intake_node,
    breach_check_node,
    broker_scan_node,
    surface_map_node,
    holehe_node,
    leakradar_node,
    blackbird_node,
    exodus_node,       # ← add this line
    maigret_node,
    ghunt_node,
    ai_audit_node,
    analysis_node,
    report_node,
)
```

In `build_graph()`, add the node registration and update edges to insert exodus between blackbird and maigret:

```python
    builder.add_node("exodus", exodus_node)   # ← add after blackbird node registration
```

Change the edge:

```python
    # Before (remove this line):
    builder.add_edge("blackbird", "maigret")

    # After (replace with these two lines):
    builder.add_edge("blackbird", "exodus")
    builder.add_edge("exodus", "maigret")
```

---

## 4. agent/report.py — tool summary table

In `_write_pdf`, inside the `tool_rows` block after the `_tr("AI Audit", ...)` line, add:

```python
    _tr("Exodus", state.exodus_result, lambda d: f"{d.get('apps_checked',0)} apps, {d.get('high_risk_count',0)} high-risk trackers found")
```

In the Markdown section of `write_report`, after the AI Audit line add:

```python
    if state.exodus_result     and state.exodus_result.success:
        lines.append(f"- **Exodus:** {state.exodus_result.data.get('apps_checked',0)} apps checked, {state.exodus_result.data.get('high_risk_count',0)} high-risk trackers found")
```
