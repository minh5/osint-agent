# Bazzell Broker Cross-Reference Patches

Three files require changes. Apply each patch in order.

---

## 1. models/broker_scan.py

Add three fields to `BrokerScanOutput`. Replace the existing class:

```python
class BrokerScanOutput(BaseModel):
    query_value: str
    brokers_found_count: int
    brokers_found: list[BrokerProfile]
    exposure_score: int
    easyoptouts_url: str = "https://easyoptouts.com/dashboard"
    priority_optouts: list[str]
    bazzell_tier1_found: list[str] = []
    manual_removal_required: list[str] = []
    easyoptouts_covers: int = 0
```

---

## 2. tools/broker_scan.py

### 2a. Add import at top of file (after existing imports)

```python
import json
from pathlib import Path
```

(Both are already imported — no change needed if they already appear.)

### 2b. Add new function after `_calculate_exposure_score`

Insert this function before `def run(`:

```python
BAZZELL_DB_PATH = Path(__file__).parent.parent / "data" / "bazzell_brokers.json"


def _cross_reference_bazzell(profiles: list[BrokerProfile]) -> dict:
    """Cross-reference found broker profiles against Bazzell's removal database.

    Returns:
        dict with keys:
          bazzell_tier1_found       - names of tier-1 brokers detected in scan
          manual_removal_required   - broker names found that EasyOptOuts does NOT cover
          easyoptouts_would_cover   - count of found brokers that EasyOptOuts covers
    """
    try:
        db: list[dict] = json.loads(BAZZELL_DB_PATH.read_text())
    except Exception as exc:
        logger.warning("bazzell cross-reference: failed to load DB — %s", exc)
        return {
            "bazzell_tier1_found": [],
            "manual_removal_required": [],
            "easyoptouts_would_cover": 0,
        }

    # Build a domain -> record map
    domain_map: dict[str, dict] = {entry["domain"]: entry for entry in db}

    tier1_found: list[str] = []
    manual_required: list[str] = []
    easyoptouts_count = 0

    for profile in profiles:
        domain = (profile.broker_domain or "").lower().lstrip("www.")
        entry = domain_map.get(domain)
        if not entry:
            continue

        if entry.get("tier") == 1:
            tier1_found.append(entry["name"])

        if entry.get("easyoptouts_covered"):
            easyoptouts_count += 1
        else:
            manual_required.append(entry["name"])

    return {
        "bazzell_tier1_found": tier1_found,
        "manual_removal_required": manual_required,
        "easyoptouts_would_cover": easyoptouts_count,
    }
```

### 2c. Update `run()` — replace the success-path output construction

Find this block inside the `try:` in `run()`:

```python
        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=len(all_profiles),
            brokers_found=all_profiles,
            exposure_score=exposure_score,
            priority_optouts=priority_optouts,
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )
```

Replace with:

```python
        bazzell = _cross_reference_bazzell(all_profiles)

        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=len(all_profiles),
            brokers_found=all_profiles,
            exposure_score=exposure_score,
            priority_optouts=priority_optouts,
            bazzell_tier1_found=bazzell["bazzell_tier1_found"],
            manual_removal_required=bazzell["manual_removal_required"],
            easyoptouts_covers=bazzell["easyoptouts_would_cover"],
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )
```

---

## 3. agent/report.py

### 3a. Add helper to load bazzell DB (add near top of file, after imports)

```python
from pathlib import Path as _Path
import json as _json

_BAZZELL_DB_PATH = _Path(__file__).parent.parent / "data" / "bazzell_brokers.json"


def _load_bazzell_db() -> dict[str, dict]:
    """Return domain -> broker entry map from bazzell_brokers.json."""
    try:
        entries = _json.loads(_BAZZELL_DB_PATH.read_text())
        return {e["domain"]: e for e in entries}
    except Exception:
        return {}
```

### 3b. Update `write_report()` — add Bazzell section in Markdown after broker_optouts block

Find this exact block in `write_report()`:

```python
    for key, title in [
        ("change_passwords", "Change Passwords"),
        ("enable_2fa",       "Enable 2FA"),
        ("account_reviews",  "Review Account Settings"),
        ("gdpr_removals",    "GDPR Removal Requests"),
        ("broker_optouts",   "Data Broker Opt-Outs"),
    ]:
        items = remediation.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for action in items:
                lines.append(f"- [ ] {action}")
            lines.append("")
```

Replace with:

```python
    for key, title in [
        ("change_passwords", "Change Passwords"),
        ("enable_2fa",       "Enable 2FA"),
        ("account_reviews",  "Review Account Settings"),
        ("gdpr_removals",    "GDPR Removal Requests"),
        ("broker_optouts",   "Data Broker Opt-Outs"),
    ]:
        items = remediation.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for action in items:
                lines.append(f"- [ ] {action}")
            lines.append("")

    # Bazzell cross-reference block
    broker_data = (state.broker_result.data if state.broker_result and state.broker_result.success else {}) or {}
    bazzell_tier1 = broker_data.get("bazzell_tier1_found") or []
    manual_required = broker_data.get("manual_removal_required") or []
    easyoptouts_covers = broker_data.get("easyoptouts_covers", 0)

    if bazzell_tier1 or manual_required:
        bazzell_db = _load_bazzell_db()
        lines += ["### Priority Manual Opt-Outs (Bazzell Tier 1)", ""]
        if easyoptouts_covers:
            lines.append(f"_EasyOptOuts.com can automate {easyoptouts_covers} of these — visit <https://easyoptouts.com> first._")
            lines.append("")
        for name in bazzell_tier1:
            # Find entry by name
            entry = next((e for e in bazzell_db.values() if e.get("name") == name), None)
            if entry and entry.get("optout_url"):
                days = entry.get("estimated_days_to_remove", "?")
                lines.append(f"- [ ] {name}: {entry['optout_url']} ({days} days)")
            else:
                lines.append(f"- [ ] {name}: see broker's website for opt-out")
        lines.append("")
        if manual_required:
            lines += ["### Additional Manual Opt-Outs (Not Covered by EasyOptOuts)", ""]
            for name in manual_required:
                entry = next((e for e in bazzell_db.values() if e.get("name") == name), None)
                if entry and entry.get("optout_url"):
                    days = entry.get("estimated_days_to_remove", "?")
                    notes = entry.get("notes", "")
                    line = f"- [ ] {name}: {entry['optout_url']} ({days} days)"
                    if notes:
                        line += f"  \n  _{notes}_"
                    lines.append(line)
                else:
                    lines.append(f"- [ ] {name}: see broker's website for opt-out")
            lines.append("")
```

### 3c. Update `_write_pdf()` — add Bazzell section after broker_optouts in PDF

Find this block in `_write_pdf()`:

```python
    rem_sections = [
        ("change_passwords", "Change Passwords"),
        ("enable_2fa",       "Enable 2FA"),
        ("account_reviews",  "Review Account Settings"),
        ("gdpr_removals",    "GDPR Removal Requests"),
        ("broker_optouts",   "Data Broker Opt-Outs"),
    ]
    for key, title in rem_sections:
        items = remediation.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(checkbox(item))
            block.append(space(2))
            story.append(KeepTogether(block))
```

Replace with:

```python
    rem_sections = [
        ("change_passwords", "Change Passwords"),
        ("enable_2fa",       "Enable 2FA"),
        ("account_reviews",  "Review Account Settings"),
        ("gdpr_removals",    "GDPR Removal Requests"),
        ("broker_optouts",   "Data Broker Opt-Outs"),
    ]
    for key, title in rem_sections:
        items = remediation.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(checkbox(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Bazzell cross-reference section
    broker_data = (state.broker_result.data if state.broker_result and state.broker_result.success else {}) or {}
    bazzell_tier1 = broker_data.get("bazzell_tier1_found") or []
    manual_required = broker_data.get("manual_removal_required") or []
    easyoptouts_covers = broker_data.get("easyoptouts_covers", 0)

    if bazzell_tier1 or manual_required:
        bazzell_db = _load_bazzell_db()
        block = [h3("Priority Manual Opt-Outs (Bazzell Tier 1)")]
        if easyoptouts_covers:
            block.append(body(
                f"EasyOptOuts.com can automate <b>{easyoptouts_covers}</b> of these — "
                f"visit easyoptouts.com first."
            ))
        for name in bazzell_tier1:
            entry = next((e for e in bazzell_db.values() if e.get("name") == name), None)
            if entry and entry.get("optout_url"):
                days = entry.get("estimated_days_to_remove", "?")
                block.append(checkbox(f'{name}: <a href="{entry["optout_url"]}">{entry["optout_url"]}</a> ({days} days)'))
            else:
                block.append(checkbox(f"{name}: see broker's website"))
        block.append(space(2))
        story.append(KeepTogether(block))

        if manual_required:
            block = [h3("Additional Manual Opt-Outs (Not Covered by EasyOptOuts)")]
            for name in manual_required:
                entry = next((e for e in bazzell_db.values() if e.get("name") == name), None)
                if entry and entry.get("optout_url"):
                    days = entry.get("estimated_days_to_remove", "?")
                    block.append(checkbox(f'{name}: {entry["optout_url"]} ({days} days)'))
                else:
                    block.append(checkbox(f"{name}: see broker's website"))
            block.append(space(2))
            story.append(KeepTogether(block))
```

---

## Notes

- `_load_bazzell_db()` is defined at module level in `agent/report.py` so it can be called from both `write_report()` (Markdown) and `_write_pdf()`.
- The `Path` and `json` imports in `agent/report.py` already exist — the helper uses `_Path` and `_json` aliases to avoid shadowing them; alternatively rename to `Path` and `json` if the existing imports already use those names at module scope (they do — adjust accordingly: use the same `Path` and `json` already imported).
- The domain comparison in `_cross_reference_bazzell` strips leading `www.` from the profile's `broker_domain` before looking up in the map. The Bazzell DB stores bare domains (e.g. `spokeo.com`), so ensure profiles do the same or adjust the strip logic.
