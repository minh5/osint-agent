import json
import logging
from datetime import datetime
from pathlib import Path

import config
from models.shared import PipelineState

logger = logging.getLogger(__name__)


def write_report(state: PipelineState) -> str:
    output_dir = Path(config.get("RESULTS_OUTPUT_PATH"))
    output_dir.mkdir(parents=True, exist_ok=True)

    primary = state.classifications[0] if state.classifications else None
    input_type = primary.type if primary else "unknown"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    base_name = f"{timestamp}_{input_type}"

    json_path = output_dir / f"{base_name}_results.json"
    md_path = output_dir / f"{base_name}_report.md"

    json_path.write_text(json.dumps(state.model_dump(), indent=2, default=str))

    analysis = state.analysis_result or {}
    known = analysis.get("what_is_known", {})
    remediation = analysis.get("remediation", {})

    lines = [
        "# Privacy OSINT Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Target:** {primary.value if primary else 'unknown'}",
        f"**Risk Score:** {analysis.get('overall_risk_score', 'N/A')}/100 — {analysis.get('overall_risk_level', 'N/A').upper()}",
        "",
        "---",
        "",
        "## What the Internet Knows About You",
        "",
        analysis.get("identity_summary", "No analysis available."),
        "",
    ]

    if known.get("handles_and_usernames"):
        lines += ["### Usernames & Handles", ""]
        for item in known["handles_and_usernames"]:
            lines.append(f"- {item}")
        lines.append("")

    if known.get("platforms_with_accounts"):
        lines += ["### Accounts Found", ""]
        for item in known["platforms_with_accounts"]:
            lines.append(f"- {item}")
        lines.append("")

    if known.get("physical_data"):
        lines += ["### Physical Data Exposed", ""]
        for item in known["physical_data"]:
            lines.append(f"- {item}")
        lines.append("")

    if known.get("credentials_exposed"):
        lines += ["### Credentials in Circulation", ""]
        for item in known["credentials_exposed"]:
            lines.append(f"- {item}")
        lines.append("")

    if known.get("google_footprint"):
        lines += ["### Google Footprint", ""]
        for item in known["google_footprint"]:
            lines.append(f"- {item}")
        lines.append("")

    if known.get("breach_history"):
        lines += ["### Breach History", ""]
        for item in known["breach_history"]:
            lines.append(f"- {item}")
        lines.append("")

    if analysis.get("top_risks"):
        lines += ["---", "", "## Top Risks", ""]
        for risk in analysis["top_risks"]:
            lines.append(f"- {risk}")
        lines.append("")

    lines += ["---", "", "## What To Do", ""]

    if remediation.get("do_today"):
        lines += ["### Do Today", ""]
        for action in remediation["do_today"]:
            lines.append(f"- [ ] {action}")
        lines.append("")

    if remediation.get("do_this_week"):
        lines += ["### Do This Week", ""]
        for action in remediation["do_this_week"]:
            lines.append(f"- [ ] {action}")
        lines.append("")

    if remediation.get("ongoing"):
        lines += ["### Ongoing", ""]
        for action in remediation["ongoing"]:
            lines.append(f"- [ ] {action}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Raw Tool Results",
        "",
    ]
    if state.hibp_result and state.hibp_result.success:
        lines.append(f"- **HIBP:** {state.hibp_result.data.get('breach_count', 0)} breaches")
    if state.blackbird_result and state.blackbird_result.success:
        lines.append(f"- **Blackbird:** {state.blackbird_result.data.get('found_count', 0)} accounts found")
    if state.sherlock_result and state.sherlock_result.success:
        lines.append(f"- **Maigret:** {state.sherlock_result.data.get('found_count', 0)} profiles found across {state.sherlock_result.data.get('platforms_checked', 0)} platforms")
    if state.ghunt_result and state.ghunt_result.success:
        lines.append(f"- **GHunt:** {'Found' if state.ghunt_result.data.get('found') else 'Not found'}")
    if state.holehe_result and state.holehe_result.success:
        lines.append(f"- **Holehe:** {state.holehe_result.data.get('found_count', 0)} registrations found")
    if state.broker_result and state.broker_result.success:
        lines.append(f"- **Broker scan:** {state.broker_result.data.get('brokers_found_count', 0)} brokers, exposure score {state.broker_result.data.get('exposure_score', 0)}/100")
    if state.leakradar_result and state.leakradar_result.success:
        lines.append(f"- **LeakRadar:** {state.leakradar_result.data.get('total_results', 0)} results")
    if state.spiderfoot_result and state.spiderfoot_result.success:
        lines.append(f"- **SpiderFoot:** {state.spiderfoot_result.data.get('element_count', 0)} elements")
    if state.ai_audit_result and state.ai_audit_result.success:
        lines.append(f"- **AI Audit:** {state.ai_audit_result.data.get('high_risk_count', 0)} high-risk platforms")

    lines += ["", f"Full results: `{json_path}`"]

    md_content = "\n".join(lines)
    md_path.write_text(md_content)

    print(md_content)
    print(f"\nFull results saved to: {json_path}")
    print(f"Report saved to: {md_path}")

    logger.info("report written to %s", md_path)
    return str(md_path)
