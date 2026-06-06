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
    lines = [
        f"# Privacy OSINT Report",
        f"",
        f"**Generated:** {timestamp}",
        f"**Input type:** {input_type}",
        f"",
        f"## Risk Summary",
        f"",
        f"**Overall risk score:** {analysis.get('overall_risk_score', 'N/A')}/100",
        f"**Overall risk level:** {analysis.get('overall_risk_level', 'N/A').upper()}",
        f"",
        f"**Summary:** {analysis.get('summary', 'No analysis available.')}",
        f"",
    ]

    if analysis.get("top_findings"):
        lines += ["## Top Findings", ""]
        for finding in analysis["top_findings"]:
            lines.append(f"- {finding}")
        lines.append("")

    if analysis.get("immediate_actions"):
        lines += ["## Immediate Actions", ""]
        for action in analysis["immediate_actions"]:
            lines.append(f"- {action}")
        lines.append("")

    if analysis.get("longer_term_actions"):
        lines += ["## Longer-Term Actions", ""]
        for action in analysis["longer_term_actions"]:
            lines.append(f"- {action}")
        lines.append("")

    if state.hibp_result and state.hibp_result.success:
        hibp_data = state.hibp_result.data
        lines += [
            "## Breach Check (HIBP)",
            "",
            f"Breaches found: **{hibp_data.get('breach_count', 0)}**",
            "",
        ]

    if state.broker_result and state.broker_result.success:
        broker_data = state.broker_result.data
        lines += [
            "## Data Broker Exposure",
            "",
            f"Brokers found: **{broker_data.get('brokers_found_count', 0)}**",
            f"Exposure score: **{broker_data.get('exposure_score', 0)}/100**",
            f"EasyOptOuts dashboard: {broker_data.get('easyoptouts_url', '')}",
            "",
        ]
        if broker_data.get("priority_optouts"):
            lines.append("**Priority opt-outs:**")
            for domain in broker_data["priority_optouts"]:
                lines.append(f"- {domain}")
            lines.append("")

    if state.ai_audit_result and state.ai_audit_result.success:
        ai_data = state.ai_audit_result.data
        lines += [
            "## AI Platform Exposure",
            "",
            f"High-risk platforms: **{ai_data.get('high_risk_count', 0)}**",
            f"Overall AI risk: **{ai_data.get('overall_risk', 'N/A').upper()}**",
            "",
        ]

    md_content = "\n".join(lines)
    md_path.write_text(md_content)

    print(md_content)
    print(f"\nFull results saved to: {json_path}")
    print(f"Report saved to: {md_path}")

    logger.info("report written to %s", md_path)
    return str(md_path)
