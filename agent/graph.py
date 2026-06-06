from langgraph.graph import StateGraph, END

from models.shared import PipelineState
from agent.nodes import (
    intake_node,
    breach_check_node,
    broker_scan_node,
    surface_map_node,
    ai_audit_node,
    analysis_node,
    report_node,
)


def build_graph() -> StateGraph:
    builder = StateGraph(PipelineState)

    builder.add_node("intake", intake_node)
    builder.add_node("breach_check", breach_check_node)
    builder.add_node("broker_scan", broker_scan_node)
    builder.add_node("surface_map", surface_map_node)
    builder.add_node("ai_audit", ai_audit_node)
    builder.add_node("analysis", analysis_node)
    builder.add_node("report", report_node)

    builder.set_entry_point("intake")
    builder.add_edge("intake", "breach_check")
    builder.add_edge("breach_check", "broker_scan")
    builder.add_edge("broker_scan", "surface_map")
    builder.add_edge("surface_map", "ai_audit")
    builder.add_edge("ai_audit", "analysis")
    builder.add_edge("analysis", "report")
    builder.add_edge("report", END)

    return builder.compile()
