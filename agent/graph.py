from langgraph.graph import END, StateGraph

from agent.nodes import (
    ai_audit_node,
    analysis_node,
    blackbird_node,
    breach_check_node,
    broker_scan_node,
    exodus_node,
    ghunt_node,
    holehe_node,
    intake_node,
    maigret_node,
    report_node,
    shodan_node,
    surface_map_node,
)
from models.shared import PipelineState


def build_graph():  # type: ignore[return-value]
    builder = StateGraph(PipelineState)

    builder.add_node("intake", intake_node)
    builder.add_node("breach_check", breach_check_node)
    builder.add_node("broker_scan", broker_scan_node)
    builder.add_node("surface_map", surface_map_node)
    builder.add_node("holehe", holehe_node)
    builder.add_node("blackbird", blackbird_node)
    builder.add_node("exodus", exodus_node)
    builder.add_node("maigret", maigret_node)
    builder.add_node("ghunt", ghunt_node)
    builder.add_node("shodan", shodan_node)
    builder.add_node("ai_audit", ai_audit_node)
    builder.add_node("analysis", analysis_node)
    builder.add_node("report", report_node)

    builder.set_entry_point("intake")
    builder.add_edge("intake", "breach_check")
    builder.add_edge("breach_check", "surface_map")
    builder.add_edge("surface_map", "holehe")
    builder.add_edge("holehe", "blackbird")
    builder.add_edge("blackbird", "exodus")
    builder.add_edge("exodus", "maigret")
    builder.add_edge("maigret", "ghunt")
    builder.add_edge(
        "ghunt", "broker_scan"
    )  # after ghunt so discovered names are available
    builder.add_edge("broker_scan", "shodan")
    builder.add_edge("shodan", "ai_audit")
    builder.add_edge("ai_audit", "analysis")
    builder.add_edge("analysis", "report")
    builder.add_edge("report", END)

    return builder.compile()
