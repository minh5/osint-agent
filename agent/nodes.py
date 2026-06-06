import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import config
from models.shared import PipelineState, InputClassification, ToolResult, AnalysisResult
from models.hibp import HibpInput
from models.spiderfoot import SpiderfootInput
from models.broker_scan import BrokerScanInput
from models.ai_audit import AiAuditInput
from agent.prompts import ANALYSIS_PROMPT

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[\d\s\-\(\)\+\.]{7,}$")

SPIDERFOOT_TARGET_TYPE = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}


def _classify_input(raw: str) -> InputClassification:
    raw = raw.strip()
    if EMAIL_RE.match(raw):
        return InputClassification(type="email", value=raw.lower(), raw=raw)
    if PHONE_RE.match(raw):
        digits = re.sub(r"\D", "", raw)
        normalized = f"+1{digits}" if len(digits) == 10 else raw
        return InputClassification(type="phone", value=normalized, raw=raw)
    words = raw.split()
    if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
        return InputClassification(type="name", value=raw, raw=raw)
    return InputClassification(type="org", value=raw, raw=raw)


def intake_node(state: PipelineState) -> PipelineState:
    logger.info("intake_node: classifying inputs")
    lines = [line.strip() for line in state.raw_input.splitlines() if line.strip()]
    classifications = [_classify_input(line) for line in lines]
    return state.model_copy(update={"classifications": classifications})


def breach_check_node(state: PipelineState) -> PipelineState:
    from tools import hibp as hibp_tool

    primary = next(
        (c for c in state.classifications if c.type in ("email", "phone")),
        state.classifications[0] if state.classifications else None,
    )
    if not primary or primary.type not in ("email", "phone"):
        logger.info("breach_check_node: no email/phone input, skipping HIBP")
        return state

    inp = HibpInput(input_type=primary.type, value=primary.value)
    result = hibp_tool.run(inp)
    return state.model_copy(update={"hibp_result": result})


def broker_scan_node(state: PipelineState) -> PipelineState:
    from tools import broker_scan as broker_tool

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("broker_scan_node: no input classifications, skipping")
        return state

    inp = BrokerScanInput(input_type=primary.type, value=primary.value)
    result = broker_tool.run(inp)
    return state.model_copy(update={"broker_result": result})


def surface_map_node(state: PipelineState) -> PipelineState:
    from tools import spiderfoot as sf_tool

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("surface_map_node: no input, skipping SpiderFoot")
        return state

    target_type = SPIDERFOOT_TARGET_TYPE.get(primary.type, "human_name")
    inp = SpiderfootInput(target=primary.value, target_type=target_type)
    result = sf_tool.run(inp)
    return state.model_copy(update={"spiderfoot_result": result})


def ai_audit_node(state: PipelineState) -> PipelineState:
    from tools import ai_audit as audit_tool

    platforms_raw = os.environ.get("AI_PLATFORMS", "")
    if not platforms_raw:
        logger.info("ai_audit_node: no AI_PLATFORMS env var set, skipping")
        return state

    platforms = [p.strip() for p in platforms_raw.split(",") if p.strip()]
    inp = AiAuditInput(platforms=platforms)
    result = audit_tool.run(inp)
    return state.model_copy(update={"ai_audit_result": result})


def analysis_node(state: PipelineState) -> PipelineState:
    logger.info("analysis_node: synthesizing results with Ollama")

    if config.is_test_mode():
        fixture_path = Path(__file__).parent.parent / "tests" / "fixtures" / "analysis_response.json"
        analysis = json.loads(fixture_path.read_text())
        return state.model_copy(update={"analysis_result": analysis})

    state_json = state.model_dump_json(indent=2)

    try:
        from langchain_ollama import ChatOllama
        llm = ChatOllama(
            model="llama3.1:8b",
            base_url=config.get("OLLAMA_HOST"),
            temperature=0,
        )
        messages = [
            ("system", ANALYSIS_PROMPT),
            ("human", state_json),
        ]
        response = llm.invoke(messages)
        raw_text = response.content

        analysis = json.loads(raw_text)
        AnalysisResult(**analysis)
        return state.model_copy(update={"analysis_result": analysis})

    except json.JSONDecodeError as exc:
        logger.error("analysis_node: failed to parse Ollama JSON response: %s", exc)
        error_result: dict = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": "Analysis failed — could not parse model response.",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})
    except Exception as exc:
        logger.error("analysis_node: unexpected error: %s", exc)
        error_result = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": f"Analysis failed: {exc}",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})


def report_node(state: PipelineState) -> PipelineState:
    from agent.report import write_report
    report_path = write_report(state)
    return state.model_copy(update={"report_path": report_path})
