from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime


class ToolResult(BaseModel):
    success: bool
    tool: str
    input_type: Literal["email", "phone", "name", "org"]
    input_value: str
    timestamp: datetime
    data: dict
    error: str | None = None


class InputClassification(BaseModel):
    type: Literal["email", "phone", "name", "org"]
    value: str
    raw: str


class PipelineState(BaseModel):
    raw_input: str
    classifications: list[InputClassification] = []
    hibp_result: ToolResult | None = None
    broker_result: ToolResult | None = None
    spiderfoot_result: ToolResult | None = None
    ai_audit_result: ToolResult | None = None
    analysis_result: dict | None = None
    report_path: str | None = None


class AnalysisResult(BaseModel):
    overall_risk_score: int
    overall_risk_level: Literal["high", "medium", "low"]
    summary: str
    top_findings: list[str]
    immediate_actions: list[str]
    longer_term_actions: list[str]
    breach_severity: Literal["high", "medium", "low", "none"]
    broker_exposure_severity: Literal["high", "medium", "low", "none"]
    ai_exposure_severity: Literal["high", "medium", "low", "none"]
