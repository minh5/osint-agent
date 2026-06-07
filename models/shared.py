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
    holehe_result: ToolResult | None = None
    leakradar_result: ToolResult | None = None
    blackbird_result: ToolResult | None = None
    sherlock_result: ToolResult | None = None
    ghunt_result: ToolResult | None = None
    ai_audit_result: ToolResult | None = None
    analysis_result: dict | None = None
    report_path: str | None = None


class WhatIsKnown(BaseModel):
    handles_and_usernames: list[str] = []
    platforms_with_accounts: list[str] = []
    physical_data: list[str] = []
    credentials_exposed: list[str] = []
    google_footprint: list[str] = []
    breach_history: list[str] = []


class Remediation(BaseModel):
    do_today: list[str] = []
    do_this_week: list[str] = []
    ongoing: list[str] = []


class AnalysisResult(BaseModel):
    overall_risk_score: int
    overall_risk_level: Literal["high", "medium", "low"]
    identity_summary: str
    what_is_known: WhatIsKnown
    top_risks: list[str]
    remediation: Remediation
    breach_severity: Literal["high", "medium", "low", "none"]
    broker_exposure_severity: Literal["high", "medium", "low", "none"]
    account_exposure_severity: Literal["high", "medium", "low", "none"]
