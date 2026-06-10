from typing import Literal

from pydantic import BaseModel


class AiAuditInput(BaseModel):
    platforms: list[str]


class AiPlatformPolicy(BaseModel):
    platform_id: str
    display_name: str
    trains_consumer_by_default: bool
    opt_out_available: bool
    consumer_retention_opted_in: str
    consumer_retention_opted_out: str
    api_excluded_from_training: bool
    jurisdiction: str
    risk_level: Literal["high", "medium", "low"]
    opt_out_url: str
    notes: str


class AiAuditOutput(BaseModel):
    platforms_checked: list[str]
    platforms_found: list[AiPlatformPolicy]
    high_risk_count: int
    action_items: list[str]
    overall_risk: Literal["high", "medium", "low"]
