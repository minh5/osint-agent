from typing import Literal

from pydantic import BaseModel


class BrokerScanInput(BaseModel):
    input_type: Literal["email", "phone", "name", "org"]
    value: str
    first_name: str | None = None
    last_name: str | None = None
    city: str | None = None
    state: str | None = None
    zip_code: str | None = None


class BrokerProfile(BaseModel):
    broker_name: str
    broker_domain: str
    source: Literal["apify", "google_cse", "scrapfly"]
    profile_url: str | None
    data_found: list[str]
    confidence: Literal["high", "medium", "low"]
    optout_url: str


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
