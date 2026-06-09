from typing import Literal

from pydantic import BaseModel, field_validator


class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    modules: list[str] = [
        # Fast API-based modules only. sfp_social/sfp_pastebin do extensive
        # crawling and routinely cause timeouts — social coverage is handled
        # better by Holehe/Blackbird/Maigret. sfp_hunter removed: it makes
        # unauthenticated calls to hunter.io that stall without an API key
        # and contribute to the status="-" queueing delay.
        "sfp_hibp",      # breach cross-check
        "sfp_emailrep",  # email reputation + risk score
        "sfp_gravatar",  # profile photo, display name, linked accounts
        "sfp_pgp",       # PGP key lookup — confirms real identity
        "sfp_whois",     # domain registration info for email domain
    ]


class SpiderfootElement(BaseModel):
    fp: int
    confidence: int
    risk: int
    source: str
    date_found: str
    module: str
    data: str
    type: str

    @field_validator("module", "source", "data", "type", "date_found", mode="before")
    @classmethod
    def coerce_to_str(cls, v: object) -> str:
        """SpiderFoot partial results sometimes return int fields (e.g. module=100).
        Coerce everything to string so validation never fails on numeric values."""
        return str(v) if v is not None else ""


class SpiderfootOutput(BaseModel):
    scan_id: str
    target: str
    status: Literal["FINISHED", "FAILED", "RUNNING", "ABORTED", "PARTIAL"]
    element_count: int
    elements: list[SpiderfootElement]
    duration_seconds: int
