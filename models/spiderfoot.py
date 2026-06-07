from pydantic import BaseModel
from typing import Literal


class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    modules: list[str] = [
        # Fast API-based modules only — sfp_social and sfp_pastebin do
        # extensive crawling and routinely cause timeouts. Social coverage
        # is handled better by Holehe/Blackbird/Maigret anyway.
        "sfp_hibp",       # breach cross-check
        "sfp_emailrep",   # email reputation + risk score
        "sfp_gravatar",   # profile photo, display name, linked accounts
        "sfp_pgp",        # PGP key lookup — confirms real identity
        "sfp_hunter",     # email format / domain intel
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


class SpiderfootOutput(BaseModel):
    scan_id: str
    target: str
    status: Literal["FINISHED", "FAILED", "RUNNING", "ABORTED"]
    element_count: int
    elements: list[SpiderfootElement]
    duration_seconds: int
