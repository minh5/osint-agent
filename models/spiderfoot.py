from pydantic import BaseModel
from typing import Literal


class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    modules: list[str] = [
        "sfp_hibp",
        "sfp_emailrep",
        "sfp_hunter",
        "sfp_whois",
        "sfp_pgp",
        "sfp_gravatar",
        "sfp_social",
        "sfp_pastebin",
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
