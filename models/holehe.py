from pydantic import BaseModel
from typing import Literal


class HoleheInput(BaseModel):
    email: str


class HoleheMatch(BaseModel):
    platform: str
    exists: bool
    email_recovery: str | None = None
    phone_number: str | None = None
    rate_limited: bool = False


class HoleheOutput(BaseModel):
    email: str
    platforms_checked: int
    platforms_found: list[HoleheMatch]
    found_count: int
