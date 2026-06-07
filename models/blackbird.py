from pydantic import BaseModel


class BlackbirdInput(BaseModel):
    email: str


class BlackbirdAccount(BaseModel):
    platform: str
    url: str
    category: str = ""
    metadata: list[dict] = []


class BlackbirdOutput(BaseModel):
    email: str
    platforms_checked: int
    accounts_found: list[BlackbirdAccount]
    found_count: int
