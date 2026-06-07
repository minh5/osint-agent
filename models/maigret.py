from pydantic import BaseModel


class MaigretInput(BaseModel):
    username: str
    timeout: int = 10
    max_connections: int = 50


class MaigretProfile(BaseModel):
    platform: str
    url: str
    status: str = "CLAIMED"
    ids_found: list[str] = []
    links: list[str] = []


class MaigretOutput(BaseModel):
    username: str
    platforms_checked: int
    profiles_found: list[MaigretProfile]
    found_count: int
