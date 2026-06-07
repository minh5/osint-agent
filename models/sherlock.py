from pydantic import BaseModel


class SherlockInput(BaseModel):
    username: str


class SherlockProfile(BaseModel):
    platform: str
    url: str


class SherlockOutput(BaseModel):
    username: str
    platforms_checked: int
    profiles_found: list[SherlockProfile]
    found_count: int
