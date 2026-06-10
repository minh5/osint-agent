from pydantic import BaseModel


class GHuntInput(BaseModel):
    email: str


class GHuntOutput(BaseModel):
    email: str
    found: bool
    name: str = ""
    profile_photo_url: str = ""
    google_services: list[str] = []
    maps_reviews_count: int = 0
    youtube_channel: str = ""
    raw: dict = {}
