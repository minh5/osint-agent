from pydantic import BaseModel


class LeakRadarInput(BaseModel):
    email: str


class LeakRadarLeak(BaseModel):
    source: str = ""
    email: str = ""
    username: str = ""
    password: str = ""
    hashed_password: str = ""
    name: str = ""
    phone: str = ""
    address: str = ""
    leak_date: str = ""


class LeakRadarOutput(BaseModel):
    email: str
    total_results: int
    leaks: list[LeakRadarLeak]
    sources: list[str]
