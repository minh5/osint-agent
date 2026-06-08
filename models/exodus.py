from pydantic import BaseModel


class ExodusInput(BaseModel):
    platforms: list[str]


class TrackerFound(BaseModel):
    name: str
    categories: list[str]
    website: str


class AppTrackerResult(BaseModel):
    platform: str
    package: str
    trackers: list[TrackerFound]
    tracker_count: int
    high_risk_trackers: list[str]


class ExodusOutput(BaseModel):
    apps_checked: int
    apps_with_trackers: int
    results: list[AppTrackerResult]
    all_trackers_found: list[str]  # deduplicated flat list
    high_risk_count: int
