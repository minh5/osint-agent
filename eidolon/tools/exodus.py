import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

from eidolon import config
from eidolon.models.exodus import (
    AppTrackerResult,
    ExodusInput,
    ExodusOutput,
    TrackerFound,
)
from eidolon.models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "exodus_response.json"
)
PACKAGES_PATH = Path(__file__).parent.parent / "data" / "platform_packages.json"

SEARCH_URL = "https://reports.exodus-privacy.eu.org/api/search/{package}"

# Exodus Privacy API requires a token — get one free at:
# https://reports.exodus-privacy.eu.org/en/api/
# Set EXODUS_API_TOKEN in .env — without it, Exodus is skipped.

HIGH_RISK_TRACKER_NAMES = {
    "facebook",
    "adjust",
    "appsflyer",
    "branch",
    "braze",
    "amplitude",
    "mixpanel",
    "segment",
    "crashlytics",
}
HIGH_RISK_CATEGORIES = {"Advertising", "Profiling"}

MAX_APPS = 15


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def _load_packages() -> dict[str, str]:
    return json.loads(PACKAGES_PATH.read_text())


def _is_high_risk(tracker: TrackerFound) -> bool:
    name_lower = tracker.name.lower()
    for risky in HIGH_RISK_TRACKER_NAMES:
        if risky in name_lower:
            return True
    for cat in tracker.categories:
        if cat in HIGH_RISK_CATEGORIES:
            return True
    return False


def _fetch_trackers(
    package: str, client: httpx.Client, token: str
) -> list[TrackerFound]:
    url = SEARCH_URL.format(package=package)
    try:
        resp = client.get(url, timeout=10, headers={"Authorization": f"Token {token}"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("exodus: failed to fetch %s: %s", package, exc)
        return []

    trackers = []
    # The API returns a dict keyed by report id; each report has a "trackers" list
    for report in data.values():
        if not isinstance(report, dict):
            continue
        for tracker_entry in report.get("trackers", []):
            trackers.append(
                TrackerFound(
                    name=tracker_entry.get("name", "Unknown"),
                    categories=tracker_entry.get("categories", []),
                    website=tracker_entry.get("website", ""),
                )
            )
    # Deduplicate by name
    seen: set[str] = set()
    unique: list[TrackerFound] = []
    for t in trackers:
        if t.name not in seen:
            seen.add(t.name)
            unique.append(t)
    return unique


def run(inp: ExodusInput) -> ToolResult:
    logger.info("exodus: checking %d platforms", len(inp.platforms))

    if config.is_test_mode():
        return _load_fixture()

    token = config.get("EXODUS_API_TOKEN")
    if not token:
        logger.info(
            "exodus: no EXODUS_API_TOKEN set — skipping "
            "(get a free token at reports.exodus-privacy.eu.org/en/api/)"
        )
        output = ExodusOutput(
            apps_checked=0,
            apps_with_trackers=0,
            results=[],
            all_trackers_found=[],
            high_risk_count=0,
        )
        return ToolResult(
            success=True,
            tool="exodus",
            input_type="name",
            input_value="",
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    packages = _load_packages()

    # Dedup platforms by normalised name before lookup — holehe and blackbird
    # often both return the same platform with slightly different casing
    seen_packages: set[str] = set()
    unique_platforms: list[str] = []
    for platform in inp.platforms:
        package = packages.get(platform.lower())
        if package and package not in seen_packages:
            seen_packages.add(package)
            unique_platforms.append(platform)

    platforms_to_check = unique_platforms[:MAX_APPS]
    logger.info(
        "exodus: %d unique platforms after dedup (was %d)",
        len(platforms_to_check),
        len(inp.platforms),
    )

    app_results: list[AppTrackerResult] = []
    all_tracker_names: set[str] = set()
    high_risk_total = 0

    with httpx.Client() as client:
        for platform in platforms_to_check:
            key = platform.lower()
            package = packages.get(key)
            if not package:
                logger.debug(
                    "exodus: no package mapping for platform=%s, skipping", platform
                )
                continue

            trackers = _fetch_trackers(package, client, token)
            high_risk = [t.name for t in trackers if _is_high_risk(t)]

            for t in trackers:
                all_tracker_names.add(t.name)
            high_risk_total += len(high_risk)

            app_results.append(
                AppTrackerResult(
                    platform=platform,
                    package=package,
                    trackers=trackers,
                    tracker_count=len(trackers),
                    high_risk_trackers=high_risk,
                )
            )

    apps_with_trackers = sum(1 for r in app_results if r.tracker_count > 0)
    output = ExodusOutput(
        apps_checked=len(app_results),
        apps_with_trackers=apps_with_trackers,
        results=app_results,
        all_trackers_found=sorted(all_tracker_names),
        high_risk_count=high_risk_total,
    )

    return ToolResult(
        success=True,
        tool="exodus",
        input_type="name",
        input_value=", ".join(inp.platforms[:3])
        + ("..." if len(inp.platforms) > 3 else ""),
        timestamp=datetime.now(timezone.utc),
        data=output.model_dump(),
        error=None,
    )
