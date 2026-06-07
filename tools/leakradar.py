import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

import config
from models.leakradar import LeakRadarInput, LeakRadarOutput, LeakRadarLeak
from models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "leakradar_response.json"
BASE_URL = "https://api.leakradar.io"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: LeakRadarInput) -> ToolResult:
    logger.info("leakradar: searching email=%s", inp.email)

    if config.is_test_mode():
        return _load_fixture()

    if not config.get("LEAKRADAR_API_KEY"):
        logger.info("leakradar: no API key set, skipping")
        return ToolResult(
            success=True,
            tool="leakradar",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=LeakRadarOutput(email=inp.email, total_results=0, leaks=[], sources=[]).model_dump(),
        )

    api_key = config.get("LEAKRADAR_API_KEY")

    try:
        resp = requests.post(
            f"{BASE_URL}/search/email",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={"email": inp.email},
            params={"page": 1, "page_size": 100},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        raw_leaks = data.get("results", data.get("data", []))
        leaks = []
        sources: set[str] = set()
        for item in raw_leaks:
            source = item.get("source", item.get("leak_source", ""))
            sources.add(source)
            leaks.append(LeakRadarLeak(
                source=source,
                email=item.get("email", ""),
                username=item.get("username", ""),
                password=item.get("password", ""),
                hashed_password=item.get("hashed_password", item.get("hash", "")),
                name=item.get("name", ""),
                phone=item.get("phone", ""),
                address=item.get("address", ""),
                leak_date=item.get("leak_date", item.get("date", "")),
            ))

        total = data.get("total", data.get("count", len(leaks)))
        output = LeakRadarOutput(
            email=inp.email,
            total_results=total,
            leaks=leaks,
            sources=sorted(sources),
        )
        logger.info("leakradar: found %d results across %d sources", total, len(sources))
        return ToolResult(
            success=True,
            tool="leakradar",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("leakradar: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="leakradar",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"leakradar error: {exc}",
        )
