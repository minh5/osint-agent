import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import config
from models.hibp import HibpInput, HibpOutput, BreachRecord
from models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "hibp_response.json"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: HibpInput) -> ToolResult:
    logger.info("hibp: querying input_type=%s", inp.input_type)

    if config.is_test_mode():
        return _load_fixture()

    api_key = config.get("HIBP_API_KEY")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{inp.value}"
    headers = {"hibp-api-key": api_key, "user-agent": "osint-agent"}

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            output = HibpOutput(query_value=inp.value, breach_count=0, breaches=[], paste_count=0)
            return ToolResult(
                success=True,
                tool="hibp",
                input_type=inp.input_type,
                input_value=inp.value,
                timestamp=datetime.now(timezone.utc),
                data=output.model_dump(),
            )

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("retry-after", 2))
            time.sleep(retry_after)
            resp = requests.get(url, headers=headers, timeout=10)

        resp.raise_for_status()

        raw_breaches = resp.json()
        breaches = [BreachRecord(**b) for b in raw_breaches]
        output = HibpOutput(
            query_value=inp.value,
            breach_count=len(breaches),
            breaches=breaches,
            paste_count=-1,
        )
        return ToolResult(
            success=True,
            tool="hibp",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        return ToolResult(
            success=False,
            tool="hibp",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"HIBP error: {exc}",
        )
