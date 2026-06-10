import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import requests
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_pascal

from eidolon import config
from eidolon.core.models import ToolResult


class HibpInput(BaseModel):
    input_type: Literal["email", "phone"]
    value: str


class BreachRecord(BaseModel):
    model_config = ConfigDict(alias_generator=to_pascal, populate_by_name=True)

    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    modified_date: str = ""
    pwn_count: int = 0
    description: str = ""
    logo_path: str = ""
    data_classes: list[str] = []
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False


class HibpOutput(BaseModel):
    query_value: str
    breach_count: int
    breaches: list[BreachRecord]
    paste_count: int


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "hibp_response.json"
)


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
        params = {"truncateResponse": "false"}
        resp = requests.get(url, headers=headers, params=params, timeout=10)

        if resp.status_code == 404:
            output = HibpOutput(
                query_value=inp.value, breach_count=0, breaches=[], paste_count=0
            )
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
            resp = requests.get(url, headers=headers, params=params, timeout=10)

        resp.raise_for_status()

        raw_breaches = resp.json()
        breaches = [BreachRecord.model_validate(b) for b in raw_breaches]
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
        logger.error("hibp: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="hibp",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"HIBP error: {exc}",
        )
