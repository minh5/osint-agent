import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import config
from models.spiderfoot import SpiderfootInput, SpiderfootOutput, SpiderfootElement
from models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "spiderfoot_response.json"

INPUT_TYPE_MAP = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}

POLL_INTERVAL = 10
POLL_TIMEOUT = 1800


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: SpiderfootInput) -> ToolResult:
    logger.info("spiderfoot: scanning target_type=%s", inp.target_type)

    if config.is_test_mode():
        return _load_fixture()

    base = config.get("SPIDERFOOT_HOST")
    start_time = time.time()

    try:
        scan_resp = requests.post(
            f"{base}/api/v1/scan",
            json={
                "scanname": f"osint-{inp.target_type}-{int(start_time)}",
                "scantarget": inp.target,
                "targettype": inp.target_type,
                "usecase": "all",
                "modulelist": ",".join(inp.modules),
            },
            timeout=30,
        )
        scan_resp.raise_for_status()
        scan_id = scan_resp.json()["id"]

        while True:
            elapsed = time.time() - start_time
            if elapsed > POLL_TIMEOUT:
                raise TimeoutError(f"SpiderFoot scan {scan_id} timed out after {POLL_TIMEOUT}s")

            status_resp = requests.get(f"{base}/api/v1/scan/{scan_id}/status", timeout=10)
            status_resp.raise_for_status()
            status = status_resp.json()["status"]

            if status in ("FINISHED", "FAILED", "ABORTED"):
                break
            time.sleep(POLL_INTERVAL)

        results_resp = requests.get(f"{base}/api/v1/scan/{scan_id}/results", timeout=30)
        results_resp.raise_for_status()
        raw_elements = results_resp.json()

        elements = [SpiderfootElement(**e) for e in raw_elements]
        output = SpiderfootOutput(
            scan_id=scan_id,
            target=inp.target,
            status=status,
            element_count=len(elements),
            elements=elements,
            duration_seconds=int(time.time() - start_time),
        )
        return ToolResult(
            success=True,
            tool="spiderfoot",
            input_type=next(k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type),
            input_value=inp.target,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        return ToolResult(
            success=False,
            tool="spiderfoot",
            input_type=next((k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type), "email"),
            input_value=inp.target,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"SpiderFoot error: {exc}",
        )
