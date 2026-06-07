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
POLL_TIMEOUT = 600  # 10 minutes max


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
            f"{base}/startscan",
            headers={"Accept": "application/json"},
            data={
                "scanname": f"osint-{inp.target_type}-{int(start_time)}",
                "scantarget": inp.target,
                "modulelist": ",".join(inp.modules),
                "typelist": "",
                "usecase": "all",
            },
            timeout=30,
        )
        scan_resp.raise_for_status()
        resp_json = scan_resp.json()
        if isinstance(resp_json, list) and resp_json[0] == "ERROR":
            raise RuntimeError(f"SpiderFoot startscan error: {resp_json[1]}")
        if isinstance(resp_json, list) and resp_json[0] == "SUCCESS":
            scan_id = resp_json[1]
        else:
            raise RuntimeError(f"Unexpected startscan response: {resp_json}")

        while True:
            elapsed = time.time() - start_time
            if elapsed > POLL_TIMEOUT:
                raise TimeoutError(f"SpiderFoot scan {scan_id} timed out after {POLL_TIMEOUT}s")

            status_resp = requests.get(
                f"{base}/scanstatus",
                params={"id": scan_id},
                headers={"Accept": "application/json"},
                timeout=10,
            )
            status_resp.raise_for_status()
            status_data = status_resp.json()
            # returns [[id, name, target, started, ended, status, ...]]
            status = status_data[0][5] if isinstance(status_data, list) and status_data else "RUNNING"

            logger.info("spiderfoot: scan %s status=%s elapsed=%.0fs", scan_id, status, elapsed)
            if status in ("FINISHED", "FAILED", "ABORTED", "ERROR-FAILED"):
                break
            time.sleep(POLL_INTERVAL)

        results_resp = requests.get(
            f"{base}/scaneventresults",
            params={"id": scan_id},
            headers={"Accept": "application/json"},
            timeout=60,
        )
        results_resp.raise_for_status()
        raw_elements = results_resp.json()

        # SpiderFoot returns rows as arrays:
        # [lastseen, type, data, source_event_type, module, confidence, fp, risk, ...]
        elements = []
        for row in raw_elements:
            if not isinstance(row, list) or len(row) < 8:
                continue
            elements.append(SpiderfootElement(
                date_found=row[0],
                type=row[1],
                data=row[2],
                source=row[3],
                module=row[4],
                confidence=int(row[5]) if str(row[5]).isdigit() else 0,
                fp=int(row[6]) if str(row[6]).isdigit() else 0,
                risk=int(row[7]) if str(row[7]).isdigit() else 0,
            ))
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
        logger.error("spiderfoot: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="spiderfoot",
            input_type=next((k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type), "email"),
            input_value=inp.target,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"SpiderFoot error: {exc}",
        )
