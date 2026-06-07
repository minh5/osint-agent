import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from apify_client import ApifyClient

import config
from models.broker_scan import BrokerScanInput, BrokerScanOutput, BrokerProfile
from models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "broker_apify_response.json"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def _run_apify(inp: BrokerScanInput) -> list[BrokerProfile]:
    token = config.get("APIFY_API_TOKEN")
    actor_id = config.get("APIFY_ACTOR_ID")
    scrapfly_key = config.get("SCRAPFLY_API_KEY")

    run_input: dict = {
        "scrapFlyApiKey": scrapfly_key,
        "searches": [],
    }

    # Actor requires name + address together, or searches list
    # For email/phone inputs we skip name lookup and rely on Google CSE instead
    if inp.input_type == "name" and inp.first_name and inp.last_name:
        run_input["name"] = f"{inp.first_name} {inp.last_name}"
        run_input["address"] = inp.state or ""
    elif inp.input_type == "name":
        parts = inp.value.split()
        run_input["name"] = inp.value
        run_input["address"] = inp.state or ""
    else:
        # email/phone/org — actor can't search by these, return empty
        logger.info("broker_scan: apify skipped for input_type=%s (name required)", inp.input_type)
        return []

    logger.info("broker_scan: starting apify actor %s", actor_id)
    client = ApifyClient(token)
    run = client.actor(actor_id).call(run_input=run_input)
    logger.info("broker_scan: apify run finished run_id=%s status=%s",
                run.id, run.status)

    profiles = []
    for item in client.dataset(run.default_dataset_id).iterate_items():
        profiles.append(BrokerProfile(
            broker_name=item.get("source", "Unknown"),
            broker_domain=item.get("domain", ""),
            source="apify",
            profile_url=item.get("profileUrl"),
            data_found=item.get("dataFound", []),
            confidence="high" if item.get("exactMatch") else "medium",
            optout_url=item.get("optoutUrl", ""),
        ))

    logger.info("broker_scan: apify returned %d profiles", len(profiles))
    return profiles


def _calculate_exposure_score(profiles: list[BrokerProfile]) -> int:
    score = 0
    depth_weights = {"email": 15, "phone": 15, "address": 10, "relatives": 20, "name": 5, "age": 5}
    for p in profiles:
        score += 5
        if p.confidence == "high":
            score += 10
        elif p.confidence == "medium":
            score += 5
        for field in p.data_found:
            score += depth_weights.get(field, 3)
    return min(score, 100)


def run(inp: BrokerScanInput) -> ToolResult:
    logger.info("broker_scan: scanning input_type=%s", inp.input_type)

    if config.is_test_mode():
        return _load_fixture()

    # Broker scan only meaningful for name inputs — brokers list by name/address
    if inp.input_type not in ("name",):
        logger.info("broker_scan: skipping for input_type=%s (name required)", inp.input_type)
        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=0,
            brokers_found=[],
            exposure_score=0,
            priority_optouts=[],
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    try:
        all_profiles = _run_apify(inp)

        seen: set[str] = set()
        deduped: list[BrokerProfile] = []
        for p in all_profiles:
            if p.broker_domain not in seen:
                seen.add(p.broker_domain)
                deduped.append(p)
        all_profiles = deduped

        exposure_score = _calculate_exposure_score(all_profiles)
        sorted_by_depth = sorted(all_profiles, key=lambda p: len(p.data_found), reverse=True)
        priority_optouts = [p.broker_domain for p in sorted_by_depth[:5]]

        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=len(all_profiles),
            brokers_found=all_profiles,
            exposure_score=exposure_score,
            priority_optouts=priority_optouts,
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("broker_scan: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"broker_scan error: {exc}",
        )
