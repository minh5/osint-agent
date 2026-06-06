import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

import config
from models.broker_scan import BrokerScanInput, BrokerScanOutput, BrokerProfile
from models.shared import ToolResult

logger = logging.getLogger(__name__)

FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "broker_apify_response.json"
BROKER_DOMAINS_PATH = Path(__file__).parent.parent / "data" / "broker_domains.txt"

APIFY_BASE = "https://api.apify.com/v2"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def _load_broker_domains() -> list[str]:
    return [
        line.strip()
        for line in BROKER_DOMAINS_PATH.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _run_apify(inp: BrokerScanInput) -> list[BrokerProfile]:
    token = config.get("APIFY_API_TOKEN")
    actor_id = config.get("APIFY_ACTOR_ID")

    query: dict = {"query": inp.value}
    if inp.first_name:
        query["firstName"] = inp.first_name
    if inp.last_name:
        query["lastName"] = inp.last_name
    if inp.state:
        query["state"] = inp.state

    run_resp = requests.post(
        f"{APIFY_BASE}/acts/{actor_id}/runs",
        params={"token": token},
        json={"input": query},
        timeout=30,
    )
    run_resp.raise_for_status()
    run_id = run_resp.json()["data"]["id"]

    import time
    for _ in range(60):
        status_resp = requests.get(
            f"{APIFY_BASE}/actor-runs/{run_id}",
            params={"token": token},
            timeout=10,
        )
        status_resp.raise_for_status()
        status = status_resp.json()["data"]["status"]
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "ABORTED", "TIMED-OUT"):
            raise RuntimeError(f"Apify run {run_id} ended with status {status}")
        time.sleep(5)
    else:
        raise TimeoutError(f"Apify run {run_id} timed out")

    dataset_id = status_resp.json()["data"]["defaultDatasetId"]
    items_resp = requests.get(
        f"{APIFY_BASE}/datasets/{dataset_id}/items",
        params={"token": token},
        timeout=30,
    )
    items_resp.raise_for_status()
    items = items_resp.json()

    profiles = []
    for item in items:
        profiles.append(BrokerProfile(
            broker_name=item.get("source", "Unknown"),
            broker_domain=item.get("domain", ""),
            source="apify",
            profile_url=item.get("profileUrl"),
            data_found=item.get("dataFound", []),
            confidence="high" if item.get("exact_match") else "medium",
            optout_url=item.get("optoutUrl", ""),
        ))
    return profiles


def _run_google_cse(inp: BrokerScanInput, broker_domains: list[str]) -> list[BrokerProfile]:
    api_key = config.get("GOOGLE_CSE_API_KEY")
    cse_id = config.get("GOOGLE_CSE_ID")

    profiles = []
    resp = requests.get(
        "https://www.googleapis.com/customsearch/v1",
        params={
            "key": api_key,
            "cx": cse_id,
            "q": inp.value,
            "num": 10,
        },
        timeout=15,
    )
    resp.raise_for_status()
    items = resp.json().get("items", [])

    seen_domains: set[str] = set()
    for item in items:
        link = item.get("link", "")
        matched_domain = next((d for d in broker_domains if d in link), None)
        if matched_domain and matched_domain not in seen_domains:
            seen_domains.add(matched_domain)
            name = matched_domain.split(".")[0].title()
            profiles.append(BrokerProfile(
                broker_name=name,
                broker_domain=matched_domain,
                source="google_cse",
                profile_url=link,
                data_found=["name"],
                confidence="low",
                optout_url=f"https://www.{matched_domain}/opt-out",
            ))
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

    try:
        broker_domains = _load_broker_domains()
        apify_profiles = _run_apify(inp)
        google_profiles = _run_google_cse(inp, broker_domains)

        seen: set[str] = set()
        all_profiles: list[BrokerProfile] = []
        for p in apify_profiles + google_profiles:
            if p.broker_domain not in seen:
                seen.add(p.broker_domain)
                all_profiles.append(p)

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
        return ToolResult(
            success=False,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"broker_scan error: {exc}",
        )
