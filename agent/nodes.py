import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

import config
from agent.prompts import ANALYSIS_PROMPT, CORRELATION_PROMPT
from models.ai_audit import AiAuditInput
from models.blackbird import BlackbirdInput
from models.broker_scan import BrokerScanInput, BrokerScanOutput

from models.ghunt import GHuntInput
from models.hibp import HibpInput
from models.holehe import HoleheInput
from models.maigret import MaigretInput
from models.phone import PhoneInput
from models.shared import AnalysisResult, InputClassification, PipelineState, ToolResult
from models.shodan import ShodanInput
from models.spiderfoot import SpiderfootInput

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_json_tolerant(text: str) -> dict | list:
    """Parse JSON with progressive repair for common LLM output quirks.

    Attempts in order:
    1. Plain json.loads (fast path)
    2. Strip trailing commas before ] or } (most common LLM mistake)
    3. Extract the first {...} or [...] block (handles surrounding prose)
    Raises json.JSONDecodeError if all attempts fail.
    """
    # Fast path
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Repair trailing commas: ,  } or ,  ]
    repaired = re.sub(r",\s*([\]}])", r"\1", text)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # Extract outermost JSON object or array
    for start_char, end_char in [('{', '}'), ('[', ']')]:
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start != -1 and end > start:
            candidate = text[start:end + 1]
            # Also repair trailing commas in extracted fragment
            candidate = re.sub(r",\s*([\]}])", r"\1", candidate)
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    # All attempts failed — raise original error for the caller to log
    raise json.JSONDecodeError("could not repair JSON", text, 0)
PHONE_RE = re.compile(r"^[\d\s\-\(\)\+\.]{7,}$")

SPIDERFOOT_TARGET_TYPE = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}


def _classify_input(raw: str) -> InputClassification:
    raw = raw.strip()
    if EMAIL_RE.match(raw):
        return InputClassification(type="email", value=raw.lower(), raw=raw)
    if PHONE_RE.match(raw):
        digits = re.sub(r"\D", "", raw)
        normalized = f"+1{digits}" if len(digits) == 10 else raw
        return InputClassification(type="phone", value=normalized, raw=raw)
    words = raw.split()
    if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
        return InputClassification(type="name", value=raw, raw=raw)
    return InputClassification(type="org", value=raw, raw=raw)


def intake_node(state: PipelineState) -> PipelineState:
    logger.info("intake_node: classifying inputs")
    classifications = []
    location: dict = {}
    for line in state.raw_input.splitlines():
        line = line.strip()
        if not line:
            continue
        # Structured format from main.py argparse: "type:value"
        if line.startswith(("email:", "phone:", "name:")):
            kind, _, value = line.partition(":")
            type_map: dict[str, Literal["email", "phone", "name", "org"]] = {
                "email": "email",
                "phone": "phone",
                "name": "name",
            }
            classifications.append(
                InputClassification(
                    type=type_map[kind], value=value.strip(), raw=value.strip()
                )
            )
        elif line.startswith(("city:", "state:", "zip:")):
            kind, _, value = line.partition(":")
            location[kind] = value.strip()
            logger.info("  location: %s=%s", kind, value.strip())
        else:
            # Fallback: regex-based classification for bare strings
            classifications.append(_classify_input(line))

    for c in classifications:
        logger.info("  classified: type=%s value=%s", c.type, c.value)

    updates: dict = {"classifications": classifications}
    if location.get("city"):
        updates["location_city"] = location["city"]
    if location.get("state"):
        updates["location_state"] = location["state"]
    if location.get("zip"):
        updates["location_zip"] = location["zip"]
    return state.model_copy(update=updates)


def breach_check_node(state: PipelineState) -> PipelineState:
    from tools import hibp as hibp_tool

    primary = next(
        (c for c in state.classifications if c.type in ("email", "phone")),
        state.classifications[0] if state.classifications else None,
    )
    if not primary or primary.type not in ("email", "phone"):
        logger.info("breach_check_node: no email/phone input, skipping HIBP")
        return state

    inp = HibpInput(input_type=primary.type, value=primary.value)
    result = hibp_tool.run(inp)
    if result.success:
        logger.info(
            "breach_check_node: OK — breach_count=%s",
            result.data.get("breach_count", 0),
        )
    else:
        logger.error("breach_check_node: FAILED — %s", result.error)
    return state.model_copy(update={"hibp_result": result})


def _resolve_name(state: PipelineState) -> str | None:
    """Find the best available name for broker search.

    Priority:
    1. Explicit --name input from the user
    2. GHunt display name (most reliable — pulled from Google account)
    3. SpiderFoot human_name elements
    Returns None if no name found anywhere.
    """
    # 1. Explicit name from intake
    name_classification = next(
        (c for c in state.classifications if c.type == "name"), None
    )
    if name_classification:
        return name_classification.value

    # 2. GHunt display name
    if state.ghunt_result and state.ghunt_result.success:
        ghunt_name = state.ghunt_result.data.get("name", "")
        if ghunt_name:
            logger.info("broker_scan_node: using GHunt name: %s", ghunt_name)
            return ghunt_name

    # 3. SpiderFoot HUMAN_NAME elements
    if state.spiderfoot_result and state.spiderfoot_result.success:
        elements = state.spiderfoot_result.data.get("elements", [])
        for el in elements:
            if el.get("type") == "HUMAN_NAME" and el.get("data"):
                name = el["data"].strip()
                if name:
                    logger.info("broker_scan_node: using SpiderFoot name: %s", name)
                    return name

    return None


def broker_scan_node(state: PipelineState) -> PipelineState:
    from tools import broker_scan as broker_tool

    name = _resolve_name(state)

    if not name:
        logger.info(
            "broker_scan_node: no name available from input or prior tools — skipping"
        )
        output = BrokerScanOutput(
            query_value="",
            brokers_found_count=0,
            brokers_found=[],
            exposure_score=0,
            priority_optouts=[],
        )
        result = ToolResult(
            success=True,
            tool="broker_scan",
            input_type="name",
            input_value="",
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )
        return state.model_copy(update={"broker_result": result})

    logger.info(
        "broker_scan_node: searching brokers for name=%s city=%s state=%s zip=%s",
        name,
        state.location_city,
        state.location_state,
        state.location_zip,
    )
    inp = BrokerScanInput(
        input_type="name",
        value=name,
        city=state.location_city,
        state=state.location_state,
        zip_code=state.location_zip,
    )
    result = broker_tool.run(inp)
    if result.success:
        logger.info(
            "broker_scan_node: OK — brokers_found=%s exposure_score=%s",
            result.data.get("brokers_found_count", 0),
            result.data.get("exposure_score", 0),
        )
    else:
        logger.error("broker_scan_node: FAILED — %s", result.error)
    return state.model_copy(update={"broker_result": result})


def surface_map_node(state: PipelineState) -> PipelineState:
    from tools import spiderfoot as sf_tool

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("surface_map_node: no input, skipping SpiderFoot")
        return state

    target_type = cast(
        Literal["emailaddr", "phone", "human_name", "company_name"],
        SPIDERFOOT_TARGET_TYPE.get(primary.type, "human_name"),
    )
    inp = SpiderfootInput(target=primary.value, target_type=target_type)
    result = sf_tool.run(inp)
    if result.success:
        logger.info(
            "surface_map_node: OK — elements=%s", result.data.get("element_count", 0)
        )
    else:
        logger.error("surface_map_node: FAILED — %s", result.error)
    return state.model_copy(update={"spiderfoot_result": result})


def holehe_node(state: PipelineState) -> PipelineState:
    from tools import holehe as holehe_tool

    primary = next(
        (c for c in state.classifications if c.type == "email"),
        None,
    )
    if not primary:
        logger.info("holehe_node: no email input, skipping")
        return state

    inp = HoleheInput(email=primary.value)
    result = holehe_tool.run(inp)
    if result.success:
        logger.info(
            "holehe_node: OK — found=%s checked=%s",
            result.data.get("found_count", 0),
            result.data.get("platforms_checked", 0),
        )
    else:
        logger.error("holehe_node: FAILED — %s", result.error)
    return state.model_copy(update={"holehe_result": result})


def blackbird_node(state: PipelineState) -> PipelineState:
    from tools import blackbird as blackbird_tool

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("blackbird_node: no email input, skipping")
        return state

    inp = BlackbirdInput(email=primary.value)
    result = blackbird_tool.run(inp)
    if result.success:
        logger.info("blackbird_node: OK — found=%s", result.data.get("found_count", 0))
    else:
        logger.error("blackbird_node: FAILED — %s", result.error)
    return state.model_copy(update={"blackbird_result": result})


def maigret_node(state: PipelineState) -> PipelineState:
    from tools import maigret as maigret_tool

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("maigret_node: no input, skipping")
        return state

    if primary.type == "email":
        username = primary.value.split("@")[0]
    elif primary.type == "name":
        username = primary.value.replace(" ", "").lower()
    else:
        logger.info("maigret_node: skipping for input_type=%s", primary.type)
        return state

    inp = MaigretInput(username=username)
    result = maigret_tool.run(inp)
    if result.success:
        logger.info(
            "maigret_node: OK — found=%s checked=%s",
            result.data.get("found_count", 0),
            result.data.get("platforms_checked", 0),
        )
    else:
        logger.error("maigret_node: FAILED — %s", result.error)
    return state.model_copy(update={"sherlock_result": result})


def ghunt_node(state: PipelineState) -> PipelineState:
    from tools import ghunt as ghunt_tool

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("ghunt_node: no email input, skipping")
        return state

    inp = GHuntInput(email=primary.value)
    result = ghunt_tool.run(inp)
    if result.success:
        logger.info(
            "ghunt_node: OK — found=%s services=%s",
            result.data.get("found", False),
            result.data.get("google_services", []),
        )
    else:
        logger.error("ghunt_node: FAILED — %s", result.error)
    return state.model_copy(update={"ghunt_result": result})


def shodan_node(state: PipelineState) -> PipelineState:
    from models.shodan import ShodanOutput
    from tools import shodan as shodan_tool

    if not state.spiderfoot_result or not state.spiderfoot_result.success:
        logger.info("shodan_node: no spiderfoot_result, skipping")
        return state

    elements = state.spiderfoot_result.data.get("elements", [])
    ips = [
        el["data"]
        for el in elements
        if el.get("type") == "IP_ADDRESS" and el.get("data")
    ][
        :5
    ]  # cap at 5 IPs

    if not ips:
        logger.info(
            "shodan_node: no IP_ADDRESS elements in spiderfoot_result, skipping"
        )
        return state

    logger.info("shodan_node: scanning %d IPs: %s", len(ips), ips)

    all_hosts = []
    for ip in ips:
        inp = ShodanInput(ip=ip)
        result = shodan_tool.run(inp)
        if result.success:
            all_hosts.extend(result.data.get("hosts", []))
        else:
            logger.warning("shodan_node: failed for ip=%s — %s", ip, result.error)

    total_open_ports = sum(len(h.get("ports", [])) for h in all_hosts)
    total_vulns = sum(len(h.get("vulns", [])) for h in all_hosts)
    high_risk_ips = [h["ip"] for h in all_hosts if h.get("vulns")]

    output = ShodanOutput(
        ips_checked=len(ips),
        hosts=[],
        total_open_ports=total_open_ports,
        total_vulns=total_vulns,
        high_risk_ips=high_risk_ips,
    )
    aggregated_data = output.model_dump()
    aggregated_data["hosts"] = all_hosts

    primary = state.classifications[0] if state.classifications else None
    aggregated = ToolResult(
        success=True,
        tool="shodan",
        input_type=primary.type if primary else "org",
        input_value=primary.value if primary else "",
        timestamp=datetime.now(timezone.utc),
        data=aggregated_data,
    )

    logger.info(
        "shodan_node: OK — ips_checked=%d open_ports=%d vulns=%d",
        len(ips),
        total_open_ports,
        total_vulns,
    )
    return state.model_copy(update={"shodan_result": aggregated})



def ai_audit_node(state: PipelineState) -> PipelineState:
    from tools import ai_audit as audit_tool

    # Derive platforms from Blackbird + Holehe + SpiderFoot social media elements
    platforms: set[str] = set()

    if state.blackbird_result and state.blackbird_result.success:
        for account in state.blackbird_result.data.get("accounts_found", []):
            platforms.add(account["platform"].lower().replace(" ", "_"))

    if state.holehe_result and state.holehe_result.success:
        for match in state.holehe_result.data.get("platforms_found", []):
            platforms.add(match["platform"].lower())

    if state.spiderfoot_result and state.spiderfoot_result.success:
        for el in state.spiderfoot_result.data.get("elements", []):
            if el.get("type") == "SOCIAL_MEDIA":
                # data field is typically "Platform: username" or a URL
                raw = el.get("data", "")
                platform = raw.split(":")[0].strip().lower().replace(" ", "_")
                if platform:
                    platforms.add(platform)

    if not platforms:
        logger.info("ai_audit_node: no platforms detected, skipping")
        return state

    logger.info("ai_audit_node: detected platforms=%s", sorted(platforms))
    inp = AiAuditInput(platforms=sorted(platforms))
    result = audit_tool.run(inp)
    if result.success:
        logger.info(
            "ai_audit_node: OK — high_risk=%s overall=%s",
            result.data.get("high_risk_count", 0),
            result.data.get("overall_risk", "?"),
        )
    else:
        logger.error("ai_audit_node: FAILED — %s", result.error)
    return state.model_copy(update={"ai_audit_result": result})


def dehashed_node(state: PipelineState) -> PipelineState:
    """Search DeHashed for breach records containing plaintext passwords,
    hashed passwords, usernames, phone numbers, and physical addresses.

    Complements HIBP: where HIBP shows breach metadata, DeHashed surfaces
    the actual record contents — filling the physical data gap when broker
    scanning returns nothing.

    Skips gracefully if DEHASHED_EMAIL or DEHASHED_API_KEY are not set.
    """
    from tools import dehashed as dehashed_tool

    primary = next(
        (c for c in state.classifications if c.type == "email"),
        None,
    )
    if not primary:
        logger.info("dehashed_node: no email input, skipping")
        return state

    result = dehashed_tool.run(primary.value)
    if result.success:
        d = result.data
        logger.info(
            "dehashed_node: OK — total=%d plaintext=%d hashed=%d addresses=%d usernames=%d",
            d.get("total", 0),
            d.get("plaintext_password_count", 0),
            d.get("hashed_password_count", 0),
            len(d.get("unique_addresses") or []),
            len(d.get("unique_usernames") or []),
        )
    else:
        logger.error("dehashed_node: FAILED — %s", result.error)
    return state.model_copy(update={"dehashed_result": result})


def whoxy_node(state: PipelineState) -> PipelineState:
    """Reverse WHOIS lookup — find all domains registered to this email.

    Surfaces business activity, old projects, company names (pivot to
    OpenCorporates), and physical addresses embedded in WHOIS registrant data.
    Expired domains are flagged as a risk finding (impersonation risk).

    Email inputs only. Skips gracefully if WHOXY_API_KEY is not set.
    """
    from tools import whoxy as whoxy_tool

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("whoxy_node: no email input, skipping")
        return state

    result = whoxy_tool.run(primary.value)
    if result.success:
        d = result.data
        logger.info(
            "whoxy_node: OK — total=%d active=%d expired=%d companies=%d",
            d.get("total_results", 0),
            d.get("active_domain_count", 0),
            d.get("expired_domain_count", 0),
            len(d.get("unique_company_names") or []),
        )
    else:
        logger.error("whoxy_node: FAILED — %s", result.error)
    return state.model_copy(update={"whoxy_result": result})


def phone_pivot_node(state: PipelineState) -> PipelineState:
    """Resolve carrier, line type, and location for phone number inputs.

    No-op for email/name/org inputs — runs only when a phone classification exists.
    Skips gracefully if NUMVERIFY_API_KEY is not set.
    """
    from tools import phone as phone_tool

    primary = next((c for c in state.classifications if c.type == "phone"), None)
    if not primary:
        logger.info("phone_pivot_node: no phone input, skipping")
        return state

    inp = PhoneInput(phone=primary.value)
    result = phone_tool.run(inp)
    if result.success:
        logger.info(
            "phone_pivot_node: OK — valid=%s line_type=%s carrier=%s location=%s",
            result.data.get("valid"),
            result.data.get("line_type"),
            (result.data.get("carrier") or {}).get("name", "unknown"),
            result.data.get("location"),
        )
    else:
        logger.error("phone_pivot_node: FAILED — %s", result.error)
    return state.model_copy(update={"phone_result": result})


def public_records_node(state: PipelineState) -> PipelineState:
    """Search CourtListener (federal cases) and OpenCorporates (corporate roles).

    Requires a resolved name — uses the same priority chain as broker_scan_node.
    Passes state location to narrow court results when available.
    Both APIs are free with no API key required for basic search.
    """
    from tools import public_records as pr_tool

    name = _resolve_name(state)
    if not name:
        logger.info("public_records_node: no name resolved, skipping")
        return state

    result = pr_tool.run(name, state=state.location_state)
    if result.success:
        logger.info(
            "public_records_node: OK — court_cases=%d corporate_records=%d",
            result.data.get("court_case_count", 0),
            result.data.get("corporate_record_count", 0),
        )
    else:
        logger.error("public_records_node: FAILED — %s", result.error)
    return state.model_copy(update={"public_records_result": result})


def _build_analysis_digest(state: PipelineState) -> str:
    """Build a compact text digest of scan results to send to the LLM.

    The full state dump can be 50-100KB with hundreds of raw tool records.
    A local 8B model given that much context is extremely slow and often
    produces garbled output. Instead we extract the signal: counts, names,
    severities, and a capped list of the most important findings.
    """
    lines: list[str] = []

    # ── Target ────────────────────────────────────────────────────────────────
    primary = state.classifications[0] if state.classifications else None
    if primary:
        lines.append(f"TARGET: {primary.value} (type={primary.type})")
    lines.append("")

    # ── HIBP breaches ─────────────────────────────────────────────────────────
    if state.hibp_result and state.hibp_result.success:
        d = state.hibp_result.data
        lines.append(f"HIBP BREACHES: {d.get('breach_count', 0)} total")
        for b in d.get("breaches") or []:
            name = b.get("name", "?")
            year = str(b.get("breach_date", ""))[:4]
            classes = (
                ", ".join((b.get("data_classes") or [])[:6]) or "unknown data types"
            )
            spam = " [spam list]" if b.get("is_spam_list") else ""
            lines.append(f"  - {name} ({year}): {classes}{spam}")
        lines.append("")

    # ── DeHashed breach records ───────────────────────────────────────────────
    if state.dehashed_result and state.dehashed_result.success:
        d = state.dehashed_result.data
        total = d.get("total", 0)
        if total:
            lines.append(
                f"DEHASHED: {total} breach records — "
                f"{d.get('plaintext_password_count', 0)} plaintext passwords, "
                f"{d.get('hashed_password_count', 0)} hashed passwords"
            )
            dbs = d.get("unique_databases") or []
            if dbs:
                lines.append(f"  Sources: {', '.join(dbs[:10])}")
            usernames = d.get("unique_usernames") or []
            if usernames:
                lines.append(f"  Usernames exposed: {', '.join(usernames[:10])}")
            addresses = d.get("unique_addresses") or []
            if addresses:
                lines.append(f"  Physical addresses: {', '.join(addresses[:5])}")
            phones = d.get("unique_phones") or []
            if phones:
                lines.append(f"  Phones in breach data: {', '.join(phones[:5])}")
            lines.append("")

    # ── Whoxy reverse WHOIS ───────────────────────────────────────────────────
    if state.whoxy_result and state.whoxy_result.success:
        d = state.whoxy_result.data
        total = d.get("total_results", 0)
        if total:
            active = d.get("active_domain_count", 0)
            expired = d.get("expired_domain_count", 0)
            lines.append(
                f"WHOXY REVERSE WHOIS: {total} domains registered — "
                f"{active} active, {expired} expired"
            )
            domains = d.get("domains") or []
            for dom in domains[:10]:
                expiry = dom.get("expiry_date", "")
                status = "active" if expiry >= datetime.now(timezone.utc).date().isoformat() else "EXPIRED"
                company = f" [{dom['registrant_company']}]" if dom.get("registrant_company") else ""
                lines.append(f"  - {dom['domain_name']} ({status}, expires {expiry}){company}")
            companies = d.get("unique_company_names") or []
            if companies:
                lines.append(f"  Company names in registrant data: {', '.join(companies[:5])}")
            addresses = d.get("unique_addresses") or []
            if addresses:
                lines.append(f"  Physical addresses: {', '.join(addresses[:3])}")
            if expired > 0:
                lines.append(f"  ⚠ {expired} expired domain(s) — impersonation/typosquat risk")
            lines.append("")

    # ── Holehe registrations ──────────────────────────────────────────────────
    if state.holehe_result and state.holehe_result.success:
        d = state.holehe_result.data
        found = [p.get("platform") for p in (d.get("platforms_found") or [])]
        lines.append(
            f"HOLEHE: {d.get('found_count', 0)} registrations found across {d.get('platforms_checked', 0)} platforms"
        )
        if found:
            lines.append(f"  Platforms: {', '.join(found[:20])}")
        lines.append("")

    # ── Blackbird accounts ────────────────────────────────────────────────────
    if state.blackbird_result and state.blackbird_result.success:
        d = state.blackbird_result.data
        accts = [
            (a.get("platform"), a.get("url")) for a in (d.get("accounts_found") or [])
        ]
        lines.append(f"BLACKBIRD: {d.get('found_count', 0)} accounts found")
        for platform, url in accts[:15]:
            lines.append(f"  - {platform}: {url}")
        lines.append("")

    # ── Maigret username profiles ─────────────────────────────────────────────
    if state.sherlock_result and state.sherlock_result.success:
        d = state.sherlock_result.data
        profiles = [
            (p.get("platform"), p.get("url")) for p in (d.get("profiles_found") or [])
        ]
        lines.append(
            f"MAIGRET: {d.get('found_count', 0)} profiles across {d.get('platforms_checked', 0)} platforms"
        )
        for platform, url in profiles[:20]:
            lines.append(f"  - {platform}: {url}")
        lines.append("")

    # ── GHunt ─────────────────────────────────────────────────────────────────
    if state.ghunt_result and state.ghunt_result.success:
        d = state.ghunt_result.data
        if d.get("found"):
            lines.append("GHUNT: Google account found")
            lines.append(f"  Name: {d.get('name', 'unknown')}")
            lines.append(f"  Services: {', '.join(d.get('google_services', []))}")
        else:
            lines.append("GHUNT: not run (no credentials)")
        lines.append("")

    # ── Broker scan ───────────────────────────────────────────────────────────
    if state.broker_result and state.broker_result.success:
        d = state.broker_result.data
        lines.append(
            f"DATA BROKERS: {d.get('brokers_found_count', 0)} brokers, exposure score {d.get('exposure_score', 0)}/100"
        )
        for b in (d.get("brokers_found") or [])[:8]:
            lines.append(
                f"  - {b.get('broker_name')}: {b.get('data_types_exposed', [])}"
            )
        lines.append("")

    # ── SpiderFoot ────────────────────────────────────────────────────────────
    if state.spiderfoot_result and state.spiderfoot_result.success:
        d = state.spiderfoot_result.data
        elements = d.get("elements") or []
        by_type: dict = defaultdict(list)
        for el in elements:
            val = (el.get("data") or "").strip()
            if val:
                by_type[el.get("type", "UNKNOWN")].append(val)

        # Exclude noisy/low-signal types that the LLM misreads as physical addresses
        SKIP_TYPES = {"RAW_RIR_DATA", "GEOINFO", "COUNTRY_NAME", "PROVIDER_TELCO",
                      "PHONE_PREFIX_OWNED", "NETBLOCK_OWNER", "BGP_AS_OWNER"}
        lines.append(f"SPIDERFOOT: {d.get('element_count', 0)} elements")
        for etype, vals in list(by_type.items())[:10]:
            if etype in SKIP_TYPES:
                continue
            # Skip values that are just short codes (e.g. "us", "md", "511")
            clean = [v for v in vals if len(v) > 4]
            if clean:
                lines.append(f"  {etype}: {', '.join(clean[:5])}")
        lines.append("")

    # ── AI audit ─────────────────────────────────────────────────────────────
    if state.ai_audit_result and state.ai_audit_result.success:
        d = state.ai_audit_result.data
        lines.append(
            f"AI PLATFORM EXPOSURE: {d.get('high_risk_count', 0)} high-risk, overall={d.get('overall_risk', 'unknown')}"
        )
        for p in d.get("platforms_found") or []:
            lines.append(
                f"  - {p.get('platform')}: risk={p.get('risk_level')} data_known={p.get('data_known', [])}"
            )
        lines.append("")

    # ── Shodan infrastructure ─────────────────────────────────────────────────
    if state.shodan_result and state.shodan_result.success:
        d = state.shodan_result.data
        lines.append(
            f"SHODAN: {d.get('ips_checked', 0)} IPs checked, "
            f"{d.get('total_open_ports', 0)} open ports, "
            f"{d.get('total_vulns', 0)} CVEs"
        )
        for h in (d.get("hosts") or [])[:5]:
            vulns = h.get("vulns", [])
            ports = h.get("ports", [])
            lines.append(f"  - {h['ip']}: ports={ports} vulns={vulns}")
        lines.append("")

    # ── Phone pivot ───────────────────────────────────────────────────────────
    if state.phone_result and state.phone_result.success:
        d = state.phone_result.data
        if d.get("valid"):
            carrier = (d.get("carrier") or {}).get("name", "unknown")
            voip_flag = " ⚠ VoIP/anonymous number" if d.get("is_voip") else ""
            geocode = d.get("geocode") or d.get("location") or "unknown"
            tz = ", ".join(d.get("timezone") or []) or "unknown"
            lines.append(
                f"PHONE: valid=true line_type={d.get('line_type','unknown')}{voip_flag} "
                f"carrier={carrier} location={geocode} timezone={tz} "
                f"country={d.get('country_code','')}"
            )
            lines.append("")

    # ── Public records ────────────────────────────────────────────────────────
    if state.public_records_result and state.public_records_result.success:
        d = state.public_records_result.data
        n_cases = d.get("court_case_count", 0)
        n_corp = d.get("corporate_record_count", 0)
        if n_cases or n_corp:
            lines.append(
                f"PUBLIC RECORDS: {n_cases} court cases, {n_corp} corporate records"
            )
            for case in (d.get("court_cases") or [])[:5]:
                lines.append(
                    f"  COURT: {case.get('case_name')} | {case.get('court')} | "
                    f"filed={case.get('date_filed')} | {case.get('nature_of_suit')}"
                )
            for rec in (d.get("corporate_records") or [])[:5]:
                lines.append(
                    f"  CORP: {rec.get('company_name')} | role={rec.get('role')} | "
                    f"jurisdiction={rec.get('jurisdiction')} | status={rec.get('status')}"
                )
            lines.append("")


    # ── Correlation follow-up results ─────────────────────────────────────────
    if state.correlation_results:
        lines.append(
            f"CORRELATION PIVOTS: {len(state.correlation_results)} follow-up results"
        )
        for r in state.correlation_results:
            if not r.success:
                continue
            if r.tool == "maigret":
                found = r.data.get("found_count", 0)
                lines.append(
                    f"  USERNAME PIVOT ({r.input_value}): {found} accounts found"
                )
                for site in (r.data.get("sites_found") or [])[:5]:
                    lines.append(f"    - {site.get('name')}: {site.get('url','')}")
            elif r.tool == "public_records":
                lines.append(
                    f"  NAME PIVOT ({r.input_value}): "
                    f"{r.data.get('court_case_count',0)} court cases, "
                    f"{r.data.get('corporate_record_count',0)} corporate records"
                )
            elif r.tool == "shodan_scan":
                lines.append(
                    f"  IP PIVOT ({r.input_value}): "
                    f"{r.data.get('total_open_ports',0)} open ports, "
                    f"{r.data.get('total_vulns',0)} CVEs"
                )
            elif r.tool == "phone_lookup":
                carrier = (r.data.get("carrier") or {}).get("name", "unknown")
                voip_tag = " [VoIP]" if r.data.get("is_voip") else ""
                geocode = r.data.get("geocode") or r.data.get("location") or "?"
                lines.append(
                    f"  PHONE PIVOT ({r.input_value}): "
                    f"{r.data.get('line_type','?')}{voip_tag} via {carrier}, "
                    f"location={geocode}"
                )
            elif r.tool == "hibp":
                lines.append(
                    f"  EMAIL PIVOT/HIBP ({r.input_value}): "
                    f"{r.data.get('breach_count',0)} breaches"
                )
            elif r.tool == "holehe":
                lines.append(
                    f"  EMAIL PIVOT/HOLEHE ({r.input_value}): "
                    f"{r.data.get('found_count',0)} accounts"
                )
        lines.append("")

    return "\n".join(lines)


def _run_concurrent(
    state: PipelineState,
    fns: list,
) -> PipelineState:
    """Run node functions concurrently and merge their state updates.

    Each function receives the *same* input state (safe because Wave 1 functions
    are fully independent).  Results are diff'd against the original state and
    merged — if two functions somehow touch the same field the last one wins,
    but in practice each tool writes to its own dedicated result field.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    updates: dict = {}
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = {
            pool.submit(fn, state): getattr(fn, "__name__", str(fn)) for fn in fns
        }
        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                result_state = future.result()
                # Extract only the fields that changed
                for field in PipelineState.model_fields:
                    new_val = getattr(result_state, field)
                    old_val = getattr(state, field)
                    if new_val is not old_val and new_val != old_val:
                        updates[field] = new_val
                        logger.debug(
                            "_run_concurrent: %s updated field=%s", fn_name, field
                        )
            except Exception as exc:
                logger.error("_run_concurrent: %s raised — %s", fn_name, exc)

    return state.model_copy(update=updates) if updates else state


def wave1_scan_node(state: PipelineState) -> PipelineState:
    """Run all input-only tools concurrently.

    These tools only need state.classifications — they have no dependencies on
    each other.  Running them in parallel reduces elapsed time from the sum of
    their runtimes to roughly the slowest single tool (usually SpiderFoot).

    Wave 1: breach_check, dehashed, whoxy, phone_pivot, surface_map, holehe,
            blackbird, maigret, ghunt
    """
    logger.info("wave1_scan_node: starting 9 tools in parallel")
    result = _run_concurrent(
        state,
        [
            breach_check_node,
            dehashed_node,
            whoxy_node,
            phone_pivot_node,
            surface_map_node,
            holehe_node,
            blackbird_node,
            maigret_node,
            ghunt_node,
        ],
    )
    logger.info("wave1_scan_node: all tools complete")
    return result


def wave2_scan_node(state: PipelineState) -> PipelineState:
    """Run tools that depend on Wave 1 results, concurrently.

    These tools need at least one Wave 1 result (GHunt name, SpiderFoot IPs,
    Holehe/Blackbird platform lists) but are independent of each other.

    Wave 2: broker_scan, shodan, public_records, ai_audit
    """
    logger.info("wave2_scan_node: starting 4 tools in parallel")
    result = _run_concurrent(
        state,
        [
            broker_scan_node,
            shodan_node,
            public_records_node,
            ai_audit_node,
        ],
    )
    logger.info("wave2_scan_node: all tools complete")
    return result


def correlation_planner_node(state: PipelineState) -> PipelineState:
    """Ask Ollama to identify follow-up pivots based on current scan findings.

    Sends the compact digest to the LLM and parses a JSON list of up to 5 pivots.
    Each pivot has: type (name/ip/username/phone/email), value, source, reason.
    Skips gracefully in TEST_MODE and on any LLM/parse failure.
    """
    logger.info("correlation_planner_node: asking Ollama to plan follow-up pivots")

    if config.is_test_mode():
        # In test mode inject one deterministic pivot so the execute node is exercised
        plan = [
            {
                "type": "username",
                "value": "jdoe92",
                "source": "holehe_result",
                "reason": "Username found on multiple platforms — check full account footprint",
            }
        ]
        return state.model_copy(update={"correlation_plan": plan})

    digest = _build_analysis_digest(state)
    if not digest.strip():
        logger.info("correlation_planner_node: empty digest, skipping correlation")
        return state

    try:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(  # type: ignore[call-arg]
            model="llama3.1:8b",
            base_url=config.get("OLLAMA_HOST"),
            temperature=0,
            request_timeout=120,
            num_ctx=4096,    # CORRELATION_PROMPT + digest fits comfortably
            num_predict=512, # small JSON array of ≤5 pivots
        )
        response = llm.invoke([("system", CORRELATION_PROMPT), ("human", digest)])
        raw = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )

        # Strip markdown fences
        stripped = raw.strip()
        if stripped.startswith("```"):
            stripped = stripped.split("\n", 1)[-1].rsplit("```", 1)[0]
        stripped = stripped.strip()

        # Attempt JSON parse with progressive repair for common LLM quirks
        data = _parse_json_tolerant(stripped)
        pivots: list[dict] = data.get("pivots") or []

        # Validate type and value presence
        valid_types = {"name", "ip", "username", "phone", "email"}
        pivots = [
            p
            for p in pivots
            if isinstance(p, dict) and p.get("type") in valid_types and p.get("value")
        ]

        # Reject hallucinated placeholder values the LLM invents even when told not to
        def _is_real_value(pivot: dict) -> bool:
            v = (pivot.get("value") or "").strip()
            t = pivot.get("type", "")
            if not v:
                return False
            # Phone: reject obvious fakes — sequential digits, all same digit, too short
            if t == "phone":
                digits = re.sub(r"\D", "", v)
                if len(digits) < 10:
                    return False
                if re.match(r"^(\d)\1+$", digits):      # all same digit: 1111111111
                    return False
                if re.match(r"^1?234567890?$", digits):  # 1234567890 placeholder
                    return False
            # IP: reject private/loopback/unspecified ranges
            if t == "ip":
                private = (
                    v.startswith("192.168.")
                    or v.startswith("10.")
                    or v.startswith("172.")
                    or v in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "localhost")
                    or re.match(r"^0\.0\.", v)
                )
                if private:
                    return False
            # Name: reject obvious placeholders
            if t == "name":
                if v.lower() in ("<name>", "unknown", "n/a", "target", "person"):
                    return False
            return True

        pivots = [p for p in pivots if _is_real_value(p)][:5]

        logger.info(
            "correlation_planner_node: planned %d pivots: %s",
            len(pivots),
            [(p["type"], p["value"]) for p in pivots],
        )
        return state.model_copy(update={"correlation_plan": pivots})

    except Exception as exc:
        logger.warning(
            "correlation_planner_node: failed (%s) — skipping correlation", exc
        )
        return state


def correlation_execute_node(state: PipelineState) -> PipelineState:
    """Execute each planned pivot sequentially and collect results.

    Deduplicates against already-completed work so we never re-query
    a value the initial scan already covered (e.g. the original email).
    Results are stored in state.correlation_results and included in the
    analysis digest so the LLM's final risk score reflects them.
    """
    if not state.correlation_plan:
        logger.info("correlation_execute_node: no pivots planned, skipping")
        return state

    logger.info(
        "correlation_execute_node: executing %d pivots", len(state.correlation_plan)
    )

    # Build a set of (type, value) pairs already covered by the initial scan
    already_done: set[tuple[str, str]] = set()
    for c in state.classifications:
        already_done.add((c.type, c.value.lower()))

    results: list[ToolResult] = []

    for pivot in state.correlation_plan:
        ptype = pivot.get("type", "")
        pvalue = (pivot.get("value") or "").strip()
        if not pvalue:
            continue

        key = (ptype, pvalue.lower())
        if key in already_done:
            logger.info("correlation: skipping %s=%s (already covered)", ptype, pvalue)
            continue
        already_done.add(key)

        logger.info(
            "correlation: running pivot type=%s value=%s reason=%s",
            ptype,
            pvalue,
            pivot.get("reason", ""),
        )

        try:
            if ptype == "username":
                from models.maigret import MaigretInput
                from tools import maigret as maigret_tool

                result = maigret_tool.run(MaigretInput(username=pvalue))
                results.append(result)

            elif ptype == "name":
                from tools import public_records as pr_tool

                result = pr_tool.run(pvalue, state=state.location_state)
                results.append(result)

            elif ptype == "ip":
                from models.shodan import ShodanInput
                from tools import shodan as shodan_tool

                result = shodan_tool.run(ShodanInput(ip=pvalue))
                results.append(result)

            elif ptype == "phone":
                from models.phone import PhoneInput
                from tools import phone as phone_tool

                result = phone_tool.run(PhoneInput(phone=pvalue))
                results.append(result)

            elif ptype == "email":
                from models.hibp import HibpInput
                from models.holehe import HoleheInput
                from tools import hibp as hibp_tool
                from tools import holehe as holehe_tool

                hibp_result = hibp_tool.run(HibpInput(input_type="email", value=pvalue))
                results.append(hibp_result)
                holehe_result = holehe_tool.run(HoleheInput(email=pvalue))
                results.append(holehe_result)

            else:
                logger.warning("correlation: unknown pivot type %s, skipping", ptype)
                continue

        except Exception as exc:
            logger.error(
                "correlation: pivot type=%s value=%s FAILED — %s", ptype, pvalue, exc
            )

    logger.info("correlation_execute_node: collected %d results", len(results))
    return state.model_copy(update={"correlation_results": results})


def analysis_node(state: PipelineState) -> PipelineState:
    logger.info("analysis_node: synthesizing results with Ollama")

    if config.is_test_mode():
        fixture_path = (
            Path(__file__).parent.parent
            / "tests"
            / "fixtures"
            / "analysis_response.json"
        )
        analysis = json.loads(fixture_path.read_text())
        return state.model_copy(update={"analysis_result": analysis})

    # Build a compact digest — sending the full state dump (50-100KB) to a local
    # 8B model makes inference extremely slow. Instead we extract only the signal.
    digest = _build_analysis_digest(state)

    try:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(  # type: ignore[call-arg]
            model="llama3.1:8b",
            base_url=config.get("OLLAMA_HOST"),
            temperature=0,
            request_timeout=300,  # 5 min hard cap
            num_ctx=8192,         # ANALYSIS_PROMPT alone is ~2300 tokens; default 2048 truncates the prompt
            num_predict=4096,     # full remediation + findings_context JSON needs ~2000-3000 tokens
        )
        messages = [
            ("system", ANALYSIS_PROMPT),
            ("human", digest),
        ]
        response = llm.invoke(messages)
        raw_text = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
        logger.debug("analysis_node: raw response length=%d", len(raw_text))

        # Strip markdown code fences if the model wrapped the JSON
        stripped = raw_text.strip()
        if stripped.startswith("```"):
            stripped = stripped.split("\n", 1)[-1]
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()

        if not stripped:
            raise json.JSONDecodeError("empty response from model", "", 0)

        analysis = json.loads(stripped)
        # Validate schema but don't discard the result if fields are missing —
        # the report uses analysis as a raw dict and handles missing keys with .get()
        try:
            AnalysisResult(**analysis)
        except Exception as val_exc:
            logger.warning(
                "analysis_node: schema mismatch (continuing anyway): %s", val_exc
            )
        # Enrich findings_context with real URLs from the static privacy DB.
        # The LLM is instructed to set how_to_remove=null; we inject verified
        # deletion URLs + correct legal frameworks here.
        findings = analysis.get("findings_context")
        if isinstance(findings, list):
            from tools.privacy_url_lookup import enrich_findings_context

            analysis["findings_context"] = enrich_findings_context(findings)
        return state.model_copy(update={"analysis_result": analysis})

    except json.JSONDecodeError as exc:
        logger.error("analysis_node: failed to parse Ollama JSON response: %s", exc)
        error_result: dict = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": "Analysis failed — could not parse model response.",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})
    except Exception as exc:
        logger.error("analysis_node: unexpected error: %s", exc)
        error_result = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": f"Analysis failed: {exc}",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})


def report_node(state: PipelineState) -> PipelineState:
    from agent.report import write_report

    report_path = write_report(state)
    return state.model_copy(update={"report_path": report_path})
