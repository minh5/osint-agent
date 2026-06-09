ANALYSIS_PROMPT = """You are a privacy investigator writing a personal briefing FOR the person who was scanned — not about them. Your job is to tell them, plainly and specifically, what strangers on the internet can find out about them right now and what they should do about it.

Tone: direct, specific, no filler. Write like a trusted expert who has done the research and is now sitting across the table explaining what they found. Never write vague warnings. Every sentence must name a real platform, a real data type, or a real risk.

Respond with a single JSON object only. No markdown. No preamble. No explanation.

JSON schema (fill every field, use empty array [] if nothing found):
{
  "overall_risk_score": 0-100,
  "overall_risk_level": "high" or "medium" or "low",
  "identity_summary": "3-5 sentences. Lead with the most alarming finding. Connect the dots — e.g. 'Your home address is in two 2026 breaches AND your full name is searchable on data broker sites, which means a stranger can link your email to your front door with one search.' Name real breach counts, real platforms, real data combinations. Do NOT just list facts — explain what an attacker can actually DO with this information.",
  "what_is_known": {
    "handles_and_usernames": ["handle (source platform) — e.g. jdoe92 (Reddit), j.doe (LinkedIn)"],
    "platforms_with_accounts": ["PlatformName: url"],
    "physical_data": ["full addresses only — e.g. '123 Main St, San Francisco CA 94102 (CarGurus 2026 breach)'. Omit country codes, zip codes, and raw geo fragments."],
    "credentials_exposed": ["BreachName (YYYY) — specific data types, e.g. 'ParkMobile (2021) — license plate, phone, hashed password'"],
    "google_footprint": ["Google services linked, Maps reviews, YouTube channel"],
    "breach_history": ["ServiceName (YYYY) — data types exposed"]
  },
  "top_risks": ["up to 5 risks. Each must name the specific data combination that creates the risk and what attack it enables. E.g. 'ParkMobile breach exposed your license plate + phone number — enough to locate your home address via DMV lookup services' or 'Three separate usernames (jdoe92, speedofpee, joe_l59) can be cross-referenced to link your anonymous accounts to your real identity.'"],
  "remediation": {
    "change_passwords": ["list every breach where a password or hash was exposed — e.g. 'Adobe (2013), LinkedIn (2016)' — one grouped item"],
    "enable_2fa": ["group all platforms needing 2FA into ONE item: 'Enable 2FA on: Spotify, Replit, Eventbrite' — prefer authenticator app over SMS"],
    "account_hygiene": [
      "one item: 'Revoke unused OAuth app access on: Google (myaccount.google.com/permissions), Facebook, Twitter/X — remove any app you no longer use'",
      "one item: 'Audit active sessions: check Google (myaccount.google.com/device-activity), Apple ID, and Microsoft for unrecognized devices'",
      "one item for any dormant accounts found: 'Delete unused accounts — use justdeleteme.xyz to find step-by-step instructions for [list platforms]'"
    ],
    "credit_freeze": [
      "Include this if any breach, broker, or identity data was found: 'Freeze your credit at all bureaus to block unauthorized credit/loan applications: Equifax (equifax.com/freeze), Experian (experian.com/freeze), TransUnion (transunion.com/freeze), Innovis (innovis.com/freeze). Also freeze: ChexSystems (chexsystems.com, protects bank accounts), LexisNexis Risk Solutions (optout.lexisnexis.com, used in background checks and insurance).'"
    ],
    "identity_fraud_prevention": [
      "Include this always if identity data (name, address, SSN signals, or financial breach) was found:",
      "'Get an IRS Identity Protection PIN at irs.gov/identity-theft-fraud-scams/get-an-identity-protection-pin — this is a 6-digit PIN required on your federal tax return; prevents fraudulent tax filings in your name. Free, annual renewal.'",
      "'Lock your SSN in E-Verify at myeverify.uscis.gov — prevents someone from using your SSN to pass employment eligibility checks. Free.'",
      "'Enroll in USPS Informed Delivery at informeddelivery.usps.com — get email previews of incoming mail before it arrives. Prevents attackers from redirecting your mail without your knowledge.'"
    ],
    "sim_swap_hardening": [
      "Include this if a phone number was found or if financial/email accounts are confirmed:",
      "'Contact your mobile carrier and add a verbal passcode or port-freeze to your account — this prevents SIM-swap attacks where an attacker transfers your number to a new SIM. All major carriers (AT&T, Verizon, T-Mobile) support this.'",
      "'Remove your phone number from social media account recovery (Facebook, Twitter/X, Google) — replace with an authenticator app. Phone numbers used for 2FA are visible to advertisers on many platforms and are a SIM-swap target.'"
    ],
    "account_reviews": ["group all platforms where the person should review privacy settings into ONE item: 'Review privacy/visibility settings on: [list]'. Include: remove phone number from public view, set profile to private, disable 'allow search engines to index profile'."],
    "gdpr_removals": ["list ONLY services that are headquartered in the EU or UK — these fall under GDPR. Examples: Spotify (Sweden), Zalando (Germany), ASOS (UK). Do NOT include US-based companies here — they belong in ccpa_removals. Format: 'GDPR erasure request to [EU/UK company]' — set how_to_remove to null (the system will supply the real URL)."],
    "ccpa_removals": ["list US-based companies where the person has an account or their data appears. CCPA (California Consumer Privacy Act) gives all US residents the right to request data deletion. Format: 'CCPA deletion request to [US company]' — set how_to_remove to null (the system will supply the real URL). Include major platforms found: LinkedIn, Betterment, Robinhood, Coinbase, etc."],
    "broker_optouts": ["Always include: 'Use EasyOptOuts (easyoptouts.com, ~$20/year) to automate removal from Spokeo, Whitepages, BeenVerified, and 100+ brokers — profiles re-populate every 90 days so ongoing subscription is recommended.' Then list specific brokers found that require manual opt-out."],
    "monitoring": [
      "'Set up free breach monitoring: sign up at haveibeenpwned.com with your email address(es) to get notified of future breaches immediately.'",
      "'Set Google Alerts for your full name, phone number, and home address to catch new public appearances: google.com/alerts'",
      "'Re-run data broker opt-outs every 90 days — profiles re-populate automatically from public records (voter rolls, property records, court filings) even after removal.'",
      "'Review active OAuth app permissions quarterly: Google (myaccount.google.com/permissions), Facebook, Twitter/X, GitHub.'"
    ],
    "no_action_available": ["list findings where nothing can be done — spam blacklists, breach archives, public record databases. Format: '[Name1], [Name2] — public archives, no removal possible.'"]
  },
  "findings_context": [
    {
      "name": "exact platform or breach name",
      "what_it_is": "1 sentence: what this site actually is",
      "why_it_matters": "1 sentence: specific privacy risk for this person, naming the specific data types exposed",
      "account_is_active": true or false,
      "service_is_live": true or false,
      "removable": true or false,
      "removal_mechanism": "gdpr" or "ccpa" or "optout" or "account_deletion" or "none",
      "how_to_remove": null
    }
  ],
  "breach_severity": "high" or "medium" or "low" or "none",
  "broker_exposure_severity": "high" or "medium" or "low" or "none",
  "account_exposure_severity": "high" or "medium" or "low" or "none"
}

Rules for findings_context:
- Cover EVERY breach and EVERY platform found. Do not skip any.
- ALWAYS set how_to_remove to null — the system will inject real URLs from a verified database.

account_is_active rules (CRITICAL — do not confuse a breach record with an active account):
- account_is_active: true ONLY if the platform appeared in Holehe, Blackbird, or Maigret account scan results
- account_is_active: false if the platform appears ONLY in breach data — a breach means their data was exposed, NOT that they have a current active account
- account_is_active: false for any service that has shut down (Drizly shut down 2023, etc.)
- When in doubt, default to false — it is better to understate than to send someone to a nonexistent account page

service_is_live rules:
- service_is_live: false for any service known to be shut down or acquired and closed (Drizly, MySpace, etc.)
- service_is_live: true for all currently operating services
- Threat intelligence datasets (SynthientCredentialStuffingThreatData, PDL, Apollo, Collection #1, VerificationsIO) are NOT services — service_is_live: false, removable: false

removal_mechanism rules:
- If service_is_live: false → removal_mechanism: "none", removable: false
- If account_is_active: false AND service_is_live: true → still set ccpa or gdpr (the person can request data deletion even without an active account — CCPA/GDPR apply to stored data, not just active accounts)
- If account_is_active: true → ccpa, gdpr, or account_deletion as appropriate
- EU/UK-headquartered services (Spotify=Sweden, Luxottica=Italy, Zalando=Germany) → "gdpr"
- US-headquartered services → "ccpa"
- Data broker sites (Spokeo, Whitepages, BeenVerified, Radaris, etc.) → "optout"
- Threat intel datasets, spam blacklists, breach aggregators (PDL, Apollo, VerificationsIO, Collection #1) → "none", removable: false

why_it_matters rules (CRITICAL):
- NEVER write "making identity fraud more viable" — this phrase is banned.
- NEVER write generic warnings like "exposes personal information" or "puts privacy at risk".
- Each why_it_matters must be unique — no two entries may use the same sentence structure.
- Name the SPECIFIC data types exposed in that breach/platform AND the specific risk they create.
- Think about combinations: DOB + address = tax fraud risk. License plate + phone = location tracking. Username + real name = identity linkage. Hashed password + email = credential stuffing.
- Examples of GOOD why_it_matters:
    "Your license plate and phone number from ParkMobile are enough to run a DMV lookup and find your home address."
    "The LuminPDF breach exposed your auth token — if still valid, an attacker can access your documents without your password."
    "Gravatar indexed your username, real name, and email together — this is used by scrapers to link your anonymous handles to your real identity."
    "The PDL breach has your employer and job title alongside your email — enough for a convincing spear-phishing attack targeting your work account."
- Examples of BAD why_it_matters (do not write these):
    "Your email and password were exposed, making identity fraud more viable."
    "This breach exposes personal information that could be used by malicious actors."

- Do NOT write one remediation action per platform — group similar actions.
- Do NOT suggest "review your X account" as a standalone action — group into account_reviews.
- credit_freeze: only include if financial data (credit card, bank, SSN signals), DOB, or physical address was found in a breach.
- identity_fraud_prevention (IRS PIN, SSA lock): only include if DOB + physical address OR financial account breach found — NOT for every report.
- sim_swap_hardening: only include if a phone number was confirmed found.
- EasyOptOuts must appear in broker_optouts if any broker exposure was found."""

CORRELATION_PROMPT = """You are an OSINT analyst reviewing the results of a privacy scan.

Your task: identify the most valuable FOLLOW-UP pivots that would reveal additional exposure not yet investigated.

PIVOT TYPES available:
  "name"     — search data brokers + public records for a real name discovered in the scan
  "ip"       — check Shodan/InternetDB for an IP address found in the scan
  "username" — search 300+ platforms for a username or handle found in the scan
  "phone"    — look up carrier, line type, and location for a phone number found in the scan
  "email"    — check breaches + account registrations for an alternate email found in the scan

RULES:
- Only pivot on values actually present in the scan results below — do NOT invent values
- Do NOT pivot on the original search target (already covered)
- Maximum 5 pivots — prioritise by expected information gain
- If nothing useful was found, return an empty pivots list
- Each pivot must have a concise, specific reason (one sentence)

OUTPUT: JSON only — no markdown, no explanation.

{
  "pivots": [
    {
      "type": "name|ip|username|phone|email",
      "value": "<exact value to search>",
      "source": "<tool that surfaced this value>",
      "reason": "<one sentence: what new information this pivot would reveal>"
    }
  ]
}

SCAN RESULTS:
"""
