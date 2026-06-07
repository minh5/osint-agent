# Privacy OSINT Agent

## Purpose
Local privacy audit tool. Runs OSINT tools against a target identity
(email / phone / name / org), analyzes results using a local Ollama model,
and produces a privacy risk report. No data leaves the machine except to
the explicitly defined external API endpoints listed below.

## Stack
- Python 3.12
- LangChain + LangGraph for pipeline orchestration
- Ollama (llama3.1:8b) — local inference, runs in Docker
- SpiderFoot — broad OSINT, runs in Docker
- uv for package management
- pytest for testing
- Docker + docker-compose for all service management

---

## Running the Tool

### One command
```bash
./bin/run.sh "target@email.com"
./bin/run.sh "John Smith"
./bin/run.sh "+14155550100"
```

`bin/run.sh` handles everything: starts SpiderFoot and Ollama if not running,
waits for both to report healthy via Docker healthchecks, pulls the model if
missing, builds the agent image if needed, then fires the scan.

### Environment check
```bash
./bin/check.sh
```

### GHunt one-time login (optional)
```bash
docker compose run --rm agent ghunt login
```

---

## Docker Architecture

Three services defined in `docker-compose.yml`:

| Service | Image | Port | Role |
|---------|-------|------|------|
| spiderfoot | spiderfoot | 5001 | Long-lived OSINT scanner |
| ollama | ollama/ollama | 11434 | Long-lived local LLM |
| agent | osint-agent (built locally) | — | Fire-and-forget scan runner |

- `spiderfoot` and `ollama` use `restart: unless-stopped` — start once, stay up
- `agent` uses `profiles: [run]` — only starts via `docker compose run --rm agent`
- `agent` has `depends_on: service_healthy` for both services
- Ollama uses `init: true` to reap zombie subprocesses spawned during inference
- SpiderFoot healthcheck uses `python3 urllib` (no curl in that image)
- Ollama healthcheck uses `ollama list`
- `bin/run.sh` uses `--no-deps` on `docker compose run` — services already verified healthy in pre-flight, no need for compose to touch them again

### Volumes
- `ollama_models` — persists downloaded models across container restarts
- `ghunt_creds` — persists GHunt auth token (`~/.malfrats/ghunt/creds.m`)
- `./output` — bind-mounted so reports land on the host at `./output/`

---

## Prerequisites

### Required — will fail loudly without these
1. **Docker Desktop** — `docker info` must succeed
2. **`.env` file** — copy `.env.example`, fill all required vars

### Required API keys (`.env`)
```
HIBP_API_KEY=        # haveibeenpwned.com/API/Key — $3.50/month
APIFY_API_TOKEN=     # apify.com → Settings → API Tokens (free tier ok)
APIFY_ACTOR_ID=      # "TruePeopleSearch Contact Finder" actor ID from Apify Store
SCRAPFLY_API_KEY=    # scrapfly.io (used by Holehe internals)
```

### Optional
```
LEAKRADAR_API_KEY=   # leakradar.io — if empty, LeakRadar step is skipped gracefully
```

### Automatic (set by docker-compose, not .env)
```
SPIDERFOOT_HOST=http://spiderfoot:5001
OLLAMA_HOST=http://ollama:11434
```

### Removed — do not add back
- ~~Google Custom Search API~~ — closed to new customers as of early 2026
- ~~EasyOptOuts API~~ — tool outputs the dashboard link only, no integration

---

## Pipeline

```
intake_node
  → breach_check_node     # HIBP
  → broker_scan_node      # Apify TruePeopleSearch (name inputs only)
  → surface_map_node      # SpiderFoot
  → holehe_node           # 121 platforms via password-reset probing
  → leakradar_node        # credential leak search (skipped if no key)
  → blackbird_node        # 600+ platforms via email
  → maigret_node          # 3155 platforms via username
  → ghunt_node            # Google account intel (skipped if no creds)
  → ai_audit_node         # derives platform list from scan results, checks data policies
  → analysis_node         # Ollama synthesizes into identity profile
  → report_node           # writes markdown + JSON to output/
```

**Important:** `analysis_node` is the only node that passes data to Ollama.
All other nodes are deterministic Python with no LLM involvement.

---

## Tools

### tools/hibp.py
HIBP API v3. Email inputs only (phone not supported by HIBP v3).
`GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}`
Header: `hibp-api-key`. Returns `HibpOutput` with breach list.
HIBP returns PascalCase JSON — use `alias_generator=to_pascal` + `model_validate()`.
Spam-list-only entries return only `Name` field; all other fields are optional with defaults.

### tools/spiderfoot.py
SpiderFoot HTTP API at `SPIDERFOOT_HOST`.
Restricted module list only (8 modules) — full scan takes 30+ mins:
`sfp_hibp, sfp_emailrep, sfp_hunter, sfp_whois, sfp_pgp, sfp_gravatar, sfp_social, sfp_pastebin`
Polls scan status every few seconds until FINISHED.
`POLL_TIMEOUT = 300` (5 minutes hard cap).

### tools/broker_scan.py
Name inputs only — email/phone return empty `BrokerScanOutput` (skip gracefully).
Uses Apify actor client. Access run fields as attributes (`run.id`, `run.status`,
`run.default_dataset_id`) — not `.get()`, it's a Pydantic object not a dict.
Google CSE completely removed — API closed to new customers.

### tools/holehe.py
Uses `holehe` Python library directly (async).
Checks 121 platforms via password-reset flow.
Returns platforms where the email has a registered account.

### tools/leakradar.py
REST API: `POST https://api.leakradar.io/search/email`
Bearer token auth. Skipped gracefully if `LEAKRADAR_API_KEY` is empty.

### tools/blackbird.py
Subprocess call to Blackbird (cloned to `/opt/blackbird` in Docker image at build time).
`PYTHONPATH=src`, parses JSON output from `results/` directory.
600+ platforms checked by email.
Do not add a `vendor/blackbird` directory — Blackbird is baked into the image.

### tools/maigret.py
Uses `maigret.checking.maigret` async function directly (Python library, not subprocess).
Loads `MaigretDatabase` from bundled `data.json` (3155 sites).
Username derived from email prefix (e.g. `minh.v.mai` from `minh.v.mai@gmail.com`).
Suppresses maigret's own logging (set to CRITICAL).

### tools/ghunt.py
Subprocess `ghunt` CLI. Requires one-time `ghunt login` to write credentials to
`~/.malfrats/ghunt/creds.m` (persisted in `ghunt_creds` Docker volume).
Skipped gracefully if credentials file is missing.

### tools/ai_audit.py
Dynamic — derives platform list from actual scan results:
`blackbird_result` accounts + `holehe_result` registrations + SpiderFoot SOCIAL_MEDIA elements.
Checks those platforms against `data/ai_policies.json` policy database.
NOT a static list — reflects what was actually found in the scan.

---

## Analysis Node

Sends a **compact digest** to Ollama, not the full state dump.
`_build_analysis_digest(state)` in `nodes.py` extracts signal only:
breach names/years/data classes, platform lists, counts, exposure scores.
~2-3KB sent vs 50-100KB for full state — critical for local 8B model performance.

Model: `llama3.1:8b`, `temperature=0`, `timeout=300`.

Response handling:
- Strip markdown code fences before `json.loads()` — model often wraps output in ` ```json `
- Raise explicit error on empty response (blank = timeout was hit)
- `JSONDecodeError` and all other exceptions caught — returns error fallback dict
- Fallback result has `overall_risk_score: 0` and empty sections (pipeline always completes)

---

## Output

Files written to `./output/` (bind-mounted from host):
```
output/YYYY-MM-DD_HH-MM_email_results.json   # full PipelineState dump
output/YYYY-MM-DD_HH-MM_email_report.md      # human-readable privacy report
```

Report sections:
- **What the Internet Knows About You** — identity_summary + what_is_known subsections
- **Top Risks** — up to 5 specific findings
- **What To Do** — do_today / do_this_week / ongoing (checklist format)
- **Raw Tool Results** — one-line summary per tool

---

## Tool Contract

Every tool must:
- Accept a typed Pydantic input model
- Return `ToolResult` envelope (never raw dicts, never raise)
- Handle errors by returning `ToolResult(success=False, error=..., data={})`
- Log what it queried (input value), **never** log the results (output data)
- In `TEST_MODE=true`, return fixture from `tests/fixtures/` without hitting any API

---

## Testing

```bash
uv run pytest
```

`TEST_MODE=true` makes all tools return fixtures. Full pipeline must pass in TEST_MODE.

Build order (follow strictly):
1. Fixtures (`tests/fixtures/*.json`)
2. Pydantic models (`models/`)
3. Tool wrappers with TEST_MODE
4. Unit tests — all pass before proceeding
5. LangGraph graph + nodes
6. Integration test (full pipeline in TEST_MODE)
7. Real endpoints only after everything is green

---

## Privacy Constraints

- No API keys in code — `.env` only, gitignored
- No external calls except defined tool endpoints
- Ollama: `http://ollama:11434` (Docker internal) only
- SpiderFoot: `http://spiderfoot:5001` (Docker internal) only
- Results never logged to stdout or log files
- `analysis_node` is the only node that sends data to Ollama
- No telemetry, no analytics, no external error reporting

---

## Project Structure

```
osint-agent/
├── CLAUDE.md
├── .env                          # gitignored
├── .env.example
├── .gitignore
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── main.py
├── config.py
├── bin/
│   ├── run.sh                    # pre-flight + scan launcher
│   └── check.sh                  # environment verification
├── data/
│   └── ai_policies.json
├── models/
│   ├── shared.py                 # ToolResult, PipelineState, InputClassification, AnalysisResult
│   ├── hibp.py
│   ├── spiderfoot.py
│   ├── broker_scan.py
│   ├── ai_audit.py
│   ├── holehe.py
│   ├── leakradar.py
│   ├── blackbird.py
│   ├── maigret.py
│   └── ghunt.py
├── tools/
│   ├── hibp.py
│   ├── spiderfoot.py
│   ├── broker_scan.py
│   ├── ai_audit.py
│   ├── holehe.py
│   ├── leakradar.py
│   ├── blackbird.py
│   ├── maigret.py
│   └── ghunt.py
├── agent/
│   ├── graph.py
│   ├── nodes.py                  # includes _build_analysis_digest()
│   └── prompts.py
├── tests/
│   ├── fixtures/
│   └── test_tools.py
└── output/                       # gitignored, bind-mounted in Docker
```

---

## Known Issues / Lessons Learned

- **Google CSE removed** — API closed to new customers (early 2026). All broker scanning is Apify only.
- **SpiderFoot healthcheck** — the spiderfoot image has no `curl`. Use `python3 urllib` in the healthcheck test.
- **Ollama zombie processes** — `init: true` required in docker-compose to reap subprocesses spawned during inference.
- **`docker compose run` recreates deps** — use `--no-deps` flag since pre-flight already verified health.
- **Ollama empty response** — `timeout=300` needed; 120s gets truncated on complex prompts with an 8B model.
- **Model wraps JSON in fences** — always strip ` ```json ` before `json.loads()`.
- **Apify Run object** — access fields as attributes (`run.id`), not dict keys (`.get("id")`).
- **HIBP PascalCase** — use `alias_generator=to_pascal` + `model_validate()`; most fields optional (spam entries return Name only).
- **Full state to Ollama** — sending the raw `state.model_dump_json()` (50-100KB) to a local 8B model causes multi-minute hangs and empty responses. Use `_build_analysis_digest()` to send a 2-3KB summary instead.
- **`docker compose ps --format json`** — returns a JSON array `[{...}]`, not a bare object. Parse with `json.load(sys.stdin)[0].get('Health')`.
