# Privacy OSINT Agent

## Purpose
Local privacy audit tool. Runs OSINT tools against a target
identity, analyzes results using a local Ollama model.
No data leaves the machine.

## Stack
- Python 3.11+
- LangChain + LangGraph for orchestration
- Ollama (llama3.1:8b) via localhost:11434
- SpiderFoot via Docker on localhost:5001
- UV for package management and virtual environment
- pytest for testing
- Standard library only for output (logging, print)

---

## Prerequisites (Manual Setup Required)
All of the following must be completed before running
the project. Do not add code that attempts to handle
missing credentials gracefully — fail loudly with a
clear error message pointing to this list.

### 1. Ollama
- Download and install from ollama.com
- Pull model: `ollama pull llama3.1:8b`
- Verify: `curl localhost:11434`
- No account required

### 2. SpiderFoot
- Install Docker Desktop if not already installed
- Run: `docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot`
- Verify UI loads at localhost:5001
- No API key required for local instance

### 3. Have I Been Pwned
- Go to haveibeenpwned.com/API/Key
- Purchase API key ($3.50/month)
- Copy key to .env as HIBP_API_KEY

### 4. Apify
- Go to apify.com and create free account
- Navigate to Settings → Integrations → API Tokens
- Create new token, copy to .env as APIFY_API_TOKEN
- Find "TruePeopleSearch Contact Finder" actor in Apify Store
- Copy actor ID to .env as APIFY_ACTOR_ID

### 5. Google Custom Search Engine
- Go to programmablesearchengine.google.com
- Create new search engine
- Under "Sites to search" add the broker domain list
  (Claude Code will generate this list in data/broker_domains.txt)
- Copy Search Engine ID to .env as GOOGLE_CSE_ID
- Go to console.cloud.google.com
- Enable Custom Search API
- Create API key under Credentials
- Copy to .env as GOOGLE_CSE_API_KEY
- Free tier: 100 queries/day

### 6. EasyOptOuts
- User has existing subscription
- No API integration needed
- Tool outputs dashboard link only
- No env var required

### 7. UV
- Install: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Verify: `uv --version`

---

## Environment Variables Required
```
HIBP_API_KEY=
APIFY_API_TOKEN=
APIFY_ACTOR_ID=
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
OLLAMA_HOST=http://localhost:11434
SPIDERFOOT_HOST=http://localhost:5001
TEST_MODE=false
RESULTS_OUTPUT_PATH=output/
```

---

## Startup Validation
config.py must validate all env vars on startup.
If any required var is missing, print which var is
missing and exit with code 1.
Do not proceed with partial configuration.
Do not use fallback defaults for missing credentials.

---

## Architecture
LangGraph sequential workflow with input-type routing.
Each node is a discrete Python function.
State passes between nodes as PipelineState (Pydantic model).
Local model only invoked in analysis_node.
All tool execution is deterministic Python with no LLM involvement.

---

## Input Handling
intake_node accepts raw text string.
Local model classifies into: email | phone | name | org.
Returns InputClassification: {"type": "email", "value": "normalized@value.com"}
Multiple inputs accepted as newline-separated string.
Each input classified independently.
Routes to type-specific subgraph in LangGraph.

---

## Agent Flow
```
START
  → intake_node        # classify input type, normalize
  → route              # email | phone | name | org subgraph
  → breach_check       # HIBP
  → broker_scan        # data broker presence (Apify + Google CSE)
  → surface_map        # SpiderFoot recon
  → ai_audit           # AI service exposure check
  → analysis_node      # Ollama synthesizes findings
  → report_node        # stdout + file output
END
```

---

## Tools

### tools/hibp.py
HIBP API v3 breach check.
Handles email and phone inputs.
Endpoint: GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}
Header: hibp-api-key
Returns HibpOutput Pydantic model wrapped in ToolResult.

### tools/spiderfoot.py
SpiderFoot API wrapper via localhost:5001.
Accepts email | phone | name | org as input.
Do NOT run all modules — restricted module list only:
  sfp_hibp, sfp_emailrep, sfp_hunter, sfp_whois,
  sfp_pgp, sfp_gravatar, sfp_social, sfp_pastebin
Full scan takes 30+ mins and hits rate limits.
Poll scan status until FINISHED before returning results.
Returns SpiderfootOutput Pydantic model wrapped in ToolResult.

### tools/broker_scan.py
Two-phase detection.
Phase 1A: Apify TruePeopleSearch wrapper — structured
  profile lookup (name, address, phone, relatives).
Phase 1B: Google CSE presence check across broker domain
  list stored in data/broker_domains.txt.
Results merged and deduplicated before returning.
Calculates exposure_score 0-100 from broker count + data depth.
Removal handled externally via EasyOptOuts — tool outputs
  dashboard link plus prioritized broker list.
Does NOT automate removal.
Returns BrokerScanOutput Pydantic model wrapped in ToolResult.

### tools/ai_audit.py
Static policy database lookup.
Reads from data/ai_policies.json.
Accepts list of AI platform IDs from user input.
Matches against policy database.
Returns AiAuditOutput Pydantic model wrapped in ToolResult.
Database updated manually — not via API.
Covers: claude, chatgpt, gemini, grok, copilot,
  meta_ai, perplexity, deepseek_cloud.

---

## Tool Schemas
Each tool in tools/ must:
- Accept typed Pydantic input models
- Return ToolResult envelope (never raw dicts)
- Handle errors gracefully — return error ToolResult, never raise
- Log what it queried (input), never log the results (output)
- In TEST_MODE, return fixture from tests/fixtures/ instead of calling API

---

## Pydantic Models
All tool inputs and outputs typed with Pydantic v2.
Models live in models/ directory.
Every tool returns ToolResult envelope from models/shared.py.
LangGraph state typed as PipelineState from models/shared.py.
No untyped dicts passed between nodes — always use model instances.
analysis_node receives PipelineState serialized to JSON string.
analysis_node output parsed and validated against AnalysisResult.
See models_and_fixtures.md for full model definitions and examples.

---

## Testing
TEST_MODE env flag (default: false).
When true, all tools return fixtures from tests/fixtures/.
Fixtures mirror real API response schemas exactly.
Full pipeline must pass integration test in TEST_MODE
before any real endpoint is called.
pytest for all tests. 100% tool coverage required.

### Build Order (follow strictly)
1. Define fixtures (JSON files in tests/fixtures/ — no code)
2. Write Pydantic models in models/
3. Write tool wrappers with TEST_MODE support
4. Write unit tests per tool against fixtures — all pass before moving on
5. Build LangGraph graph.py and nodes.py with mocked tools
6. Write integration test — full pipeline in TEST_MODE
7. Flip to real endpoints only after everything is green

---

## Analysis Node
Receives: PipelineState serialized to JSON string
Model: llama3.1:8b via Ollama at localhost:11434
Must instruct model: respond in JSON only, no preamble, no markdown
Parse response with json.loads() — if parse fails, return error ToolResult
Validate parsed JSON against AnalysisResult Pydantic model
System prompt template in agent/prompts.py

---

## Output Formatting
No Rich or third-party terminal formatting libraries.
Use Python standard logging module for runtime output.
Use print() for report output to stdout.
Keep stdout clean — no ANSI codes, no spinners, no progress bars.
Reports also written to output/ as timestamped files.

---

## Storage
No database for v1.
Results written to output/ as timestamped JSON + markdown.
Filename format: YYYY-MM-DD_HH-MM_<input_type>_results.json
Report format: YYYY-MM-DD_HH-MM_<input_type>_report.md
output/ directory must be gitignored.

---

## Privacy Constraints
- No API keys stored in code (use .env only)
- .env must be gitignored
- No external calls except defined tool endpoints
- Ollama endpoint: localhost:11434 only
- SpiderFoot endpoint: localhost:5001 only
- Results never logged to stdout or file system logs
- analysis_node is the only node that passes data to Ollama
- No telemetry, no analytics, no external error reporting

---

## Deployment
CLI only: `uv run python main.py "<input>"`
NOT a web service. No Flask/FastAPI layer.
Config via .env only, no hardcoded paths.
Setup: `uv sync`
Run: `uv run python main.py "<input>"`
Test: `uv run pytest`
Multiple inputs: `uv run python main.py "email@example.com\nJohn Doe\n555-123-4567"`

---

## Project Structure
```
osint-agent/
├── CLAUDE.md
├── .env                          # gitignored
├── .gitignore
├── pyproject.toml
├── README.md
├── main.py                       # entry point, arg parsing
├── config.py                     # env var validation, startup check
├── data/
│   ├── ai_policies.json          # AI platform policy database
│   └── broker_domains.txt        # broker domain list for Google CSE
├── models/
│   ├── shared.py                 # ToolResult, PipelineState, InputClassification
│   ├── hibp.py                   # HibpInput, HibpOutput, BreachRecord
│   ├── spiderfoot.py             # SpiderfootInput, SpiderfootOutput, SpiderfootElement
│   ├── broker_scan.py            # BrokerScanInput, BrokerScanOutput, BrokerProfile
│   └── ai_audit.py               # AiAuditInput, AiAuditOutput, AiPlatformPolicy
├── tools/
│   ├── hibp.py
│   ├── spiderfoot.py
│   ├── broker_scan.py
│   └── ai_audit.py
├── agent/
│   ├── graph.py                  # LangGraph workflow definition
│   ├── nodes.py                  # individual node functions
│   └── prompts.py                # Ollama system prompt templates
├── tests/
│   ├── fixtures/
│   │   ├── hibp_response.json
│   │   ├── hibp_no_results.json
│   │   ├── spiderfoot_response.json
│   │   ├── broker_apify_response.json
│   │   ├── broker_google_response.json
│   │   ├── ai_audit_response.json
│   │   ├── analysis_response.json
│   │   └── error_response.json
│   ├── test_tools.py
│   ├── test_routing.py
│   └── test_pipeline.py
└── output/                       # gitignored
```

---

## .gitignore
```
.env
output/
__pycache__/
.pytest_cache/
*.pyc
.venv/
```
