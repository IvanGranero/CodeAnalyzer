# Multi-Agent Vulnerability Scanner

An enterprise-grade, asynchronous SAST (Static Application Security Testing) platform designed specifically for automotive AutoSAR C/C++ codebases. By combining **Neo4j Code Property Graphs (CPG)** with **Asynchronous LLM Agents**, this tool autonomously maps attack surfaces, traces UDS taint, prioritizes critical functions, and mathematically proves vulnerabilities—all while scaling concurrently.

## ✨ Key Features

* **Graph-Backed Taint Analysis:** Uses Neo4j to resolve ASTs, trace UDS (ISO 14229) diagnostic taint, map RTE data flows, and prune dead code instantly.

* **Name-Convention-Independent UDS Entry-Point Detection:** Resolves RTE port-accessor macro aliases (`Rte_Read_/Rte_Write_/Rte_Call_/Rte_IrvRead_/Rte_IrvWrite_`) and scrapes the generated Dcm DID dispatch table (`Dcm_CfgDidMgrSignalOpClassInfo[]`) directly, so UDS callback functions are correctly recognized as reachable even when their C symbol name gives no hint of DID handling and they have no direct caller anywhere in the source tree.

* **Fully Asynchronous Engine:** Built from the ground up with Python's `asyncio` for maximum I/O performance. Scans multiple targets concurrently and shuts down instantly/gracefully on `Ctrl+C`.

* **Domain-Specific Targeting:** Interactively filter scans by application domain (e.g., `/diag`, `/security`, `/ota`) to focus security audits on relevant modules.

* **Multi-Class, Multi-Finding Analysis:** The Deep-Scan agent evaluates every vulnerability class in its checklist per function (not just the first one found) and cross-checks data-race and unreachability claims against the graph's own ground truth, flagging any disagreement for human review instead of trusting the model silently.

* **Safety-Gated Exploit Validation:** Crafted UDS payloads for write/routine-control/flash/reset services (`0x2E`, `0x31`, `0x34-0x37`, `0x11`, `0x14`) are blocked before ever reaching a real ECU unless explicitly enabled — the exploit loop defaults to read-only, non-destructive services.

* **Intelligent State Management:** Features a robust caching system. Use `--resume` to pick up exactly where a previous scan left off, and `--skip-ingest` to instantly query an already-built database.

* **Enterprise Reporting:** Automatically consolidates findings into a single Human-readable **Markdown** report and an industry-standard **SARIF v2.1.0** file for CI/CD integration.

## ⚙️ Prerequisites

* **Python 3.10+** installed on your system.
* **Neo4j Database:** (Desktop or AuraDB) running locally or remotely.
* **LLM Access:** Azure OpenAI or standard OpenAI API credentials.

## 🚀 Installation & Setup

Follow these steps to get your environment set up and ready for scanning:

**1. Clone the repository**
Navigate to your desired workspace and clone the project:

```bash
git clone https://github.com/IvanGranero/CodeAnalyzer.git
cd CodeAnalyzer
```

**2. Create a Python Virtual Environment**
It is highly recommended to use a virtual environment to manage dependencies cleanly.

* **On Windows:**
  ```cmd
  python -m venv venv
  venv\Scripts\activate
  ```

* **On Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

**3. Install Dependencies**
With your virtual environment activated, install all required packages using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

**4. Configure Environment Variables**
Ensure your `.env` or `config.py` file is populated with your specific database and LLM credentials:
* `neo4j_uri`, `neo4j_user`, `neo4j_password`
* `genai_subscription_key`, `genai_subscription_header`
* `cheap_model_id`, `cheap_base_url`, `cheap_api_version`
* `strong_model_id`, `strong_base_url`, `strong_api_version`

The application reports missing or invalid settings before starting the scanner. If `.env` is missing, create it in the project directory. Use `python codeanalyzer.py --help` to view command-line usage without configuring the environment first.

Exploit behavior is configured separately in `exploit/.env`:

* `EXPLOIT_MAX_ATTEMPTS` defaults to `5` payload attempts per vulnerability. The strategist may stop earlier by returning `GIVE_UP` or `VALIDATED`.
* `EXPLOIT_LLM_TIMEOUT` defaults to `120.0` seconds per exploit-agent request. A timeout is recorded for the current attempt, then the loop continues to the next attempt.
* `PREFLIGHT_CONNECT_RETRIES` defaults to `3` total connection attempts per vulnerability.
* `PREFLIGHT_CONNECT_RETRY_DELAY` defaults to `2.0` seconds between failed connection attempts.
* `ALLOW_WRITE_SERVICES` defaults to `false`. LLM-crafted payloads targeting write/routine-control/flash/reset UDS services are blocked unless this is explicitly set to `true` — only enable it against a bench ECU you're authorized to write to.
* `MAX_CONCURRENT_PAYLOADS` defaults to `10`. Hard ceiling on how many concurrent requests a data-race/concurrency exploit attempt may fire, regardless of what the crafter agent requests.

A failed connection is retried for the current vulnerability before the exploit queue moves to the next one.

## 💻 Usage

Run the orchestrator using the main `codeanalyzer.py` entrypoint. Point it at the root directory of your AutoSAR source code.

### Command-Line Options

Display the built-in usage information at any time:

```bash
python codeanalyzer.py --help
```

Command-line parsing happens before environment configuration is loaded, so `--help` and invalid argument combinations show usage even when the `.env` file is not configured. A valid command that starts the scanner still requires the environment variables described in [Prerequisites](#prerequisites).

| Option | Description |
| --- | --- |
| `source_dir` | Optional path to the AutoSAR source directory. Defaults to the current directory (`.`). |
| `--limit N` | Maximum number of top-risk functions to scan. Defaults to `50`. |
| `--scan-all` | Scans every discovered target, bypassing `--limit` (prompts for confirmation first). |
| `--target-file PATH` | Restricts the scan to a specific file, bypassing domain selection. |
| `--skip-ingest` | Reuses the cached discovery configuration and existing Neo4j graph when available. |
| `--skip-exploit` | Disables the dynamic exploit validation phase for UDS-reachable findings. |
| `--resume` | Loads completed reports from `scan_cache/` and schedules unfinished scans and UDS exploit validations. |
| `--exploit-only REPORT.json` | Skips discovery, ingestion, domain selection, and static scanning, then executes the exploit loop for each vulnerability in the supplied JSON report. |

The normal scan flow is discovery, graph ingestion, domain selection, static scanning, and exploit validation for findings that are reachable through UDS/DoIP. The `--exploit-only` option is a separate direct-validation mode and does not require a new scan.

### Standard Run (Top 50 Targets)
Parses the codebase, builds the graph, prompts for a domain, and scans the top 50 targets:

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/
```

### Fast Triage (Top 10 Targets)

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/ --limit 10
```

### Full Exhaustive Scan
Scans every single active function (prompts for confirmation before starting to prevent unexpected API costs):

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/ --scan-all
```

### Skipping Ingestion (Instant Scans)
If you have already parsed the project and the Neo4j database is populated, skip the heavy lifting and jump straight to domain selection:

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/ --skip-ingest
```

### Resuming a Cancelled Scan
If a scan was interrupted (e.g., via `Ctrl+C`), you can resume without losing progress. The orchestrator will read the `scan_cache/` and only process unscanned targets:

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/ --skip-ingest --resume
```

### Direct Exploit Validation
To validate vulnerabilities from an existing JSON report without running discovery, ingestion, or static analysis:

```bash
python codeanalyzer.py ./path/to/AutoSAR_Project/ --exploit-only ./path/to/vulnerabilities.json
```

The report must be a JSON object keyed by function name. Each value should contain the vulnerability fields used by the exploit agents, such as `type`, `description`, and optionally `domain`:

```json
{
  "DiagnosticHandler": {
    "type": "Denial of Service",
    "description": "Malformed diagnostic input can reach an unsafe parser.",
    "domain": "diag"
  }
}
```

The domain is inferred from the first report entry and passed to every exploit in direct mode. Exploit results are printed in the final log output; this mode does not write a new consolidated scan report.

## 🏗️ Architecture Pipeline

* **Phase 1: Architectural Discovery**
  * An LLM analyzes the directory tree to identify the MCU, Stack Vendor, and logical application domains.

* **Phase 2: Graph Ingestion & Resolution**
  * Parses C/C++ code into a Neo4j Code Property Graph.
  * Runs a fixed sequence of resolver passes: resolves the generated Dcm DID dispatch table and RTE macro-call aliases into real `HANDLES_UDS`/`CALLS` edges first (both are name-convention-independent, generator-authoritative sources), then propagates UDS taint, binds runnables to OS tasks, resolves concurrency/data-race risk, maps RTE data flow, flags dangerous sinks, and finally flags dead code — in that order, so dead-code detection only ever runs against the fully-resolved call graph.

* **Phase 2.5: Interactive Domain Selection**
  * Prompts the user to isolate the scan to a specific module (e.g., `diag`).

* **Phase 3: Multi-Agent Vulnerability Scan**
  * **Triage Agent:** Analyzes the target's graph neighborhood to generate a prioritized, structured vulnerability checklist and a tailored investigation directive.
  * **Deep-Scan Agent:** Iterates that checklist directly, producing one finding per vulnerability class, and cross-checks any data-race or unreachability claim against the graph's own ground truth (`has_data_race_risk`, `is_dead_code`, UDS-trigger provenance) before the report is finalized.

* **Phase 4: Exploit Validation**
  * For UDS/DoIP-reachable findings, the exploit orchestrator uses a crafter, executor, analyzer, and strategist loop to generate payloads and validate ECU behavior, gated by the safety allowlist described above.

When `--exploit-only` is supplied, the normal phases are bypassed and execution starts directly with exploit validation from the supplied report.

## 📁 Project Layout

```
codeanalyzer.py           # Entrypoint: logging setup, CLI parsing, asyncio.run
app/
  cli.py                  # argparse definition
  context.py              # AppContext: LLM service + GraphManager bootstrap/shutdown
  runner.py                # Sequences the phases below; owns try/finally shutdown
  phases/
    discovery_phase.py      # Phase 1
    ingestion_phase.py      # Phase 2
    domain_selection.py     # Phase 2.5
    scan_phase.py           # Phase 3 (target prioritization + concurrent scan queue)
    exploit_phase.py        # Phase 4 (shared by the queue-driven path and --exploit-only)
    reporting_phase.py      # Final summary + report generation
ingest/                    # tree-sitter AST parsing, ARXML/RTE-JSON config parsing, graph payload builder
graph/                     # Neo4j driver, ingestion/resolution passes, NL→Cypher, typed graph models
scan/                      # Triage/deep-scan orchestration, analyzer tools, report generation
exploit/                   # DoIP/UDS client, crafter/analyzer/strategist exploit loop, safety config
llm/                       # LLM client (Responses + legacy Chat APIs), prompts.json, token tracker
```

Tests live in `tests/` and are intentionally excluded from version control (see `.gitignore`); run them locally with `pip install -r requirements-dev.txt && pytest tests/`.

## 📊 Reporting

Upon completion (or graceful cancellation), the `ScanReporter` aggregates all findings into the `reports/` directory:

* `raw_findings_*.json`: Raw LLM output.
* `Vulnerability_Report_*.md`: Beautifully formatted markdown containing line numbers, severity, and mitigation advice.
* `results_*.sarif`: Static Analysis Results Interchange Format, ready to be ingested into GitHub Security or SonarQube.
