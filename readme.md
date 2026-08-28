# Multi-Agent Vulnerability Scanner

An enterprise-grade, asynchronous SAST (Static Application Security Testing) platform designed specifically for automotive AutoSAR C/C++ codebases. By combining **Neo4j Code Property Graphs (CPG)** with **Asynchronous LLM Agents**, this tool autonomously maps attack surfaces, traces UDS taint, prioritizes critical functions, and mathematically proves vulnerabilities—all while scaling concurrently.

## ✨ Key Features

* **Graph-Backed Taint Analysis:** Uses Neo4j to resolve ASTs, trace UDS (ISO 14229) diagnostic taint, map RTE data flows, and prune dead code instantly.

* **Fully Asynchronous Engine:** Built from the ground up with Python's `asyncio` for maximum I/O performance. Scans multiple targets concurrently and shuts down instantly/gracefully on `Ctrl+C`.

* **Domain-Specific Targeting:** Interactively filter scans by application domain (e.g., `/diag`, `/security`, `/ota`) to focus security audits on relevant modules.

* **Progressive Scan Depths:**
  * `fast`: Quick triage of the top 10 most critical functions.
  * `critical`: Balanced sweep of the top 50 highest-risk vectors.
  * `full`: Exhaustive audit of all active, non-vendor functions in the domain.

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
* `genai_subscription_key`, `strong_model_id`, `strong_base_url`

## 💻 Usage

Run the orchestrator using the main `run.py` script. Point it at the root directory of your AutoSAR source code.

### Standard Run (Critical Depth)
Parses the codebase, builds the graph, prompts for a domain, and scans the top 50 targets:

```bash
python run.py ./path/to/AutoSAR_Project/ --depth critical
```

### Fast Triage (Top 10 Targets)

```bash
python run.py ./path/to/AutoSAR_Project/ --depth fast
```

### Full Exhaustive Scan
Scans every single active function (prompts for confirmation before starting to prevent unexpected API costs):

```bash
python run.py ./path/to/AutoSAR_Project/ --depth full
```

### Skipping Ingestion (Instant Scans)
If you have already parsed the project and the Neo4j database is populated, skip the heavy lifting and jump straight to domain selection:

```bash
python run.py ./path/to/AutoSAR_Project/ --depth critical --skip-ingest
```

### Resuming a Cancelled Scan
If a scan was interrupted (e.g., via `Ctrl+C`), you can resume without losing progress. The orchestrator will read the `scan_cache/` and only process unscanned targets:

```bash
python run.py ./path/to/AutoSAR_Project/ --depth critical --skip-ingest --resume
```

## 🏗️ Architecture Pipeline

* **Phase 1: Architectural Discovery**
  * An LLM analyzes the directory tree to identify the MCU, Stack Vendor, and logical application domains.

* **Phase 2: Graph Ingestion & Resolution**
  * Parses C/C++ code into a Neo4j Code Property Graph.
  * Resolves UDS entry points, propagates taint, maps RTE ports, and flags dead code.

* **Phase 2.5: Interactive Domain Selection**
  * Prompts the user to isolate the scan to a specific module (e.g., `diag`).

* **Phase 3: Multi-Agent Vulnerability Scan**
  * **Triage Agent:** Analyzes the target's graph neighborhood to generate specific attack hypotheses.
  * **Deep-Scan Agent:** Executes an asynchronous, strict-JSON static analysis based on the triage directive.

* **Phase 4: Validation**
  * Translates static analysis findings into actionable exploit scripts.

## 📊 Reporting

Upon completion (or graceful cancellation), the `ScanReporter` aggregates all findings into the `reports/` directory:

* `raw_findings_*.json`: Raw LLM output.
* `Vulnerability_Report_*.md`: Beautifully formatted markdown containing line numbers, severity, and mitigation advice.
* `results_*.sarif`: Static Analysis Results Interchange Format, ready to be ingested into GitHub Security or SonarQube.
