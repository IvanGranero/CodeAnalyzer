import os
import sys
import argparse
import logging
import json
import asyncio
from dataclasses import dataclass

# Configuration and Services
from llm.service import LLMService
from graph.manager import GraphManager

# Pipeline logic
from ingest.discovery import RepoDiscoverer
from ingest.pipeline import IngestionPipeline
from graph.resolver import GraphResolver
from scan.orchestrator import ScanOrchestrator
from scan.reporter import ScanReporter
from exploit.orchestrator import ExploitOrchestrator
from exploit.config import exploit_settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress noisy third-party library logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("neo4j").setLevel(logging.ERROR)          # Changed to ERROR
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR) # Added to silence DBMS warnings

@dataclass
class AppContext:
    llm: LLMService
    graph: GraphManager

async def main():
    parser = argparse.ArgumentParser(description="AutoSAR Vulnerability Scanner Orchestrator")
    parser.add_argument("source_dir", nargs='?', default=".", help="Path to the AutoSAR source code directory")
    
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of top-risk functions to scan (default: 50).")
    parser.add_argument("--scan-all", action="store_true", help="Scan all discovered targets in scope, bypassing the limit.")
    parser.add_argument("--target-file", type=str, help="Restrict the scan to a specific file (e.g., 'bsw/Com.c').")

    parser.add_argument("--resume", action="store_true", help="Resume from cached scans.")
    parser.add_argument("--skip-ingest", action="store_true", help="Skip the graph building phase.")
    parser.add_argument("--skip-exploit", action="store_true", help="Skip the dynamic exploit validation phase.")
    parser.add_argument("--exploit-only", type=str, help="Path to a vulnerability JSON report to exploit directly.")
    args = parser.parse_args()

    from config import settings

    target_directory = os.path.abspath(args.source_dir)
    if not os.path.isdir(target_directory):
        logger.error(f"The directory '{target_directory}' does not exist.")
        sys.exit(1)

    scan_limit = 0 if args.scan_all or args.target_file else args.limit
    
    logger.info("Initializing Core Services...")
    try:
        llm_service = LLMService(
            api_key=settings.genai_subscription_key,
            model_name=settings.strong_model_id,
            base_url=settings.strong_base_url,
            api_version=settings.strong_api_version,
            api_key_header=settings.genai_subscription_header,
            usd_per_1m_input=settings.strong_usd_input,
            usd_per_1m_output=settings.strong_usd_output
        )
        graph = GraphManager(
            uri=settings.neo4j_uri, 
            user=settings.neo4j_user, 
            password=settings.neo4j_password
        )
        graph.resolver = GraphResolver(graph.db)
    except Exception as e:
        logger.error(f"Failed to initialize core services: {e}")
        sys.exit(1)

    app_context = AppContext(llm=llm_service, graph=graph)
    reporter = ScanReporter(output_dir="reports")

    # ==========================================
    # --- PHASE 0 DIRECT EXPLOIT BYPASS ---
    # ==========================================
    if args.exploit_only:
        # (Exploit only logic remains exactly the same...)
        logger.info("\n" + "="*60)
        logger.info(f"🚀 DIRECT EXPLOIT MODE: Loading {args.exploit_only}")
        print("="*60)
        if not os.path.exists(args.exploit_only):
            parser.error(f"report file not found: {args.exploit_only}")
        with open(args.exploit_only, 'r') as f:
            pre_existing_report = json.load(f)
        vuln_queue = asyncio.Queue()
        for func_name, vuln_entry in pre_existing_report.items():
            vuln_queue.put_nowait((func_name, vuln_entry))
        first_key = next(iter(pre_existing_report))
        target_domain = pre_existing_report[first_key].get("domain", "all")
        exploit_orch = ExploitOrchestrator(target_domain=target_domain, llm_service=app_context.llm)
        results = {}
        while not vuln_queue.empty():
            func_name, vuln_entry = await vuln_queue.get()
            try:
                vuln_entry = dict(vuln_entry)
                vuln_entry["function_name"] = func_name
                result = await exploit_orch.execute_exploit_loop(vulnerability_report=vuln_entry, target_domain=target_domain)
                results[func_name] = result
                if result.get("status") == "success":
                    logger.info(f"💀 [PWNED] {func_name} exploit validated!")
                else:
                    logger.info(f"🛡️ [MITIGATED] {func_name} exploit failed.")
            except Exception as e:
                logger.error(f"Exploit-only mode crashed on {func_name}: {e}")
        app_context.graph.close()
        return

    try:
        CACHE_DIR = "scan_cache"
        os.makedirs(CACHE_DIR, exist_ok=True)

        # ==========================================
        # PHASE 1 & 2: DISCOVERY, INGESTION, RESOLUTION
        # ==========================================
        discovery_cache_file = os.path.join(CACHE_DIR, "discovery_config.json")
        config_json = {}

        if args.skip_ingest and os.path.exists(discovery_cache_file):
            logger.info("--- PHASE 1 & 2: Skipped (Using cached graph and discovery) ---")
            with open(discovery_cache_file, 'r') as f:
                config_json = json.load(f)
        else:
            logger.info("--- PHASE 1: Starting Architectural Discovery ---")
            dir_tree = RepoDiscoverer.generate_directory_tree(target_directory)
            llm_response = await app_context.llm.execute_task(task_name="discovery", kwargs={"directory_tree": dir_tree})
            try:
                config_json = json.loads(llm_response)
                with open(discovery_cache_file, 'w') as f:
                    json.dump(config_json, f)
            except json.JSONDecodeError:
                logger.error("Discovery LLM did not return valid JSON. Cannot proceed.")
                sys.exit(1)

            found_configs = config_json.get('config_files', [])
            if found_configs:
                logger.info(f"Discovery found {len(found_configs)} system configuration files.")

            logger.info("\n--- PHASE 2: Starting Graph Ingestion & Resolution ---")
            IngestionPipeline(target_directory, app_context.graph).run(
                vendor_folders=config_json.get('vendor_folders', []),
                config_files=found_configs
            )            
            
            app_context.graph.resolver.run_all_passes()

        # ==========================================
        # PHASE 2.5: INTERACTIVE DOMAIN SELECTION
        # ==========================================
        mcu = config_json.get("mcu_guess", "Unknown MCU")
        vendor = config_json.get("stack_vendor", "Generic AutoSAR")
        platform_info = f"Hardware: {mcu}, Stack: {vendor}"
        logger.info(f"Platform Context established: {platform_info}")        
        orchestrator = ScanOrchestrator(app_context.llm, app_context.graph, platform_info=platform_info)
        app_domains = config_json.get('app_domains', [])
        selected_domain = None

        # Only ask for a domain if the user didn't hardcode a specific target file
        if args.target_file:
            logger.info(f"Target file '{args.target_file}' specified. Bypassing domain selection.")
        elif args.scan_all:
            logger.info("--scan-all specified. Bypassing domain selection to scan everything globally.")
        elif app_domains:
            print("\n" + "="*60)
            logger.info("Discovered the following application domains:")
            for i, domain in enumerate(app_domains, 1):
                print(f"  {i}. {domain}")
            print(f"  {len(app_domains) + 1}. all (Scan all domains)")
            print("="*60)
            try:
                choice = input(f"Which domain would you like to scan? (1-{len(app_domains) + 1}): ")
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(app_domains):
                    selected_domain = app_domains[choice_idx]
            except (ValueError, IndexError):
                logger.warning("Invalid input. Defaulting to a full scan.")
            except KeyboardInterrupt:
                logger.info("\nScan aborted by user.")
                sys.exit(0)

        # ==========================================
        # PHASE 3: MULTI-AGENT VULNERABILITY SCAN
        # ==========================================
        mode_str = "ALL" if args.scan_all else str(args.limit)
        logger.info(f"\n--- PHASE 3: Multi-Agent Vulnerability Scan ---")
        
        all_reports = {}
        if args.resume:
            logger.info("Resume flag detected. Loading completed scans from cache...")
            for filename in os.listdir(CACHE_DIR):
                if filename.endswith(".json") and filename != "discovery_config.json":
                    func_name = filename[:-5]
                    with open(os.path.join(CACHE_DIR, filename), 'r') as f:
                        all_reports[func_name] = json.load(f)
            logger.info(f"Successfully loaded {len(all_reports)} completed scans.")

        # --- NEW: Pass the target_file and clean limit to the orchestrator ---
        top_targets = await orchestrator.prioritize_targets(
            max_targets=scan_limit,
            domain_filter=selected_domain,
            file_filter=args.target_file
        )
        
        targets_to_scan = [t for t in top_targets if t not in all_reports]
        
        if not targets_to_scan:
            logger.info("✅ All prioritized targets have already been scanned or no targets were found.")
        else:
            if args.scan_all:
                print("\n" + "="*70)
                logger.warning(f"ATTENTION: A global scan-all has identified {len(targets_to_scan)} targets.")
                logger.warning("This may take a significant amount of time and incur API costs.")
                print("="*70)
                try:
                    if input("Are you sure you want to continue? (y/n): ").lower() != 'y': sys.exit(0)
                except KeyboardInterrupt: sys.exit(0)

            print("\n" + "="*60)
            logger.info(f"Launching Progressive Scan on {len(targets_to_scan)} new targets...")
            print("="*60 + "\n")

            exploit_queue = asyncio.Queue()

            async def exploit_worker():
                while True:
                    item = await exploit_queue.get()
                    if item is None:
                        exploit_queue.task_done()
                        break
                    report, func_name, domain = item
                    logger.info(f"🛡️ [EXPLOIT QUEUE] Popped vulnerability for {func_name}. Initiating exploit...")
                    try:
                        exploit_orch = ExploitOrchestrator(target_domain=domain, llm_service=app_context.llm)
                        report = dict(report)
                        report["function_name"] = func_name
                        result = await exploit_orch.execute_exploit_loop(vulnerability_report=report, target_domain=domain)
                        report["exploit_validation"] = result                        
                        with open(os.path.join(CACHE_DIR, f"{func_name}.json"), 'w') as f:
                            json.dump(report, f)
                        if result.get("status") == "success":
                            logger.info(f"💀 [PWNED] {func_name} exploit validated!")
                        else:
                            logger.info(f"🛡️ [MITIGATED] {func_name} exploit failed: {result.get('rationale')}")
                    except Exception as e:
                        logger.error(f"Exploit worker crashed on {func_name}: {e}")
                    finally:
                        exploit_queue.task_done()

            # Start Exploit background task
            if not args.skip_exploit:
                exploit_worker_task = asyncio.create_task(exploit_worker())
            else:
                exploit_worker_task = None
                logger.info("Exploitation phase disabled via --skip-exploit.")

            MAX_CONCURRENT_SCANS = 5 
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
            if args.resume:
                resumed_exploits = 0
                for func_name, report in all_reports.items():
                    is_uds = report.get("metadata", {}).get("TaintedByUDS") is True
                    if report.get("vulnerability_found") and "exploit_validation" not in report and is_uds:
                        if not args.skip_exploit:  # <--- NEW CHECK
                            domain_to_use = selected_domain if selected_domain else report.get("domain", "all")
                            exploit_queue.put_nowait((report, func_name, domain_to_use))
                            resumed_exploits += 1

                if resumed_exploits > 0:
                    logger.info(f"🔄 Resumed {resumed_exploits} pending exploit(s) from cache.")
                                
            async def bounded_scan(target_func):
                async with semaphore:
                    try:
                        report = await orchestrator.scan_function(target_func)
                        all_reports[target_func] = report
                        with open(os.path.join(CACHE_DIR, f"{target_func}.json"), 'w') as f:
                            json.dump(report, f)
                        
                        if report.get("vulnerability_found"):
                            logger.warning(f"⚠️ [VULNERABILITY FOUND] -> {target_func} ({report.get('severity')})")
                            
                            # --- FIX 1: Robust Boolean Parsing ---
                            taint_val = report.get("metadata", {}).get("TaintedByUDS", False)
                            is_uds = taint_val is True or str(taint_val).lower() == "true"
                            
                            if is_uds:
                                if args.skip_exploit:
                                    logger.info(f"⏭️ [SKIPPED EXPLOIT] -> {target_func} (--skip-exploit flag active).")
                                else:                                
                                    domain_to_use = selected_domain
                                    
                                    if not domain_to_use:
                                        # Normalize the file path to use forward slashes
                                        file_path = report.get("metadata", {}).get("FilePath", "")
                                        normalized_path = file_path.replace("\\\\", "/").replace("\\", "/").lower()
                                        
                                        # Match the folder name against the keys in DOIP_TARGET_MAP (.env)
                                        for domain_key in exploit_settings.target_map.keys():
                                            if f"/{domain_key.lower()}/" in normalized_path:
                                                domain_to_use = domain_key
                                                logger.debug(f"Dynamically mapped {target_func} to domain: {domain_key}")
                                                break
                                                
                                    # Fallback if no folder matches known domains
                                    if not domain_to_use:
                                        domain_to_use = "diag" # Safer default than 'all'
                                    
                                    await exploit_queue.put((report, target_func, domain_to_use))
                            else:
                                logger.info(f"⏭️ [SKIPPED EXPLOIT] -> {target_func} is not reachable via UDS/DoIP.")

                        else:
                            logger.info(f"✔ [CLEAN] -> {target_func}")
                        return report
                    except asyncio.CancelledError:
                        logger.warning(f"Scan task for {target_func} was cancelled.")
                        raise
                    except Exception as exc:
                        logger.error(f"Scan for {target_func} crashed: {exc}")
                        return None                            

            # --- ENTERPRISE SCALE SCANNER QUEUE ---
            scan_queue = asyncio.Queue()
            for t in targets_to_scan:
                scan_queue.put_nowait(t)

            async def scan_worker():
                while True:
                    # --- FIX 2: Prevent asyncio deadlocks using get_nowait ---
                    try:
                        target_func = scan_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break  # Cleanly exit the worker when queue is empty
                        
                    try:
                        # bounded_scan handles the semaphore and orchestrator calls
                        await bounded_scan(target_func)
                    except Exception as e:
                        logger.error(f"Worker failed on {target_func}: {e}")
                    finally:
                        scan_queue.task_done()

            # Create a fixed number of concurrent workers (e.g., 5)
            MAX_CONCURRENT_SCANS = 5
            workers = [asyncio.create_task(scan_worker()) for _ in range(MAX_CONCURRENT_SCANS)]
            
            try:
                # Wait for the scan queue to empty
                if targets_to_scan:
                    await scan_queue.join()
                
                if not args.skip_exploit:
                    if not exploit_queue.empty():
                        logger.info("⏳ Scans complete. Waiting for remaining exploits to finish...")
                    await exploit_queue.join() 
                    
                    # Kill the exploit worker safely
                    await exploit_queue.put(None)
                    await exploit_worker_task
                    
            except asyncio.CancelledError:
                logger.warning("\nExecution was cancelled. Shutting down gracefully...")
                for w in workers:
                    w.cancel()

        # --- Final Reporting ---
        if all_reports:
            print("\n" + "="*60)
            logger.info("FINAL SCAN SUMMARY:")
            print("="*60)
            
            vuln_count = 0
            for func, report in all_reports.items():
                if report.get("vulnerability_found"):
                    vuln_count += 1
                    logger.warning(f"🚨 [{report.get('severity', 'HIGH').upper()}] {func}")
                    # --- NEW: Generate the individual report ---
                    reporter.generate_individual_report(func, report)
            
            if vuln_count > 0:
                logger.info(f"✅ Generated {vuln_count} individual Markdown reports in the 'reports/' directory.")
            else:
                logger.info("✅ No vulnerabilities were found in the scanned targets.")
            print("="*60 + "\n")
            
            # Optional: Generate a single SARIF file for CI/CD integration if your reporter supports it
            if hasattr(reporter, 'generate_consolidated_reports'):
                reporter.generate_consolidated_reports(all_reports)

    except asyncio.CancelledError:
        logger.info("\nMain execution was cancelled.")
    except Exception as e:
        logger.exception("An unhandled error occurred during execution:")
    finally:
        if 'app_context' in locals() and hasattr(app_context.llm, 'tracker'):
            app_context.llm.tracker.log_summary()
        app_context.graph.close()
        logger.info("Database connection closed.")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
