import os
import sys
import argparse
import logging
import json
import asyncio # --- NEW: Native asyncio ---
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logging.getLogger("neo4j").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

@dataclass
class AppContext:
    llm: LLMService
    graph: GraphManager

async def main():
    parser = argparse.ArgumentParser(description="AutoSAR Vulnerability Scanner Orchestrator")
    parser.add_argument("source_dir", nargs='?', default=".", help="Path to the AutoSAR source code directory")
    parser.add_argument("--depth", choices=["fast", "critical", "full"], default="critical")

    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-ingest", action="store_true")
    parser.add_argument("--exploit-only", type=str, help="Path to a vulnerability JSON report to exploit directly, bypassing the scan.")
    args = parser.parse_args()

    # Load environment-backed settings only after argparse handles --help/errors.
    from config import settings

    target_directory = os.path.abspath(args.source_dir)
    if not os.path.isdir(target_directory):
        logger.error(f"The directory '{target_directory}' does not exist.")
        sys.exit(1)

    target_limits = {"fast": 10, "critical": 50, "full": 9999}
    scan_limit = target_limits[args.depth]
    
    logger.info("Initializing Core Services...")
    try:
        llm_service = LLMService(
            api_key=settings.genai_subscription_key,
            model_name=settings.strong_model_id,
            base_url=settings.strong_base_url,
            api_version=settings.strong_api_version
        )
        graph = GraphManager(
            uri=settings.neo4j_uri, 
            user=settings.neo4j_user, 
            password=settings.neo4j_password
        )
    except Exception as e:
        logger.error(f"Failed to initialize core services: {e}")
        sys.exit(1)

    app_context = AppContext(llm=llm_service, graph=graph)
    orchestrator = ScanOrchestrator(app_context.llm, app_context.graph)
    reporter = ScanReporter(output_dir="reports")


    # ==========================================
    # --- PHASE 0 DIRECT EXPLOIT BYPASS ---
    # ==========================================
    if args.exploit_only:
        logger.info("\n" + "="*60)
        logger.info(f"🚀 DIRECT EXPLOIT MODE: Loading {args.exploit_only}")
        print("="*60)

        if not os.path.exists(args.exploit_only):
            parser.error(f"report file not found: {args.exploit_only}")

        with open(args.exploit_only, 'r') as f:
            pre_existing_report = json.load(f)

        # Build a queue of (func_name, vuln_entry)
        vuln_queue = asyncio.Queue()
        for func_name, vuln_entry in pre_existing_report.items():
            vuln_queue.put_nowait((func_name, vuln_entry))

        # Infer domain from first entry
        first_key = next(iter(pre_existing_report))
        target_domain = pre_existing_report[first_key].get("domain", "all")
        logger.info(f"Target domain inferred as: {target_domain}")

        exploit_orch = ExploitOrchestrator(
            target_domain=target_domain,
            llm_service=app_context.llm
        )

        results = {}

        while not vuln_queue.empty():
            func_name, vuln_entry = await vuln_queue.get()
            logger.info(f"🛡️ [EXPLOIT-ONLY] Processing vulnerability for {func_name}...")

            try:
                vuln_entry = dict(vuln_entry)
                vuln_entry["function_name"] = func_name
                result = await exploit_orch.execute_exploit_loop(
                    vulnerability_report=vuln_entry,   # <-- ONE vulnerability only
                    target_domain=target_domain
                )
                results[func_name] = result

                if result.get("status") == "success":
                    logger.info(f"💀 [PWNED] {func_name} exploit validated!")
                else:
                    logger.info(f"🛡️ [MITIGATED] {func_name} exploit failed: {result.get('rationale')}")

            except Exception as e:
                logger.error(f"Exploit-only mode crashed on {func_name}: {e}")

        logger.info(f"Final Exploit Results: {json.dumps(results, indent=2)}")

        app_context.graph.close()
        return

    # ==========================================

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

            logger.info("\n--- PHASE 2: Starting Graph Ingestion & Resolution ---")
            # These remain synchronous as planned
            IngestionPipeline(target_directory, app_context.graph).run(vendor_folders=config_json.get('vendor_folders', []))
            GraphResolver(app_context.graph).run_all_passes()
        
        # ==========================================
        # PHASE 2.5: INTERACTIVE DOMAIN SELECTION
        # ==========================================
        app_domains = config_json.get('app_domains', [])
        selected_domain = None

        if args.depth == "full":
            logger.info("Depth 'full' selected. Bypassing domain selection to scan all domains automatically.")
        elif app_domains:
            print("\n" + "="*60)
            logger.info("Discovered the following application domains:")
            for i, domain in enumerate(app_domains, 1):
                print(f"  {i}. {domain}")
            print(f"  {len(app_domains) + 1}. all (Scan all domains)")
            print("="*60)

            try:
                # Use standard synchronous input() here, it's fine for blocking startup config
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
        logger.info(f"\n--- PHASE 3: Multi-Agent Vulnerability Scan (Depth: {args.depth.upper()}) ---")
        
        all_reports = {}
        if args.resume:
            logger.info("Resume flag detected. Loading completed scans from cache...")
            for filename in os.listdir(CACHE_DIR):
                if filename.endswith(".json") and filename != "discovery_config.json":
                    func_name = filename[:-5]
                    with open(os.path.join(CACHE_DIR, filename), 'r') as f:
                        all_reports[func_name] = json.load(f)
            logger.info(f"Successfully loaded {len(all_reports)} completed scans.")

        top_targets = await orchestrator.prioritize_targets(
            scan_depth=args.depth, 
            max_targets=scan_limit,
            domain_filter=selected_domain
        )
        
        targets_to_scan = [t for t in top_targets if t not in all_reports]
        
        if not targets_to_scan:
            logger.info("✅ All prioritized targets have already been scanned or no targets were found.")
        else:
            if args.depth == "full":
                print("\n" + "="*70)
                logger.warning(f"ATTENTION: A 'full' depth scan has identified {len(targets_to_scan)} new targets.")
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
                """Processes exploits sequentially to prevent UDS session collisions."""
                while True:
                    item = await exploit_queue.get()
                    if item is None:  # Sentinel value to shut down
                        exploit_queue.task_done()
                        break
                    
                    report, func_name, domain = item
                    logger.info(f"🛡️ [EXPLOIT QUEUE] Popped vulnerability for {func_name}. Initiating exploit...")
                    try:
                        exploit_orch = ExploitOrchestrator(
                            target_domain=domain,
                            llm_service=app_context.llm
                        )
                        report = dict(report)
                        report["function_name"] = func_name
                        result = await exploit_orch.execute_exploit_loop(
                            vulnerability_report=report,
                            target_domain=domain
                        )

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

            # Start the single background worker task
            exploit_worker_task = asyncio.create_task(exploit_worker())

            MAX_CONCURRENT_SCANS = 5 
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
            if args.resume:
                resumed_exploits = 0
                for func_name, report in all_reports.items():
                    is_uds = report.get("metadata", {}).get("TaintedByUDS") is True
                    if report.get("vulnerability_found") and "exploit_validation" not in report and is_uds:
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
                            
                            is_uds = report.get("metadata", {}).get("TaintedByUDS") is True
                            
                            if is_uds:
                                domain_to_use = selected_domain if selected_domain else "all"
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

            # Create tasks
            tasks = [asyncio.create_task(bounded_scan(t)) for t in targets_to_scan]
            
            try:
                # Await all tasks concurrently
                await asyncio.gather(*tasks)

                if not exploit_queue.empty():
                    logger.info("⏳ Scans complete. Waiting for remaining exploits to finish...")
                await exploit_queue.join()  # Blocks until all items are processed
                
                # Shut down the worker gracefully
                await exploit_queue.put(None)
                await exploit_worker_task
                                
            except asyncio.CancelledError:
                logger.warning("\nGathering was cancelled. Shutting down gracefully...")

        # --- Final Reporting ---
        if all_reports:
            reporter.generate_consolidated_reports(all_reports)
            print("\n" + "="*60)
            logger.info("FINAL AUTOMOTIVE SCAN SUMMARY:")
            print("="*60)
            vuln_count = sum(1 for r in all_reports.values() if r.get("vulnerability_found"))
            if vuln_count > 0:
                for func, report in all_reports.items():
                    if report.get("vulnerability_found"):
                        logger.warning(f"🚨 [{report.get('severity', 'HIGH').upper()}] {func}")
            else:
                logger.info("✅ No vulnerabilities were found in the scanned targets.")
            print("="*60 + "\n")

    except asyncio.CancelledError:
        logger.info("\nMain execution was cancelled.")
    except Exception as e:
        logger.exception("An unhandled error occurred during execution:")
    finally:
        app_context.graph.close()
        logger.info("Database connection closed.")

if __name__ == "__main__":
    try:
        # Windows specific fix for asyncio EventLoop Policy
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
