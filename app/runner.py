import asyncio
import json
import logging
import os
import sys

from scan.orchestrator import ScanOrchestrator
from scan.reporter import ScanReporter

from app.context import AppContext, build_app_context, shutdown
from app.phases.discovery_phase import DiscoveryPhase
from app.phases.domain_selection import select_domain
from app.phases.exploit_phase import ExploitPhase
from app.phases.ingestion_phase import IngestionPhase
from app.phases.reporting_phase import generate_final_report
from app.phases.scan_phase import ScanPhase, resolve_scan_limit

logger = logging.getLogger(__name__)

CACHE_DIR = "scan_cache"


async def run(args) -> None:
    from config import settings

    target_directory = os.path.abspath(args.source_dir)
    if not os.path.isdir(target_directory):
        logger.error(f"The directory '{target_directory}' does not exist.")
        sys.exit(1)

    logger.info("Initializing Core Services...")
    try:
        app_context = build_app_context(settings)
    except Exception as e:
        logger.error(f"Failed to initialize core services: {e}")
        sys.exit(1)

    reporter = ScanReporter(output_dir="reports")

    if args.exploit_only:
        await _run_exploit_only(app_context, args.exploit_only, reporter)
        return

    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        await _run_full_pipeline(app_context, reporter, args, target_directory)
    except asyncio.CancelledError:
        logger.info("\nMain execution was cancelled.")
    except Exception:
        logger.exception("An unhandled error occurred during execution:")
    finally:
        shutdown(app_context)


async def _run_exploit_only(app_context: AppContext, report_path: str, reporter: ScanReporter) -> None:
    logger.info("\n" + "=" * 60)
    logger.info(f"🚀 DIRECT EXPLOIT MODE: Loading {report_path}")
    print("=" * 60)
    try:
        os.makedirs("reports", exist_ok=True)
        exploit_phase = ExploitPhase(app_context.llm, cache_dir="reports")
        results = await exploit_phase.run_standalone(report_path)
        generate_final_report(exploit_phase.standalone_reports, reporter)
        for func_name, result in results.items():
            if result.get("status") == "success":
                logger.info(f"💀 [PWNED] {func_name} exploit validated!")
            else:
                logger.info(f"🛡️ [MITIGATED] {func_name} exploit failed.")
    finally:
        shutdown(app_context)


async def _run_full_pipeline(app_context: AppContext, reporter: ScanReporter, args, target_directory: str) -> None:
    # --- PHASE 1 & 2: DISCOVERY, INGESTION, RESOLUTION ---
    discovery = DiscoveryPhase(app_context.llm, CACHE_DIR)
    used_cache = discovery.used_cache(args.skip_ingest)
    config_json = await discovery.run(target_directory, skip_ingest=args.skip_ingest)

    if used_cache:
        logger.info("--- PHASE 2: Skipped (using cached graph) ---")
    else:
        IngestionPhase().run(target_directory, app_context.graph, config_json)

    # --- PHASE 2.5: INTERACTIVE DOMAIN SELECTION ---
    mcu = config_json.get("mcu_guess", "Unknown MCU")
    vendor = config_json.get("stack_vendor", "Generic AutoSAR")
    platform_info = f"Hardware: {mcu}, Stack: {vendor}"
    logger.info(f"Platform Context established: {platform_info}")

    orchestrator = ScanOrchestrator(app_context.llm, app_context.graph, platform_info=platform_info)
    app_domains = config_json.get('app_domains', [])
    selected_domain = select_domain(app_domains, args.scan_all, args.target_file)

    # Computed AFTER domain selection: choosing a domain interactively defaults to an
    # exhaustive scan of that domain unless --limit was explicitly passed. See
    # app/phases/scan_phase.resolve_scan_limit for the exact precedence.
    scan_limit = resolve_scan_limit(args.limit, args.scan_all, args.target_file, selected_domain)
    if scan_limit == 0 and not args.scan_all and not args.target_file:
        logger.info(f"No --limit given; scanning all functions in domain '{selected_domain}'.")

    # --- PHASE 3: MULTI-AGENT VULNERABILITY SCAN ---
    logger.info("\n--- PHASE 3: Multi-Agent Vulnerability Scan ---")

    all_reports = {}
    if args.resume:
        logger.info("Resume flag detected. Loading completed scans from cache...")
        for filename in os.listdir(CACHE_DIR):
            if filename.endswith(".json") and filename != "discovery_config.json":
                func_name = filename[:-5]
                with open(os.path.join(CACHE_DIR, filename), 'r') as f:
                    all_reports[func_name] = json.load(f)
        logger.info(f"Successfully loaded {len(all_reports)} completed scans.")

    exploit_phase = ExploitPhase(app_context.llm, CACHE_DIR, skip=args.skip_exploit)
    scan_phase = ScanPhase(orchestrator, exploit_phase, CACHE_DIR)

    top_targets = await scan_phase.prioritize(
        max_targets=scan_limit, domain_filter=selected_domain, file_filter=args.target_file
    )
    targets_to_scan = [t for t in top_targets if t not in all_reports]

    if not targets_to_scan:
        logger.info("✅ All prioritized targets have already been scanned or no targets were found.")
    else:
        if scan_limit == 0 and not args.target_file:
            scope_desc = "global scan-all" if args.scan_all else (
                f"exhaustive scan of domain '{selected_domain}'" if selected_domain else "uncapped scan"
            )
            print("\n" + "=" * 70)
            logger.warning(f"ATTENTION: An uncapped {scope_desc} has identified {len(targets_to_scan)} targets.")
            logger.warning("This may take a significant amount of time and incur API costs.")
            print("=" * 70)
            try:
                if input("Are you sure you want to continue? (y/n): ").lower() != 'y':
                    sys.exit(0)
            except KeyboardInterrupt:
                sys.exit(0)

        print("\n" + "=" * 60)
        logger.info(f"Launching Progressive Scan on {len(targets_to_scan)} new targets...")
        print("=" * 60 + "\n")

        exploit_phase.start()

        if args.resume:
            resumed = scan_phase.resume_pending_exploits(all_reports, selected_domain)
            for func_name, report, domain_to_use in resumed:
                await exploit_phase.enqueue(report, func_name, domain_to_use)
            if resumed:
                logger.info(f"🔄 Resumed {len(resumed)} pending exploit(s) from cache.")

        await scan_phase.run(targets_to_scan, selected_domain, all_reports)
        await exploit_phase.drain()

    generate_final_report(all_reports, reporter)
