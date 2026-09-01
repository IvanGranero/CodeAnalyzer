import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AutoSAR Vulnerability Scanner Orchestrator")
    parser.add_argument("source_dir", nargs='?', default=".", help="Path to the AutoSAR source code directory")

    parser.add_argument(
        "--limit", type=int, default=None,
        help=(
            "Maximum number of top-risk functions to scan. If omitted: scans ALL "
            "functions in the selected domain when a domain is chosen (or --target-file "
            "is used), or the top 50 when no domain is selected (a global scan)."
        ),
    )
    parser.add_argument("--scan-all", action="store_true", help="Scan all discovered targets in scope, bypassing the limit.")
    parser.add_argument("--target-file", type=str, help="Restrict the scan to a specific file (e.g., 'bsw/Com.c').")

    parser.add_argument("--resume", action="store_true", help="Resume from cached scans.")
    parser.add_argument("--skip-ingest", action="store_true", help="Skip the graph building phase.")
    parser.add_argument("--skip-exploit", action="store_true", help="Skip the dynamic exploit validation phase.")
    parser.add_argument("--exploit-only", type=str, help="Path to a vulnerability JSON report to exploit directly.")
    return parser
