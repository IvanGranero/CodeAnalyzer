import logging
import sys
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def select_domain(
    app_domains: list,
    scan_all: bool,
    target_file: Optional[str],
    input_fn: Callable[[str], str] = input,
) -> Optional[str]:
    """
    Phase 2.5: ask the operator which application domain to scan, unless a
    specific target file was given or a global scan was requested. `input_fn`
    is injectable so this stays unit-testable without real stdin.
    """
    if target_file:
        logger.info(f"Target file '{target_file}' specified. Bypassing domain selection.")
        return None
    if scan_all:
        logger.info("--scan-all specified. Bypassing domain selection to scan everything globally.")
        return None
    if not app_domains:
        return None

    print("\n" + "=" * 60)
    logger.info("Discovered the following application domains:")
    for i, domain in enumerate(app_domains, 1):
        print(f"  {i}. {domain}")
    print(f"  {len(app_domains) + 1}. all (Scan all domains)")
    print("=" * 60)
    try:
        choice = input_fn(f"Which domain would you like to scan? (1-{len(app_domains) + 1}): ")
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(app_domains):
            return app_domains[choice_idx]
    except (ValueError, IndexError):
        logger.warning("Invalid input. Defaulting to a full scan.")
    except KeyboardInterrupt:
        logger.info("\nScan aborted by user.")
        sys.exit(0)
    return None
