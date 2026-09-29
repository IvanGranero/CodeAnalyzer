import logging
import sys
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def _flatten_with_descriptions(application_domains: list, application_roots: Optional[list]) -> list[dict]:
    """Build one flat [{folder, description}] list: every application_root, each annotated
    with the name of the application_domains group it belongs to (if any). A folder the
    model never grouped still appears, just without a description, so nothing is hidden."""
    folder_description: dict[str, str] = {}
    order: list[str] = []

    def add(folder: str, description: str = "") -> None:
        key = folder.casefold()
        if key not in folder_description:
            folder_description[key] = description
            order.append(folder)
        elif description and not folder_description[key]:
            folder_description[key] = description

    for item in application_domains or []:
        if isinstance(item, dict) and isinstance(item.get("folders"), list) and item["folders"]:
            name = str(item.get("name") or "").strip()
            for folder in item["folders"]:
                folder = str(folder).strip()
                if folder:
                    add(folder, name)
        elif isinstance(item, str) and item.strip():
            add(item.strip())

    for root in application_roots or []:
        root = str(root).strip()
        if root:
            add(root)

    return [{"folder": folder, "description": folder_description[folder.casefold()]} for folder in order]


def select_domain(
    application_domains: list,
    scan_all: bool,
    target_file: Optional[str],
    input_fn: Callable[[str], str] = input,
    application_roots: Optional[list] = None,
) -> Optional[str]:
    """
    Phase 2.5: ask the operator which application folder to scan, unless a specific target
    file was given or a global scan was requested. `input_fn` is injectable so this stays
    unit-testable without real stdin.
    """
    if target_file:
        logger.info(f"Target file '{target_file}' specified. Bypassing domain selection.")
        return None
    if scan_all:
        logger.info("--scan-all specified. Bypassing domain selection to scan everything globally.")
        return None

    entries = _flatten_with_descriptions(application_domains, application_roots)
    if not entries:
        return None

    print("\n" + "=" * 60)
    logger.info("Discovered the following application folders:")
    for i, entry in enumerate(entries, 1):
        label = f"  {i}. {entry['folder']}"
        if entry["description"]:
            label += f" ({entry['description']})"
        print(label)
    all_idx = len(entries) + 1
    print(f"  {all_idx}. All")
    print("=" * 60)

    try:
        choice = input_fn(f"Which folder would you like to scan? (1-{all_idx}): ")
        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            return entries[idx]["folder"]
    except ValueError:
        logger.warning("Invalid input. Defaulting to a full scan.")
    except KeyboardInterrupt:
        logger.info("\nScan aborted by user.")
        sys.exit(0)
    return None