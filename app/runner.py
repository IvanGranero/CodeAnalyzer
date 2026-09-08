"""CLI adapter for the UI-neutral scan application service."""

import asyncio
import logging
import sys
from pathlib import Path

from app.application import ScanApplication, ScanRequest
from app.context import build_app_context, shutdown

logger = logging.getLogger(__name__)


async def run(args) -> None:
    """Translate parsed CLI arguments into an application request."""
    from config import settings

    source_directory = Path(args.source_dir).resolve()
    if not source_directory.is_dir():
        logger.error("The directory '%s' does not exist.", source_directory)
        sys.exit(1)

    try:
        app_context = build_app_context(settings)
    except Exception as exc:
        logger.error("Failed to initialize core services: %s", exc)
        sys.exit(1)

    def confirm(message: str) -> bool:
        try:
            return input(f"{message} (y/n): ").lower() == "y"
        except KeyboardInterrupt:
            return False

    application = ScanApplication(
        app_context,
        max_candidates_per_target=settings.scan_max_candidates_per_target,
        confirm=confirm,
    )
    request = ScanRequest(
        source_directory=source_directory,
        limit=args.limit,
        scan_all=args.scan_all,
        target_file=args.target_file,
        resume=args.resume,
        skip_ingest=args.skip_ingest,
        skip_exploit=args.skip_exploit,
        exploit_only=Path(args.exploit_only) if args.exploit_only else None,
    )
    try:
        await application.run(request)
    except asyncio.CancelledError:
        logger.info("Main execution was cancelled.")
    except Exception:
        logger.exception("An unhandled error occurred during execution:")
    finally:
        shutdown(app_context)
