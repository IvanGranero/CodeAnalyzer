import asyncio
import logging
import sys
import warnings


class _QuietTransportFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.getMessage().startswith("HTTP Request:")

from app.cli import build_parser
from app.runner import run

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
for handler in logging.getLogger().handlers:
    handler.addFilter(_QuietTransportFilter())
logger = logging.getLogger(__name__)


logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)
logging.getLogger("openai").setLevel(logging.ERROR)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)
warnings.filterwarnings(
    "ignore",
    message="Expected a result with a single record, but found multiple.",
    category=UserWarning,
    module=r"neo4j\..*",
)


def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        if args.repl:
            logging.getLogger().setLevel(logging.WARNING)
            from pathlib import Path

            from app.context import build_app_context, shutdown
            from app.repl import ApplicationRepl

            source_directory = Path(args.source_dir).resolve()
            if not source_directory.is_dir():
                parser.error(f"The directory '{source_directory}' does not exist.")
            app_context = build_app_context()
            try:
                ApplicationRepl(app_context, source_directory).run()
            finally:
                shutdown(app_context)
        else:
            asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()
