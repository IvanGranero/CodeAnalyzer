import asyncio
import logging
import sys

from app.cli import build_parser
from app.runner import run

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress noisy third-party library logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)


def main() -> None:
    args = build_parser().parse_args()
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()
