"""Source ingestion services."""

__all__ = ["IngestionService"]


def __getattr__(name: str):
	if name == "IngestionService":
		from tools.ingestion.ingestion_service import IngestionService

		return IngestionService
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
