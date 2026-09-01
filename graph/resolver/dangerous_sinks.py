import logging

logger = logging.getLogger(__name__)


class DangerousSinksMixin:
    """Flags functions that are known memory/NVM vulnerability sinks."""

    def _flag_dangerous_sinks(self):
        """Flags functions that are known vulnerability sinks."""
        logger.info("Flagging Dangerous Memory and NVM Sinks...")
        query = """
        MATCH (f:Function)
        WHERE toLower(f.name) CONTAINS 'memcpy'
           OR toLower(f.name) CONTAINS 'memcopy'
           OR toLower(f.name) CONTAINS 'memset'
           OR toLower(f.name) CONTAINS 'memmove'
           OR toLower(f.name) CONTAINS 'strcpy'
           OR toLower(f.name) CONTAINS 'sprintf'
           OR f.name STARTS WITH 'NvM_Write'
           OR f.name STARTS WITH 'Fls_Write'
        SET f.is_dangerous_sink = true
        RETURN count(f) AS sink_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["sink_count"] if result else 0
                logger.info(f"Flagged {count} functions as dangerous memory sinks.")
        except Exception as e:
            logger.error(f"Failed to flag dangerous sinks: {e}")
            raise
