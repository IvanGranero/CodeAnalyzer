"""Synchronous fan-out for structured application events."""

import logging

from app.events import AppEvent, EventSink

logger = logging.getLogger(__name__)


class EventBus(EventSink):
    """Deliver each event to multiple frontend, state, and logging consumers."""

    def __init__(self, *sinks: EventSink) -> None:
        self._sinks = list(sinks)

    def subscribe(self, sink: EventSink) -> None:
        """Register a consumer for future events."""
        if sink not in self._sinks:
            self._sinks.append(sink)

    def unsubscribe(self, sink: EventSink) -> None:
        """Stop delivering events to a consumer."""
        if sink in self._sinks:
            self._sinks.remove(sink)

    def emit(self, event: AppEvent) -> None:
        """Fan out one immutable event to all current consumers."""
        for sink in tuple(self._sinks):
            try:
                sink.emit(event)
            except Exception:
                logger.exception("Event consumer failed for %s", event.kind)
