"""Friendly, stable error classification for long-running CLI/REPL sessions.

The purpose of this module is to keep interactive sessions (REPL, scripts) alive
when the underlying infrastructure fails transiently -- for example when the user
loses network connectivity and the LLM/graph providers raise opaque connection
errors. Instead of letting an opaque ``Connection error.`` bubble up, we map the
exception to a concise, actionable message and indicate whether a retry is likely
to help.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Exception types that indicate the network/proxy/DNS layer failed. Imported
# lazily so importing this module never depends on optional provider packages.
_CONNECTION_EXCEPTIONS: tuple[type[BaseException], ...] | None = None


def _connection_exception_types() -> tuple[type[BaseException], ...]:
    """Return the network/transport exception classes we recognize.

    The list is resolved once, lazily. Wrappers change across provider SDK
    versions, so we match on both the concrete classes we know and a name
    suffix heuristic for anything we have not seen yet.
    """
    global _CONNECTION_EXCEPTIONS
    if _CONNECTION_EXCEPTIONS is not None:
        return _CONNECTION_EXCEPTIONS

    types: list[type[BaseException]] = []
    import httpx  # noqa: PLC0415 (lazy optional dependency)

    candidates = [
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.NetworkError,
        httpx.RemoteProtocolError,
        httpx.TransportError,
    ]
    for candidate in candidates:
        try:
            types.append(candidate)
        except Exception:  # pragma: no cover - defensive against SDK drift
            continue

    try:
        from openai import APIConnectionError, APITimeoutError  # noqa: PLC0415
        types.append(APIConnectionError)
        types.append(APITimeoutError)
    except Exception:  # pragma: no cover - optional
        pass

    try:
        from httpcore import ConnectError as _HttpCoreConnectError  # noqa: PLC0415
        types.append(_HttpCoreConnectError)
    except Exception:  # pragma: no cover - optional
        pass

    _CONNECTION_EXCEPTIONS = tuple(types)
    return _CONNECTION_EXCEPTIONS


def _is_connection_error(exc: Exception) -> bool:
    """Return True when ``exc`` (or its cause chain) is a transport/network error."""
    if isinstance(exc, _connection_exception_types()):
        return True

    # Match by class name suffix to catch provider wrappers (e.g.
    # APIConnectionError, ConnectError, TransportError) that we could not import.
    for cls in type(exc).__mro__:
        name = cls.__name__
        if name in {"APIConnectionError", "ConnectError", "ConnectTimeout", "ProxyError", "TransportError", "NetworkError"}:
            return True
    # Walk the __cause__/__context__ chain for wrapped connect failures.
    cause = getattr(exc, "__cause__", None)
    if cause is not None and cause is not exc:
        return _is_connection_error(cause)
    context = getattr(exc, "__context__", None)
    if context is not None and context is not exc:
        return _is_connection_error(context)
    return False


def _is_empty_response(exc: Exception) -> bool:
    """Return True when the provider returned no usable assistant content."""
    name = type(exc).__name__
    if name == "EmptyLLMResponseError":
        return True
    message = str(exc).lower()
    return "empty_response" in message or "no assistant content" in message


def friendly_error_message(exc: Exception) -> str:
    """Return a concise, stable, user-facing message for ``exc``.

    Network/connectivity failures get an actionable offline message; everything
    else is reported with its class name so it stays debuggable without dumping
    a full traceback to the terminal.
    """
    if _is_connection_error(exc):
        return (
            "Connection unavailable (offline or provider unreachable). "
            "Check your network and try again in a moment."
        )
    if _is_empty_response(exc):
        return "The model returned no response text. This is usually transient; please retry."
    message = str(exc).strip()
    if message:
        return message
    return type(exc).__name__


def log_error_quietly(exc: Exception, context: str = "operation") -> str:
    """Log the full detail but return a short friendly message for the user.

    An interactive session should not print a giant traceback for every
    transient provider failure, yet the detail must not be lost -- it is logged
    at DEBUG level for the logs file.
    """
    logger.debug("REPL %s failed: %s (%s)", context, exc, type(exc).__name__, exc_info=True)
    return friendly_error_message(exc)


def retry_hint(exc: Exception) -> str:
    """Return a short retry guidance suffix for ``exc``."""
    if is_retryable(exc):
        return " You can simply run the same command again once connectivity returns."
    return ""


def is_retryable(exc: Exception) -> bool:
    """Return True when retrying the operation is likely to help.

    Network/connectivity failures and empty model responses are inherently
    transient; everything else (contract errors, validation failures) is not
    helped by an immediate silent retry.
    """
    return _is_connection_error(exc) or _is_empty_response(exc)


def format_repl_error(exc: Exception, context: str = "operation") -> str:
    """Combine classification, logging, and retry hint into one printed line."""
    return friendly_error_message(exc) + retry_hint(exc)


__all__ = [
    "friendly_error_message",
    "log_error_quietly",
    "retry_hint",
    "is_retryable",
    "format_repl_error",
]
