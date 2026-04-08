"""
CyberNest Parser Registry.

Provides automatic discovery and routing of log parsers by format type.
Each parser module registers itself via the @register_parser decorator.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Callable, Optional

from shared.utils.logger import get_logger

logger = get_logger("parser.registry")

# ---------------------------------------------------------------------------
# Registry internals
# ---------------------------------------------------------------------------

# Maps format name -> parser callable(raw_log: str|dict) -> dict
_PARSER_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {}

# Ordered list of (priority, detector_func, parser_name) for auto-detection
_DETECTORS: list[tuple[int, Callable[[Any], bool], str]] = []


def register_parser(
    name: str,
    *,
    detector: Optional[Callable[[Any], bool]] = None,
    priority: int = 50,
):
    """Decorator to register a parser function.

    Args:
        name: Unique parser name (e.g. "windows_evtx", "syslog_rfc3164").
        detector: Optional callable(raw_data) -> bool that returns True if
                  this parser can handle the given raw log data.
        priority: Lower number = higher priority for auto-detection (default 50).
    """

    def wrapper(func: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        _PARSER_REGISTRY[name] = func
        if detector is not None:
            _DETECTORS.append((priority, detector, name))
            _DETECTORS.sort(key=lambda x: x[0])
        logger.debug("parser registered", parser=name)
        return func

    return wrapper


def get_parser(name: str) -> Optional[Callable[..., dict[str, Any]]]:
    """Get a parser by name."""
    return _PARSER_REGISTRY.get(name)


def detect_parser(raw_data: Any) -> Optional[str]:
    """Auto-detect which parser should handle the given raw data.

    Iterates through registered detectors in priority order and returns
    the name of the first parser whose detector returns True.
    """
    for _prio, detector_func, parser_name in _DETECTORS:
        try:
            if detector_func(raw_data):
                return parser_name
        except Exception:
            continue
    return None


def list_parsers() -> list[str]:
    """Return all registered parser names."""
    return list(_PARSER_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Auto-import all parser modules in this package
# ---------------------------------------------------------------------------

def _auto_discover() -> None:
    """Import all submodules so their @register_parser decorators execute."""
    package_path = __path__  # type: ignore[name-defined]
    for _importer, modname, _ispkg in pkgutil.iter_modules(package_path):
        if modname.startswith("_"):
            continue
        try:
            importlib.import_module(f"{__name__}.{modname}")
        except Exception as exc:
            logger.warning(
                "failed to load parser module",
                module=modname,
                error=str(exc),
            )


_auto_discover()
