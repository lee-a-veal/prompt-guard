"""Scanner adapter — lazy bridge to promptguard.scan/urlscan/session.

Imports are conditional so the plugin degrades to a no-op if the scanner
package is unavailable (missing, broken install, etc.). All functions return
None on failure rather than raising, keeping the host agent loop safe.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Package location — prefer the project checkout, fall back to installed pkg
# ---------------------------------------------------------------------------

_SCAN_PKG_DIR = os.environ.get(
    "PROMPTGUARD_DIR",
    os.path.expanduser("~/projects/prompt-guard"),
)

# Make the project importable if it exists
if os.path.isdir(_SCAN_PKG_DIR) and _SCAN_PKG_DIR not in sys.path:
    sys.path.insert(0, _SCAN_PKG_DIR)

# ---------------------------------------------------------------------------
# Lazy imports with availability flags
# ---------------------------------------------------------------------------

_scan = None
_urlscan = None
_session = None
scanner_available = False
urlscan_available = False
session_available = False

try:
    from promptguard.scan import scan as _scan_fn
    _scan = _scan_fn
    scanner_available = True
except ImportError:
    logger.debug("promptguard.scan not available — content scanning disabled")

try:
    from promptguard.urlscan import scan as _urlscan_fn
    _urlscan = _urlscan_fn
    urlscan_available = True
except ImportError:
    logger.debug("promptguard.urlscan not available — URL scanning disabled")

try:
    from promptguard import session as _session_mod
    _session = _session_mod
    session_available = True
except ImportError:
    logger.debug("promptguard.session not available — taint tracking disabled")


# ---------------------------------------------------------------------------
# Public API — thin wrappers that swallow internal errors
# ---------------------------------------------------------------------------


def scan_content(text: str, source: str = "hermes") -> Optional[Dict[str, Any]]:
    """Scan text for injection signals. Returns scan result dict or None."""
    if not scanner_available or _scan is None:
        return None
    try:
        return _scan(text, source=source)
    except Exception as exc:
        logger.warning("prompt-guard scan error: %s", exc)
        return None


def scan_url(url: str) -> Optional[Dict[str, Any]]:
    """Scan a URL for exfiltration risk. Returns urlscan result dict or None."""
    if not urlscan_available or _urlscan is None:
        return None
    try:
        return _urlscan(url)
    except Exception as exc:
        logger.warning("prompt-guard urlscan error: %s", exc)
        return None


def get_taint_count() -> Optional[int]:
    """Get current session taint count. Returns int or None."""
    if not session_available or _session is None:
        return None
    try:
        return _session.get_taint_count()
    except Exception:
        return None


def record_taint(tool_name: str) -> None:
    """Record a taint event for the given tool."""
    if not session_available or _session is None:
        return
    try:
        _session.record_taint(tool_name)
    except Exception:
        pass


def record_tool_call(tool_name: str, label: str = "") -> None:
    """Record a tool call in the session for behavioral analysis (D3/D6)."""
    if not session_available or _session is None:
        return
    try:
        _session.record_tool_call(tool_name, label)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Guard module — high-level platform-agnostic interface
# ---------------------------------------------------------------------------

guard_available = False

try:
    from promptguard.guard import check_output, check_pre_tool, check_memory_write, GuardResult
    guard_available = True
except ImportError:
    logger.debug("promptguard.guard not available — falling back to direct scanner calls")