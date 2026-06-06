"""URL exfiltration scanner for egress validation (D5).

Scores outgoing URLs for patterns that indicate credential transmission or
data exfiltration. Separate from scan.py — URLs have different signal
shapes than document text; applying the document scanner to URLs produces
false positives on normal web content.

Python 3.6.8 compatible. No third-party dependencies.
"""
from __future__ import unicode_literals

import re

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs  # pragma: no cover

_SENSITIVE_PARAM_NAMES = frozenset([
    "api_key", "apikey", "api-key", "api_token", "token", "secret",
    "password", "passwd", "pwd", "credential", "credentials",
    "auth", "bearer", "session", "session_id", "sessionid",
    "id_rsa", "private_key", "privatekey", "access_key", "accesskey",
    "secret_key", "secretkey", "key",
])

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

_LOCALHOST_HOSTS = frozenset(["localhost", "127.0.0.1", "0.0.0.0", "::1"])

_BAND_HIGH = 50
_BAND_MEDIUM = 20


def scan(url):
    """Score a URL for exfiltration signals.

    Returns a dict matching promptguard.scan.scan() shape for consistency:
    risk_score, risk_band, recommend, signals, source, obfuscation, content_length.
    """
    url = url or ""
    found = []
    score = 0

    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return _result(0, found, url)

    # D5-1: sensitive query parameter name
    for name in qs:
        if name.lower() in _SENSITIVE_PARAM_NAMES:
            score += 50
            found.append({
                "id": "sensitive_param_name",
                "weight": 50,
                "description": "Query parameter name indicates credential/secret transmission",
                "evidence": "param: %s" % name,
            })
            break  # one hit is sufficient; don't stack per-param

    # D5-2: base64-encoded parameter value (>=20 chars)
    _b64_found = False
    for name, values in qs.items():
        if _b64_found:
            break
        for val in values:
            if _BASE64_RE.match(val):
                score += 30
                found.append({
                    "id": "base64_param_value",
                    "weight": 30,
                    "description": "Query parameter value resembles base64-encoded data",
                    "evidence": "param: %s = %s..." % (name, val[:24]),
                })
                _b64_found = True
                break

    # D5-3: localhost/loopback with query parameters
    host = (parsed.hostname or "").lower()
    if host in _LOCALHOST_HOSTS and parsed.query:
        score += 20
        found.append({
            "id": "localhost_exfil",
            "weight": 20,
            "description": "Request to loopback host with query parameters",
            "evidence": "host: %s" % host,
        })

    score = min(100, score)
    return _result(score, found, url)


def _band(score):
    if score >= _BAND_HIGH:
        return "high"
    if score >= _BAND_MEDIUM:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _recommend(band):
    return "escalate" if band in ("high", "medium") else "allow"


def _result(score, signals, url=""):
    b = _band(score)
    return {
        "source": "url",
        "risk_score": score,
        "risk_band": b,
        "recommend": _recommend(b),
        "signals": signals,
        "obfuscation": {},
        "content_length": len(url) if isinstance(url, str) else 0,
    }
