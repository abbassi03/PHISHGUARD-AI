from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit

try:
    import tldextract  # type: ignore

    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # optional robust fallback for offline/minimal environments
    _TLD_EXTRACTOR = None

import pandas as pd

SUSPICIOUS_TOKENS = (
    "account", "auth", "bank", "bonus", "confirm", "free", "gift", "invoice",
    "login", "log-in", "password", "pay", "secure", "signin", "sign-in",
    "support", "update", "verify", "wallet", "webscr", "recover", "unlock",
)
PERCENT_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
TOKEN_RE = re.compile(r"[a-z0-9-]+", re.IGNORECASE)

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_at_symbols",
    "num_subdomains_estimated",
    "has_ip_host",
    "uses_https_scheme",
    "has_nonstandard_port",
    "num_percent_encodings",
    "num_suspicious_tokens",
    "url_entropy",
    "has_fragment",
    "num_query_parameters",
    "num_slashes",
    "has_punycode_label",
    "hostname_digit_ratio",
]

# A compact fallback set for offline environments. tldextract, when installed,
# uses its bundled Public Suffix List snapshot and is preferred for domain grouping.
_COMMON_MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "co.nz",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "co.za", "com.sg",
}


def normalize_url(value: object) -> tuple[str, object, str]:
    """Validate and parse an URL string without performing any network request."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        raise ValueError("URL is empty.")
    raw = str(value).strip()
    if not raw:
        raise ValueError("URL is empty.")
    if len(raw) > 4096:
        raise ValueError("URL exceeds the 4,096-character safety limit.")
    if any(ord(ch) < 32 or ch.isspace() for ch in raw):
        raise ValueError("URL contains whitespace or control characters.")

    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else f"http://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Accessing .port also validates malformed port values.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported in this version.")
    if not hostname:
        raise ValueError("URL must contain a hostname.")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Hostname could not be normalized using IDNA.") from exc
    if not hostname or "." not in hostname and hostname not in {"localhost"}:
        # Single-label hosts can be valid internally, but are atypical for this task.
        if hostname != "localhost":
            raise ValueError("URL hostname appears incomplete.")
    return raw, parsed, hostname


def registered_domain(hostname: str) -> str:
    """Return a registrable domain for grouping; offline fallback is documented."""
    try:
        if _TLD_EXTRACTOR is not None:
            result = _TLD_EXTRACTOR(hostname)
            domain = result.top_domain_under_public_suffix
            if domain:
                return domain
    except Exception:
        pass
    labels = hostname.lower().strip(".").split(".")
    if len(labels) <= 2:
        return hostname.lower()
    suffix2 = ".".join(labels[-2:])
    take = 3 if suffix2 in _COMMON_MULTI_LABEL_SUFFIXES else 2
    return ".".join(labels[-take:])


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return float(-sum((count / length) * math.log2(count / length) for count in counts.values()))


def extract_url_features(value: object) -> dict[str, float]:
    """Extract ordered, numeric URL-string features. This function never visits the URL."""
    raw, parsed, hostname = normalize_url(value)
    lower = raw.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        has_ip = 1.0
    except ValueError:
        has_ip = 0.0

    host_labels = [part for part in hostname.split(".") if part]
    base_domain = registered_domain(hostname)
    subdomain_labels = max(len(host_labels) - len(base_domain.split(".")), 0)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port: {exc}") from exc
    nonstandard_port = float(port is not None and port not in {80, 443})
    tokens = TOKEN_RE.findall(lower)
    suspicious_count = sum(tokens.count(token) for token in SUSPICIOUS_TOKENS)
    hostname_digits = sum(ch.isdigit() for ch in hostname)
    percent_count = len(PERCENT_ESCAPE_RE.findall(raw))
    query_count = len(parse_qsl(query, keep_blank_values=True)) if query else 0

    values: dict[str, float] = {
        "url_length": float(len(raw)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "fragment_length": float(len(fragment)),
        "num_dots": float(raw.count(".")),
        "num_hyphens": float(raw.count("-")),
        "num_underscores": float(raw.count("_")),
        "num_digits": float(sum(ch.isdigit() for ch in raw)),
        "num_at_symbols": float(raw.count("@")),
        "num_subdomains_estimated": float(subdomain_labels),
        "has_ip_host": has_ip,
        "uses_https_scheme": float(parsed.scheme.lower() == "https"),
        "has_nonstandard_port": nonstandard_port,
        "num_percent_encodings": float(percent_count),
        "num_suspicious_tokens": float(suspicious_count),
        "url_entropy": shannon_entropy(raw),
        "has_fragment": float(bool(fragment)),
        "num_query_parameters": float(query_count),
        "num_slashes": float(raw.count("/")),
        "has_punycode_label": float(any(label.startswith("xn--") for label in host_labels)),
        "hostname_digit_ratio": float(hostname_digits / max(len(hostname), 1)),
    }
    # Keep feature order explicit and reject accidental schema drift.
    return {name: values[name] for name in FEATURE_NAMES}


def extract_features_frame(urls: Iterable[object]) -> pd.DataFrame:
    rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float64")
