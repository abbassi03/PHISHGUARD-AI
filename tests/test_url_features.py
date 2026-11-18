import math
import pytest

from phishguard.features.url_features import FEATURE_NAMES, extract_url_features, normalize_url, registered_domain


def test_extracts_stable_url_only_feature_schema():
    features = extract_url_features("https://login.example.com/account/verify?id=42#top")
    assert list(features) == FEATURE_NAMES
    assert features["uses_https_scheme"] == 1.0
    assert features["hostname_length"] > 0
    assert features["num_query_parameters"] == 1.0
    assert features["has_fragment"] == 1.0
    assert all(math.isfinite(value) for value in features.values())


def test_bare_domain_is_normalized_without_network():
    raw, parsed, host = normalize_url("example.com/login")
    assert raw == "example.com/login"
    assert parsed.scheme == "http"
    assert host == "example.com"


def test_ip_host_and_nonstandard_port_are_detected():
    features = extract_url_features("http://192.0.2.10:8080/auth")
    assert features["has_ip_host"] == 1.0
    assert features["has_nonstandard_port"] == 1.0


@pytest.mark.parametrize("value", ["", "   ", "javascript:alert(1)", "https:///missing-host", "https://bad host.com"])
def test_invalid_urls_are_rejected(value):
    with pytest.raises(ValueError):
        extract_url_features(value)


def test_domain_group_is_not_empty():
    assert registered_domain("login.example.co.uk") == "example.co.uk"
