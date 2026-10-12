"""
Tests for subdomain_takeover.yaml condition logic.

Regression tests for issue #1491: Flexbe and Uptimerobot checks were using
condition_type: or, which caused false positives on any server returning a
plain 404. Both checks require the service-specific body fingerprint AND a
404 status code (condition_type: and) to fire.
"""

import re
import os

import pytest
import yaml


YAML_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "nettacker",
    "modules",
    "vuln",
    "subdomain_takeover.yaml",
)


def load_module():
    with open(YAML_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_service(name):
    module = load_module()
    checks = (
        module["payloads"][0]["steps"][0]["response"]["conditions"][
            "iterative_response_match"
        ]
    )
    return checks[name]["response"]


# ---------------------------------------------------------------------------
# Flexbe
# ---------------------------------------------------------------------------


class TestFlexbeConditionType:
    def test_condition_type_is_and(self):
        """Flexbe must require both fingerprint body AND 404 status."""
        svc = get_service("Flexbe Takeover")
        assert svc["condition_type"] == "and", (
            "Flexbe condition_type must be 'and' to avoid false positives "
            "on generic 404 responses (issue #1491)"
        )

    def test_has_content_condition(self):
        svc = get_service("Flexbe Takeover")
        assert "content" in svc["conditions"]

    def test_has_status_code_condition(self):
        svc = get_service("Flexbe Takeover")
        assert "status_code" in svc["conditions"]

    def test_content_regex_matches_flexbe_fingerprint(self):
        svc = get_service("Flexbe Takeover")
        pattern = svc["conditions"]["content"]["regex"]
        genuine = "Domain isn't configured and flexbe is the platform"
        assert re.search(pattern, genuine, re.IGNORECASE | re.DOTALL), (
            "Content regex must still match a genuine Flexbe takeover response"
        )

    def test_content_regex_does_not_match_generic_404(self):
        svc = get_service("Flexbe Takeover")
        pattern = svc["conditions"]["content"]["regex"]
        generic = "<html><body><h1>404 Not Found</h1></body></html>"
        assert not re.search(pattern, generic, re.IGNORECASE | re.DOTALL), (
            "Content regex must NOT match a generic 404 page"
        )

    def test_status_code_regex_matches_404(self):
        svc = get_service("Flexbe Takeover")
        pattern = svc["conditions"]["status_code"]["regex"]
        assert re.search(pattern, "404"), "Status code regex must match '404'"

    def test_status_code_regex_does_not_match_200(self):
        svc = get_service("Flexbe Takeover")
        pattern = svc["conditions"]["status_code"]["regex"]
        assert not re.fullmatch(pattern, "200"), (
            "Status code regex must not match '200'"
        )


# ---------------------------------------------------------------------------
# Uptimerobot
# ---------------------------------------------------------------------------


class TestUptimerorbotConditionType:
    def test_condition_type_is_and(self):
        """Uptimerobot must require both fingerprint body AND 404 status."""
        svc = get_service("Uptimerobot Takeover")
        assert svc["condition_type"] == "and", (
            "Uptimerobot condition_type must be 'and' to avoid false positives "
            "on generic 404 responses (issue #1491)"
        )

    def test_has_content_condition(self):
        svc = get_service("Uptimerobot Takeover")
        assert "content" in svc["conditions"]

    def test_has_status_code_condition(self):
        svc = get_service("Uptimerobot Takeover")
        assert "status_code" in svc["conditions"]

    def test_content_regex_matches_uptimerobot_fingerprint(self):
        svc = get_service("Uptimerobot Takeover")
        pattern = svc["conditions"]["content"]["regex"]
        genuine = "page not found"
        assert re.search(pattern, genuine), (
            "Content regex must still match the genuine Uptimerobot fingerprint"
        )

    def test_content_regex_does_not_match_generic_404_body(self):
        svc = get_service("Uptimerobot Takeover")
        pattern = svc["conditions"]["content"]["regex"]
        generic = "<html><body><h1>404 Not Found</h1><p>The requested URL was not found.</p></body></html>"
        assert not re.search(pattern, generic), (
            "Content regex must NOT match a generic 404 HTML body"
        )

    def test_status_code_regex_matches_404(self):
        svc = get_service("Uptimerobot Takeover")
        pattern = svc["conditions"]["status_code"]["regex"]
        assert re.search(pattern, "404"), "Status code regex must match '404'"
