"""user_agent: candidates from report text, typed consistently in the merge."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    name = "threat_intel_ingester_tool_ua"
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


def _uas(text: str) -> list[str]:
    return [i.value for i in _tool_mod.extract_iocs_regex(text, ["user_agent"])]


class TestPattern:
    @pytest.mark.parametrize("text, expected", [
        ("| **Python-urllib/3.12** | **User Agent** |", ["Python-urllib/3.12"]),
        ("| **python-requests/2.31.0** | **User Agent** |", ["python-requests/2.31.0"]),
        ("curl/7.88.1 and azure-toolkit/1.0.", ["curl/7.88.1", "azure-toolkit/1.0"]),
        ("Go-http-client/1.1 okhttp/4.9.0 Wget/1.21.4",
         ["Go-http-client/1.1", "okhttp/4.9.0", "Wget/1.21.4"]),
    ])
    def test_tool_and_library_strings(self, text, expected):
        assert _uas(text) == expected

    def test_a_browser_string_is_one_candidate(self):
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        assert _uas(f"| {ua} | User Agent |") == [ua]
        assert _uas(f'header "{ua}" was seen') == [ua]

    @pytest.mark.parametrize("text", [
        "GET / HTTP/1.1 over TLS/1.2, HTTPS/2.0 and SMB2/2.1",
        "see https://example.com/api/2.0/users and /v1/2.5",
        "T1078/004 on 10/14/2026, ratio 1/2, and/or",
        "ATT&CK v19.2 on Windows NT 10.0",
        "curl/8 without a dotted version",
    ])
    def test_not_user_agents(self, text):
        assert _uas(text) == []

    def test_never_crosses_a_line(self):
        # The page-join invariant in test_submitted_reconciliation depends on it.
        text = "Mozilla/5.0 (X11; Linux x86_64)\n\nAppleWebKit/537.36"
        assert all("\n" not in v for v in _uas(text))


class TestContract:
    def test_on_by_default(self):
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "input.schema.json").read_text(encoding="utf-8")
        )
        ioc_types = schema["properties"]["ioc_types"]
        assert "user_agent" in ioc_types["items"]["enum"]
        assert "user_agent" in ioc_types["default"]

    def test_output_schema_names_the_type(self):
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "output.schema.json").read_text(encoding="utf-8")
        )
        enum = schema["properties"]["result"]["properties"]["iocs"]["items"][
            "properties"]["ioc_type"]["enum"]
        assert "user_agent" in enum

    def test_accepted_as_an_input_type(self):
        result = _tool_mod.ThreatIntelIngester().validate_inputs(
            {"artifact_id": "a", "ioc_types": ["user_agent"]}
        )
        assert result.ok

    def test_every_pattern_is_a_valid_input_type_and_back(self):
        schema = json.loads(
            (PLUGIN_DIR / "schemas" / "input.schema.json").read_text(encoding="utf-8")
        )
        enum = set(schema["properties"]["ioc_types"]["items"]["enum"])
        assert enum == set(_tool_mod.IOC_PATTERNS)


class TestModelTyping:
    @pytest.mark.parametrize("spelling", ["user_agent", "User Agent", "user-agent", "UserAgent"])
    def test_spellings_converge(self, spelling):
        shaped, _ = _tool_mod._coerce_result_shape({
            "refined_iocs": [{"value": "curl/7.88.1", "ioc_type": spelling,
                              "confidence": "high"}],
        })
        assert shaped["refined_iocs"][0]["ioc_type"] == "user_agent"

    def test_other_types_are_untouched(self):
        shaped, _ = _tool_mod._coerce_result_shape({
            "refined_iocs": [{"value": "1.2.3.4", "ioc_type": "IP", "confidence": "high"}],
        })
        assert shaped["refined_iocs"][0]["ioc_type"] == "IP"


class TestFromAFetchedPage:
    def test_an_ioc_table_of_user_agents(self):
        pytest.importorskip("bs4")
        pytest.importorskip("markdownify")
        from framework.documents.web_markdown import html_to_markdown

        html = (
            "<main><h2>Indicators</h2><table>"
            "<tr><th>Indicator</th><th>Type</th></tr>"
            "<tr><td><b>Python-urllib/3.12</b></td><td><b>User Agent</b></td></tr>"
            "<tr><td><b>python-requests/2.31.0</b></td><td><b>User Agent</b></td></tr>"
            "<tr><td><b>curl/7.88.1</b></td><td><b>User Agent</b></td></tr>"
            "<tr><td><b>azure-toolkit/1.0</b></td><td><b>User Agent</b></td></tr>"
            "<tr><td><b>144.172.64[.]99</b></td><td><b>IP</b></td></tr>"
            "</table><p>Requests used HTTP/1.1 over TLS/1.2.</p></main>"
        )
        md = html_to_markdown(html).markdown
        assert _uas(md) == [
            "Python-urllib/3.12", "python-requests/2.31.0",
            "curl/7.88.1", "azure-toolkit/1.0",
        ]
