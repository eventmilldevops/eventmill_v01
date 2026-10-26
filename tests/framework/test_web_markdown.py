"""Tests for framework.documents.web_markdown: page to report Markdown."""

from __future__ import annotations

import pytest

pytest.importorskip("bs4")
pytest.importorskip("markdownify")

from framework.documents.web_markdown import (  # noqa: E402
    html_to_markdown,
    split_markdown_sections,
    text_to_markdown,
)

REPORT = """<!doctype html><html><head>
<title>Storm-0000 campaign | Vendor Blog</title>
<meta property="og:title" content="Storm-0000 campaign">
<script>var tracking = "198.51.100.1";</script><style>.x{}</style>
</head><body>
<nav><a href="/">Home</a> <a href="/products">Products</a></nav>
<main>
  <h1>Storm-0000 campaign</h1>
  <p>The actor used <a href="https://docs.vendor.example/guide">our guidance</a> poorly.</p>
  <p>""" + "Narrative describing the intrusion in detail. " * 20 + """</p>
  <h2>Indicators of compromise</h2>
  <table>
    <tr><th>Indicator</th><th>Type</th></tr>
    <tr><td><b>144.172.64[.]128</b></td><td>IP</td></tr>
    <tr><td>evil_domain[.]com</td><td>Domain</td></tr>
    <tr><td>C:\\Windows\\Temp\\a_b*.exe</td><td>Path</td></tr>
  </table>
  <h2>Hunting</h2>
  <pre><code>let IPs = dynamic(["144.172.64.60"]);
| where name == "a_b"</code></pre>
  <img src="/fig1.png" alt="Figure 1: attack flow">
  <article class="card"><h3>Related: Storm-9999 phishing</h3><p>Teaser.</p></article>
  <footer>Share this post</footer>
</main>
<footer>Copyright Vendor</footer>
</body></html>"""


@pytest.fixture(scope="module")
def page():
    return html_to_markdown(REPORT.encode("utf-8"), encoding="utf-8")


class TestVerbatimIndicators:
    def test_defanged_values_are_not_escaped(self, page):
        md = page.markdown
        assert "144.172.64[.]128" in md
        assert "evil_domain[.]com" in md
        assert "\\[" not in md and "\\_" not in md

    def test_paths_and_asterisks_survive(self, page):
        assert "C:\\Windows\\Temp\\a_b*.exe" in page.markdown


class TestStructure:
    def test_table_rows_stay_rows(self, page):
        assert "| 144.172.64[.]128 | IP |" in page.markdown.replace("**", "")

    def test_code_is_fenced(self, page):
        assert '```\nlet IPs = dynamic(["144.172.64.60"]);' in page.markdown

    def test_headings_are_atx(self, page):
        assert "## Indicators of compromise" in page.markdown


class TestNoise:
    def test_link_targets_dropped_text_kept(self, page):
        assert "our guidance" in page.markdown
        assert "docs.vendor.example" not in page.markdown

    def test_images_keep_only_alt_text(self, page):
        assert "[Image: Figure 1: attack flow]" in page.markdown
        assert "fig1.png" not in page.markdown

    def test_scripts_nav_and_footers_removed(self, page):
        md = page.markdown
        assert "198.51.100.1" not in md
        assert "Products" not in md
        assert "Copyright" not in md and "Share this post" not in md

    def test_related_post_cards_removed(self, page):
        assert "Storm-9999" not in page.markdown

    def test_the_post_in_its_own_article_is_never_a_card(self):
        html = (
            "<html><body><main><article><h1>Post</h1><p>"
            + "report body " * 300
            + "</p></article><section>" + "comment " * 50
            + "</section></main></body></html>"
        )
        assert "report body" in html_to_markdown(html).markdown

    def test_title_from_og_title(self, page):
        assert page.title == "Storm-0000 campaign"
        assert page.markdown.startswith("# Storm-0000 campaign")


class TestContentRoot:
    def test_main_beats_a_larger_count_of_small_articles(self):
        cards = "".join(
            f"<article><h3>Other post {i}</h3><p>teaser</p></article>" for i in range(5)
        )
        html = (
            "<html><body>" + cards
            + "<main><h1>Real</h1><p>" + "report text " * 200 + "</p></main></body></html>"
        )
        md = html_to_markdown(html).markdown
        assert "report text" in md
        assert "Other post" not in md

    def test_aspnet_form_wrapper_does_not_swallow_the_page(self):
        html = (
            "<html><body><form id='aspnetForm'><div><h1>Advisory</h1>"
            "<p>Indicator 203.0.113[.]9 seen.</p><input type='hidden' value='x'>"
            "</div></form></body></html>"
        )
        md = html_to_markdown(html).markdown
        assert "203.0.113[.]9" in md

    def test_title_prepended_when_the_body_lacks_it(self):
        html = "<html><head><title>Advisory AA26-001</title></head><body><p>Body text.</p></body></html>"
        assert html_to_markdown(html).markdown.startswith("# Advisory AA26-001")


class TestPlainText:
    def test_decoded_verbatim(self):
        assert text_to_markdown(b"1.2.3[.]4\r\nevil_x[.]com\r\n\r\n\r\n\r\nend") == (
            "1.2.3[.]4\nevil_x[.]com\n\nend"
        )

    def test_bad_charset_falls_back(self):
        assert text_to_markdown(b"abc", encoding="no-such-codec") == "abc"


class TestSections:
    def test_split_at_headings(self):
        md = "# Title\n\nintro\n\n## A\n\na text\n\n## B\n\nb text"
        assert split_markdown_sections(md) == [
            "# Title\n\nintro", "## A\n\na text", "## B\n\nb text",
        ]

    def test_headings_inside_code_are_not_boundaries(self):
        md = "## Query\n\n```\n# not a heading\nSELECT 1\n```\n\n## Next\n\nx"
        sections = split_markdown_sections(md)
        assert len(sections) == 2
        assert "# not a heading" in sections[0]

    def test_text_before_the_first_heading_is_kept(self):
        assert split_markdown_sections("preamble\n\n## A\n\nx")[0] == "preamble"

    def test_long_section_is_cut_with_fences_balanced(self):
        rows = "\n".join(f"198.51.{i // 250}.{i % 250}" for i in range(400))
        md = "## IOCs\n\n```\n" + rows + "\n```"
        sections = split_markdown_sections(md, max_section_chars=1000)
        assert len(sections) > 1
        for sec in sections:
            assert sec.count("```") % 2 == 0, sec[:80]
            assert len(sec) <= 1000 + 10
        joined = "\n".join(sections)
        for i in (0, 199, 399):
            assert f"198.51.{i // 250}.{i % 250}" in joined

    def test_heading_only_sections_are_kept_blank_lines_are_not(self):
        md = "## A\n\n\n\n## B\n\nb"
        assert split_markdown_sections(md) == ["## A", "## B\n\nb"]

    def test_empty_input(self):
        assert split_markdown_sections("") == []
