from datetime import UTC, datetime
from html.parser import HTMLParser

from traust_core.v1.rendering import MarkdownRenderer, Report, Section, Table, markdown_table


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.names.append(tag)


def test_external_report_values_cannot_emit_active_html() -> None:
    hostile = '<img src=x onerror="alert(1)"> & <iframe src="https://example.test">'
    report = Report(
        title=hostile,
        generated_at=datetime(2026, 11, 4, tzinfo=UTC),
        sections=(Section(heading=hostile, table=Table(columns=(hostile,), rows=((hostile,),))),),
        sources=(hostile,),
    )
    output = MarkdownRenderer().render(report).decode()
    parsed = Tags()
    parsed.feed(output)
    assert parsed.names == []
    assert "&lt;img" in output
    assert "&amp;" in output


def test_table_values_cannot_create_links_formatting_or_extra_rows() -> None:
    hostile = "[trust me](javascript:alert(1)) *approved*\n| forged |"
    lines = markdown_table(("Finding",), ((hostile,),))
    assert len(lines) == 3
    assert r"\*approved\*" in lines[2]
    assert "[trust me](javascript:" not in lines[2]
    assert r"\[trust me\]" in lines[2]
    assert r"\| forged \|" in lines[2]


def test_literal_backslashes_do_not_disable_table_separator_escaping() -> None:
    row = markdown_table(("Path",), ((r"a\|b",),))[-1]
    assert r"a\\\|b" in row
