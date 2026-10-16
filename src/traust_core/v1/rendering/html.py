from __future__ import annotations

from traust_core.v1.rendering.markdown import Report


class HtmlRenderer:
    media_type = "text/html"

    def render(self, report: Report) -> bytes:
        raise NotImplementedError("stub: replaces 5 render_html copies, reporting/render.py")
