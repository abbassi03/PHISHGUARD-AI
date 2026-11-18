from __future__ import annotations

from datetime import datetime, timezone
from html import escape

import pandas as pd


def dataframe_to_csv(frame: pd.DataFrame) -> bytes:
    """Export CSV while neutralizing spreadsheet-formula prefixes in text cells."""
    safe = frame.copy()
    dangerous_prefixes = ("=", "+", "-", "@", "\t", "\r")
    for column in safe.columns:
        if pd.api.types.is_object_dtype(safe[column]) or pd.api.types.is_string_dtype(safe[column]):
            safe[column] = safe[column].map(
                lambda value: "'" + value
                if isinstance(value, str) and value.lstrip().startswith(dangerous_prefixes)
                else value
            )
    return safe.to_csv(index=False).encode("utf-8-sig")


def build_html_report(title: str, sections: dict[str, str], tables: dict[str, pd.DataFrame] | None = None) -> bytes:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    section_html = "".join(
        f"<section><h2>{escape(name)}</h2><p>{escape(text)}</p></section>"
        for name, text in sections.items()
    )
    table_html = ""
    for name, frame in (tables or {}).items():
        table_html += f"<section><h2>{escape(name)}</h2>{frame.to_html(index=False, border=0, classes='data')}</section>"
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title>
<style>body{{font:15px/1.6 Inter,Segoe UI,sans-serif;background:#f4f6fb;color:#18233b;margin:0;padding:32px}}main{{max-width:1100px;margin:auto;background:#fff;padding:36px;border-radius:18px;box-shadow:0 12px 40px #18233b12}}h1{{color:#24345a;margin-bottom:4px}}h2{{color:#6658d3;margin-top:28px}}.muted{{color:#6c7890}}.data{{border-collapse:collapse;width:100%;font-size:13px}}.data th,.data td{{padding:9px 11px;border-bottom:1px solid #e8ebf3;text-align:left}}.data th{{background:#f4f5fb}}.notice{{background:#fff8e8;padding:14px;border-left:4px solid #e5a43b;border-radius:6px}}</style></head>
<body><main><p class="muted">PHISHGUARD AI · Generated {generated}</p><h1>{escape(title)}</h1><p class="notice">This report is an educational triage aid. A model score is not proof that a URL is malicious or safe. PHISHGUARD AI does not visit the target URL.</p>{section_html}{table_html}</main></body></html>"""
    return html.encode("utf-8")
