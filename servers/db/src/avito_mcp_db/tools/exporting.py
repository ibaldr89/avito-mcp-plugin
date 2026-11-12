"""MCP-тулза экспорта объявлений в xlsx/json/csv (db-сервер).

Экспорт переехал в db из gateway (Фаза 3): он оперирует данными, которые db
же и хранит/пишет.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from avito_mcp_scraper.models import ExportResult, Listing
from avito_mcp_scraper.tools.execution import run_blocking

from ..export.exporter import ExportFormat
from ..export.exporter import export_listings as do_export


def export_dir() -> Path:
    """Каталог, в который разрешено писать выгрузки (``AVITO_EXPORT_DIR``)."""
    raw = os.getenv("AVITO_EXPORT_DIR", "").strip()
    base = Path(raw).expanduser() if raw else Path.home() / "avito-exports"
    return base.resolve()


def resolve_export_path(path: str) -> str:
    """Путь выгрузки внутри ``export_dir()``; относительный — от него же.

    Путь приходит от модели, а в её контексте лежат тексты объявлений — чужой
    ввод. Без границы тулза перезаписала бы любой файл, доступный процессу.

    Raises:
        ValueError: путь выходит за каталог выгрузок.
    """
    base = export_dir()
    target = (base / Path(path).expanduser()).resolve()
    if not target.is_relative_to(base):
        raise ValueError(
            f"путь вне каталога выгрузок {base} — задайте относительный путь "
            "или смените каталог через AVITO_EXPORT_DIR"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    return str(target)


def register(mcp: FastMCP) -> None:
    """Зарегистрировать тулзу экспорта на инстансе FastMCP."""

    @mcp.tool(
        annotations=ToolAnnotations(destructiveHint=True, openWorldHint=False),
    )
    async def export_listings(
        items: list[Listing],
        ctx: Context,
        fmt: ExportFormat = "xlsx",
        path: str | None = None,
    ) -> ExportResult:
        """Экспортировать объявления в xlsx/json/csv.

        Use when нужно сохранить результаты поиска в файл (Excel, JSON, CSV)
        для анализа или передачи. Принимает список объявлений (из
        search_listings), формат и опциональный путь — относительно каталога
        выгрузок (``AVITO_EXPORT_DIR``, дефолт ``~/avito-exports``); путь вне
        него отклоняется. Без пути возвращает
        содержимое как строку (base64 для xlsx).
        """
        await ctx.info(f"export_listings: fmt={fmt}, count={len(items)}")

        def _run() -> ExportResult:
            target = resolve_export_path(path) if path else None
            content, written_path = do_export(items, fmt, target)
            return ExportResult(
                format=fmt,
                path=written_path,
                content=content if not written_path else None,
                count=len(items),
            )

        return await run_blocking(
            _run, failure="не удалось экспортировать", operation="export_listings"
        )
