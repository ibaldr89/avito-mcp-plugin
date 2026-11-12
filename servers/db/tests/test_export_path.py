"""Экспорт пишет только в каталог выгрузок (``AVITO_EXPORT_DIR``).

Путь приходит от модели, а в её контексте — тексты объявлений (чужой ввод):
без границы тулза перезаписала бы любой файл, доступный процессу.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from avito_mcp_db.tools.exporting import export_dir, resolve_export_path


def test_relative_path_lands_inside_export_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AVITO_EXPORT_DIR", str(tmp_path))
    target = Path(resolve_export_path("flats/today.csv"))
    assert target == tmp_path.resolve() / "flats" / "today.csv"
    # Подкаталог создаётся: запись файла не должна падать на его отсутствии.
    assert target.parent.is_dir()


def test_absolute_path_inside_export_dir_is_allowed(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AVITO_EXPORT_DIR", str(tmp_path))
    inside = tmp_path / "a.json"
    assert Path(resolve_export_path(str(inside))) == inside.resolve()


@pytest.mark.parametrize("path", ["../outside.csv", "a/../../outside.csv"])
def test_escape_through_parent_is_refused(monkeypatch, tmp_path, path: str) -> None:
    monkeypatch.setenv("AVITO_EXPORT_DIR", str(tmp_path / "exports"))
    with pytest.raises(ValueError, match="AVITO_EXPORT_DIR"):
        resolve_export_path(path)


def test_absolute_path_outside_is_refused(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AVITO_EXPORT_DIR", str(tmp_path / "exports"))
    with pytest.raises(ValueError):
        resolve_export_path(str(tmp_path / "elsewhere.csv"))


def test_default_export_dir_is_under_home(monkeypatch) -> None:
    monkeypatch.delenv("AVITO_EXPORT_DIR", raising=False)
    assert export_dir() == (Path.home() / "avito-exports").resolve()
