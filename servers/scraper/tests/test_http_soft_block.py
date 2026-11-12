"""Блокировка с кодом 200 (капча, пустой каталог) лечится сменой адреса.

Цикл попыток ``HttpClient.get`` судит по коду статуса и такую блокировку не
видит — её ловит классификация страницы в ``_follow``.
"""

from __future__ import annotations

import pytest

import avito_mcp_scraper.http.client as client_mod
from avito_mcp_scraper.http.client import fetch_catalog
from avito_mcp_scraper.parser import PageKind

URL = "https://www.avito.ru/nn/kvartiry"


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text


class _Client:
    """Клиент, отдающий заранее заданные страницы; считает смены адреса."""

    def __init__(self, pages: list[str], can_heal: bool = True) -> None:
        self._pages = list(pages)
        self.can_heal = can_heal
        self.requested: list[str] = []
        self.heals = 0

    def get(self, url: str, max_attempts: int | None = None) -> _Resp:
        self.requested.append(url)
        return _Resp(self._pages.pop(0))

    def heal_soft_block(self) -> bool:
        self.heals += 1
        return self.can_heal


def _classify_by_text(monkeypatch) -> None:
    kinds = {
        "firewall": (PageKind.FIREWALL, None),
        "softblock": (PageKind.SOFTBLOCK, None),
        "ok": (PageKind.OK, {"items": [1]}),
    }
    monkeypatch.setattr(client_mod, "classify", lambda text: kinds[text])


def test_captcha_page_triggers_address_change_and_retry(monkeypatch) -> None:
    _classify_by_text(monkeypatch)
    client = _Client(["firewall", "ok"])

    kind, payload = fetch_catalog(client, URL)

    assert kind == PageKind.OK
    assert payload == {"items": [1]}
    assert client.heals == 1
    assert client.requested == [URL, URL]


def test_soft_block_is_reported_when_address_cannot_change(monkeypatch) -> None:
    _classify_by_text(monkeypatch)
    client = _Client(["softblock"], can_heal=False)

    kind, _ = fetch_catalog(client, URL)

    assert kind == PageKind.SOFTBLOCK
    assert client.requested == [URL]


def test_address_changes_are_bounded(monkeypatch) -> None:
    _classify_by_text(monkeypatch)
    client = _Client(["firewall"] * 10)

    kind, _ = fetch_catalog(client, URL)

    assert kind == PageKind.FIREWALL
    assert client.heals == client_mod._SOFT_BLOCK_HEALS
    assert len(client.requested) == client_mod._SOFT_BLOCK_HEALS + 1


def test_foreign_start_url_is_refused_before_any_request(monkeypatch) -> None:
    _classify_by_text(monkeypatch)
    client = _Client(["ok"])

    with pytest.raises(ValueError):
        fetch_catalog(client, "http://127.0.0.1:8080/admin")

    assert client.requested == []


def test_redirect_off_avito_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(
        client_mod,
        "classify",
        lambda text: (PageKind.REDIRECT, "https://evil.example/collect"),
    )
    client = _Client(["redirect"])

    with pytest.raises(ValueError):
        fetch_catalog(client, URL)

    assert client.requested == [URL]
