"""Пул прокси фермы и разбор ответа ссылки смены IP.

Пул только перебирает адреса: IP у модемов ферма меняет сама по расписанию.
Ответ ссылки смены IP (одиночный ``MobileProxy``) — JSON со ``status``: HTTP
200 приходит и на отказ.
"""

from __future__ import annotations

import pytest

import avito_mcp_scraper.proxies.proxy as proxy_mod
from avito_mcp_scraper.proxies.proxy import (
    ChainProxy,
    MobileProxy,
    NoProxy,
    ProxyPool,
    ServerProxy,
)
from avito_mcp_scraper.tools.diagnostics import find_pool
from avito_mcp_scraper.utils import require_avito_url


class _Resp:
    def __init__(self, payload: object, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> object:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _cabinet(monkeypatch, payload: object, calls: list[str] | None = None) -> None:
    def fake_get(url, **kwargs):  # noqa: ANN001, ANN003
        if calls is not None:
            calls.append(str(url))
        return _Resp(payload)

    monkeypatch.setattr(proxy_mod.httpx, "get", fake_get)


def test_reconnect_refusal_in_body_is_not_a_rotation(monkeypatch) -> None:
    # Ферма отвечает 200 и на отказ: {"status": "fail", "error": "..."}.
    _cabinet(monkeypatch, {"status": "fail", "error": "modem busy"})
    assert MobileProxy("u:p@h:1", "https://farm/reconnect?port=1").rotate() is False


def test_reconnect_ok_in_body_is_a_rotation(monkeypatch) -> None:
    _cabinet(monkeypatch, {"status": "ok"})
    assert MobileProxy("u:p@h:1", "https://farm/reconnect?port=1").rotate() is True


def test_non_json_reconnect_answer_still_counts(monkeypatch) -> None:
    # Провайдеры, отдающие просто текст с новым IP, ломаться не должны.
    _cabinet(monkeypatch, ValueError("not json"))
    assert MobileProxy("u:p@h:1", "https://chg?k=1").rotate() is True


def test_pool_switch_is_instant_until_the_circle_closes() -> None:
    pool = ProxyPool(["h1:1", "h2:2"])
    assert pool.rotate() is True
    assert pool.rotation_was_instant is True
    assert pool.httpx_proxy() == "http://h2:2"
    # Круг замкнулся: адреса кончились, переподключать пул ничего не умеет.
    assert pool.rotate() is False
    assert pool.rotation_was_instant is False


def test_explicit_scheme_is_kept() -> None:
    assert ServerProxy("socks5://u:p@h:1080").httpx_proxy() == "socks5://u:p@h:1080"
    assert ServerProxy("u:p@h:1").httpx_proxy() == "http://u:p@h:1"


def test_diagnostics_sees_pool_behind_direct_link() -> None:
    # Дефолтная сборка: ChainProxy([NoProxy(), <пул>]) — пул не должен теряться.
    pool = ProxyPool(["h1:1", "h2:2"])
    assert find_pool(ChainProxy([NoProxy(), pool])) is pool
    assert find_pool(pool) is pool
    assert find_pool(NoProxy()) is None


def test_chain_reports_instant_switch_inside_pool() -> None:
    chain = ChainProxy([NoProxy(), ProxyPool(["h1:1", "h2:2", "h3:3"])])
    chain.rotate()  # прямое соединение → пул
    assert chain.rotate() is True  # h1 → h2 внутри пула
    assert chain.rotation_was_instant is True


@pytest.mark.parametrize(
    "url",
    [
        "https://www.avito.ru/moskva/kvartiry",
        "https://avito.ru/items/1",
        "http://m.avito.ru/x",
    ],
)
def test_avito_urls_pass(url: str) -> None:
    assert require_avito_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/admin",
        "https://evil.example/www.avito.ru",
        "https://avito.ru.evil.example/x",
        "https://notavito.ru/x",
        "file:///etc/passwd",
        "ftp://www.avito.ru/x",
        "www.avito.ru/x",
    ],
)
def test_foreign_urls_are_refused(url: str) -> None:
    with pytest.raises(ValueError):
        require_avito_url(url)
