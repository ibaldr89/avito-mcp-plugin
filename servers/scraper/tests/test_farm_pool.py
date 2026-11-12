"""Пул модемов фермы: у каждого адреса своя ссылка смены IP.

Смена IP у модема идёт 15–17 с, поэтому выжженный адрес переподключается в
фоне, а работа сразу уходит на следующий. Ответ ссылки — JSON со ``status``:
HTTP 200 приходит и на отказ.
"""

from __future__ import annotations

import threading

import pytest

import avito_mcp_scraper.proxies.proxy as proxy_mod
from avito_mcp_scraper.proxies.factory import build_proxy, split_entry
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


def test_entry_with_its_own_change_url() -> None:
    assert split_entry(" u:p@h:1 | https://farm/r?port=1 ") == (
        "u:p@h:1",
        "https://farm/r?port=1",
    )
    assert split_entry("u:p@h:1") == ("u:p@h:1", None)


def test_factory_builds_pool_with_per_proxy_change_urls(monkeypatch) -> None:
    monkeypatch.setenv("AVITO_DIRECT_FIRST", "0")
    pool = build_proxy(
        proxy="u:p@h1:1|https://farm/r?port=1, u:p@h2:2|https://farm/r?port=2",
        change_url="",
    )
    assert isinstance(pool, ProxyPool)
    assert pool.urls == ["u:p@h1:1", "u:p@h2:2"]
    assert pool.change_urls == ["https://farm/r?port=1", "https://farm/r?port=2"]


def test_single_entry_change_url_beats_the_shared_one(monkeypatch) -> None:
    monkeypatch.setenv("AVITO_DIRECT_FIRST", "0")
    proxy = build_proxy(proxy="u:p@h:1|https://own", change_url="https://shared")
    assert isinstance(proxy, MobileProxy)
    assert proxy.change_url == "https://own"


def test_pool_switches_at_once_and_reconnects_burned_modem(monkeypatch) -> None:
    calls: list[str] = []
    _cabinet(monkeypatch, {"status": "ok"}, calls)
    pool = ProxyPool(
        ["u:p@h1:1", "u:p@h2:2"],
        change_urls=["https://farm/r?port=1", "https://farm/r?port=2"],
    )

    assert pool.rotate() is True
    # Работа уходит на следующий модем без ожидания смены IP.
    assert pool.httpx_proxy() == "http://u:p@h2:2"
    assert pool.rotation_was_instant is True

    # Круг замкнулся — пул дожидается переподключений и идёт на второй круг.
    assert pool.rotate() is True
    assert pool.rotation_was_instant is False
    assert pool.httpx_proxy() == "http://u:p@h1:1"
    assert sorted(calls) == [
        "https://farm/r?port=1&format=json",
        "https://farm/r?port=2&format=json",
    ]


def test_pool_is_exhausted_when_every_reconnect_is_refused(monkeypatch) -> None:
    _cabinet(monkeypatch, {"status": "fail"})
    pool = ProxyPool(
        ["h1:1", "h2:2"], change_urls=["https://farm/r?port=1", "https://farm/r?port=2"]
    )
    assert pool.rotate() is True
    assert pool.rotate() is False


def test_pool_does_not_wait_for_reconnect_on_switch(monkeypatch) -> None:
    release = threading.Event()

    def slow_get(url, **kwargs):  # noqa: ANN001, ANN003
        release.wait(5)
        return _Resp({"status": "ok"})

    monkeypatch.setattr(proxy_mod.httpx, "get", slow_get)
    pool = ProxyPool(
        ["h1:1", "h2:2", "h3:3"], change_urls=["https://r1", "https://r2", "https://r3"]
    )
    try:
        # Ссылка ещё «висит», а пул уже отдал следующий адрес.
        assert pool.rotate() is True
        assert pool.httpx_proxy() == "http://h2:2"
    finally:
        release.set()


def test_change_urls_must_match_the_pool() -> None:
    with pytest.raises(ValueError):
        ProxyPool(["h1:1", "h2:2"], change_urls=["https://r1"])


def test_reconnectable_modem_is_not_put_on_cooldown(monkeypatch) -> None:
    _cabinet(monkeypatch, {"status": "ok"})

    class _Store:
        def __init__(self) -> None:
            self.marked: list[str] = []

        def mark_proxy_blocked(self, proxy: str) -> None:
            self.marked.append(proxy)

        def blocked_proxies(self, ttl: float) -> set[str]:
            return set()

    store = _Store()
    pool = ProxyPool(
        ["h1:1", "h2:2"], cooldown_store=store, change_urls=["https://r1", None]
    )
    pool.rotate()  # h1 выжжен, но у него есть ссылка смены IP
    pool.rotate()  # h2 выжжен, ссылки нет — в cooldown
    assert store.marked == ["h2:2"]


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
