"""Список прокси из файла (``AVITO_PROXY_FILE``): по адресу на строку."""

from __future__ import annotations

from avito_mcp_scraper.config import build_http_client
from avito_mcp_scraper.proxies.proxy import ProxyPool, ServerProxy


def _env(monkeypatch) -> None:
    monkeypatch.setenv("AVITO_COOKIE_PROVIDER", "none")
    monkeypatch.setenv("AVITO_DIRECT_FIRST", "0")
    monkeypatch.delenv("AVITO_PROXY_LIST_URL", raising=False)
    monkeypatch.delenv("AVITO_PROXY_CHANGE_URL", raising=False)


def test_file_feeds_the_pool(monkeypatch, tmp_path) -> None:
    _env(monkeypatch)
    listing = tmp_path / "proxies.txt"
    listing.write_text(
        "# ферма, порты 10001-10002\n\nu:p@h1:1\n  u:p@h2:2  \n", encoding="utf-8"
    )
    monkeypatch.setenv("AVITO_PROXY_FILE", str(listing))
    monkeypatch.setenv("AVITO_PROXY", "u:p@from-env:9")

    with build_http_client() as client:
        assert isinstance(client.proxy, ProxyPool)
        # Файл важнее AVITO_PROXY; комментарии и пустые строки пропущены.
        assert client.proxy.urls == ["u:p@h1:1", "u:p@h2:2"]


def test_notepad_bom_does_not_stick_to_first_proxy(monkeypatch, tmp_path) -> None:
    _env(monkeypatch)
    listing = tmp_path / "proxies.txt"
    listing.write_text("u:p@h1:1\n", encoding="utf-8-sig")
    monkeypatch.setenv("AVITO_PROXY_FILE", str(listing))
    monkeypatch.delenv("AVITO_PROXY", raising=False)

    with build_http_client() as client:
        assert isinstance(client.proxy, ServerProxy)
        assert client.proxy.httpx_proxy() == "http://u:p@h1:1"


def test_missing_file_falls_back_to_env(monkeypatch, tmp_path) -> None:
    _env(monkeypatch)
    monkeypatch.setenv("AVITO_PROXY_FILE", str(tmp_path / "nope.txt"))
    monkeypatch.setenv("AVITO_PROXY", "u:p@fallback:9")

    with build_http_client() as client:
        assert client.proxy.httpx_proxy() == "http://u:p@fallback:9"


def test_empty_file_falls_back_to_env(monkeypatch, tmp_path) -> None:
    _env(monkeypatch)
    listing = tmp_path / "proxies.txt"
    listing.write_text("# пока пусто\n", encoding="utf-8")
    monkeypatch.setenv("AVITO_PROXY_FILE", str(listing))
    monkeypatch.setenv("AVITO_PROXY", "u:p@fallback:9")

    with build_http_client() as client:
        assert client.proxy.httpx_proxy() == "http://u:p@fallback:9"
