"""Отказ называет настоящую причину; прямое соединение не включается молча.

Недоступный прокси и бан IP лечатся по-разному: первый — проверкой адреса и
логина, второй — другим адресом. И если прямое соединение запрещено
(``AVITO_DIRECT_FIRST=0``), отсутствие прокси — ошибка настройки, а не повод
пойти со своего IP.
"""

from __future__ import annotations

import pytest
from curl_cffi.curl import CurlError

import avito_mcp_scraper.http.client as hc
from avito_mcp_scraper.config import build_http_client
from avito_mcp_scraper.http.client import HttpClient
from avito_mcp_scraper.proxies.factory import build_proxy
from avito_mcp_scraper.proxies.proxy import NoProxy

URL = "https://www.avito.ru/x"


class _Resp:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _Session:
    """Отдаёт по очереди ответы; исключение в очереди — бросает."""

    def __init__(self, seq: list) -> None:
        self._seq = seq

    def get(self, url, cookies=None, timeout=None, allow_redirects=True):  # noqa: ANN001, ANN201
        item = self._seq.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        pass


class _StaticProxy:
    def httpx_proxy(self) -> str:
        return "http://u:secret@h:1"

    def rotate(self) -> bool:
        return False


def _client(monkeypatch, seq: list, proxy: object, attempts: int = 2) -> HttpClient:
    monkeypatch.setattr(hc, "_build_session", lambda url, imp: _Session(seq))
    return HttpClient(
        proxy=proxy,  # type: ignore[arg-type]
        cookies=None,
        max_attempts=attempts,
        wait_after_rotate=0,
    )


def test_dead_proxy_is_not_called_an_ip_block(monkeypatch) -> None:
    refused = CurlError("Failed to connect to h port 1: Connection refused")
    client = _client(monkeypatch, [refused, refused], _StaticProxy())

    with pytest.raises(RuntimeError) as exc:
        client.get(URL)

    message = str(exc.value)
    assert "сбой соединения" in message
    assert "Connection refused" in message
    assert "блокировки IP" not in message
    # У пула ссылок смены IP нет — советовать её нельзя.
    assert "CHANGE_URL" not in message
    assert "AVITO_PROXY_FILE" in message


def test_block_is_still_called_a_block(monkeypatch) -> None:
    client = _client(monkeypatch, [_Resp(403), _Resp(403)], _StaticProxy())

    with pytest.raises(RuntimeError) as exc:
        client.get(URL)

    message = str(exc.value)
    assert "блокировки IP" in message
    assert "CHANGE_URL" not in message


def test_block_after_a_transport_error_is_reported_as_block(monkeypatch) -> None:
    # Соединение ожило и пришёл 403 — причина отказа уже не сеть.
    hiccup = CurlError("Operation timed out")
    client = _client(monkeypatch, [hiccup, _Resp(403)], _StaticProxy())

    with pytest.raises(RuntimeError) as exc:
        client.get(URL)

    assert "блокировки IP" in str(exc.value)


def test_no_proxy_with_direct_forbidden_is_a_config_error(monkeypatch) -> None:
    monkeypatch.setenv("AVITO_DIRECT_FIRST", "0")
    with pytest.raises(ValueError, match="AVITO_DIRECT_FIRST"):
        build_proxy(proxy="", change_url="")


def test_no_proxy_by_default_still_goes_direct(monkeypatch) -> None:
    monkeypatch.delenv("AVITO_DIRECT_FIRST", raising=False)
    assert isinstance(build_proxy(proxy="", change_url=""), NoProxy)


def test_client_is_not_built_without_proxy_when_direct_forbidden(monkeypatch) -> None:
    # Путь тулз (в т.ч. check_proxy_health): сборка клиента обязана упасть,
    # а не вернуть клиента с прямым соединением.
    monkeypatch.setenv("AVITO_DIRECT_FIRST", "0")
    monkeypatch.setenv("AVITO_COOKIE_PROVIDER", "none")
    for name in ("AVITO_PROXY", "AVITO_PROXY_FILE", "AVITO_PROXY_LIST_URL"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="прокси не задан"):
        build_http_client()
