"""Типы прокси и ротация выходного IP."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

import httpx

from ..utils import mask_proxy

log = logging.getLogger(__name__)


@runtime_checkable
class ProxyCooldownStore(Protocol):
    """Память о выжженных прокси между запусками (DIP).

    Протокол, а не конкретное хранилище: scraper stateless и не тянет на себя
    реализацию БД. Бэкенд (БД или тестовый двойник) реализует его структурно
    и передаёт в ``build_http_client(cooldown_store=…)``.
    """

    def mark_proxy_blocked(self, proxy: str) -> None:
        """Запомнить адрес, отдавший блокировку."""
        ...

    def blocked_proxies(self, ttl: float) -> set[str]:
        """Адреса, заблокированные не позже ``ttl`` секунд назад."""
        ...


#: Значения поля ``status`` в JSON-ответе кабинета, означающие отказ. Кабинеты
#: мобильных прокси отвечают HTTP 200 и на отказ (``{"status": "fail", …}``) —
#: по одному коду статуса его не видно.
_FAILURE_STATUSES = frozenset({"fail", "failed", "err", "error"})


def with_scheme(url: str) -> str:
    """Достроить ``host:port`` до URL прокси; явную схему (socks5://…) не трогаем."""
    return url if "://" in url else f"http://{url}"


def reports_failure(resp: object) -> bool:
    """Тело ответа кабинета явно сообщает об отказе (``status: fail``)?

    Не-JSON и JSON без поля ``status`` отказом не считаются: формат у
    провайдеров разный, и требовать ``status: ok`` значило бы сломать тех,
    кто отдаёт просто новый IP.
    """
    try:
        payload = resp.json()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — тело не JSON, судить не по чему
        return False
    if not isinstance(payload, dict):
        return False
    return str(payload.get("status", "")).strip().lower() in _FAILURE_STATUSES


def change_ip(change_url: str, timeout: float) -> bool:
    """Дёрнуть ссылку смены IP. ``True`` — кабинет подтвердил смену."""
    try:
        # Параметр клеим через URL, а не строкой: change_url может уже
        # иметь или не иметь query. trust_env=False — служебный запрос к
        # кабинету не должен уходить через HTTPS_PROXY из шелла (то есть
        # через сам ротируемый прокси). Построение URL — внутри try:
        # httpx.InvalidURL (опечатка/битый порт в change_url) не наследует
        # HTTPError (проверено в httpx 0.28.1) и иначе пробросился бы сырым
        # исключением вместо контрактного False.
        url = httpx.URL(change_url).copy_merge_params({"format": "json"})
        resp = httpx.get(
            url,
            timeout=timeout,
            trust_env=False,
            follow_redirects=True,
        )
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        log.warning("ротация IP не удалась: %s", exc)
        return False
    if resp.status_code != 200:
        log.warning("ротация IP вернула статус %s", resp.status_code)
        return False
    if reports_failure(resp):
        log.warning("кабинет отказал в смене IP (status=fail в теле ответа)")
        return False
    return True


class Proxy(ABC):
    """Прокси для запросов к Avito. `rotate()` меняет выходной IP, если умеет."""

    #: Была ли последняя ротация мгновенной (смена звена цепочки, а не запрос в
    #: кабинет провайдера). Мгновенная смена уже даёт другой выходной адрес,
    #: поэтому пауза «чтобы прежний IP остыл» после неё не нужна — см.
    #: ``HttpClient._rotate_and_backoff``.
    rotation_was_instant: bool = False

    @abstractmethod
    def httpx_proxy(self) -> str | None:
        """Строка прокси для HTTP-клиента (`http://user:pass@host:port`) или None."""

    @abstractmethod
    def rotate(self) -> bool:
        """Сменить выходной IP. True — успех; False — не поддерживается/не удалось."""

    def escalate(self) -> bool:
        """Более тяжёлая мера, чем `rotate()`, если поддерживается.

        `rotate()` меняет IP в пределах той же физической точки/подсети — не
        спасает, если под подозрением Qrator вся подсеть (см. `MpsApiProxy`,
        который переключает регион/оператора через API mobileproxy.space).
        По умолчанию не поддерживается.
        """
        return False


class NoProxy(Proxy):
    def httpx_proxy(self) -> str | None:
        return None

    def rotate(self) -> bool:
        return False


class ServerProxy(Proxy):
    """Статический серверный прокси — без ротации IP."""

    def __init__(self, url: str) -> None:
        self.url = url

    def httpx_proxy(self) -> str | None:
        return with_scheme(self.url)

    def rotate(self) -> bool:
        return False


class MobileProxy(Proxy):
    """Мобильный прокси с ротацией IP через change-IP URL."""

    def __init__(self, url: str, change_url: str, timeout: float = 20.0) -> None:
        self.url = url
        self.change_url = change_url
        self.timeout = timeout

    def httpx_proxy(self) -> str | None:
        return with_scheme(self.url)

    def rotate(self) -> bool:
        return change_ip(self.change_url, self.timeout)


class ProxyPool(Proxy):
    """Несколько прокси-адресов с перебором при блокировках.

    Пул выходных IP смешанный: часть адресов прожжена Qrator, часть чиста. При
    блокировке ``rotate()`` переключается на следующий адрес; когда круг замкнулся,
    возвращает ``False`` — перебирать больше нечего, нужен свежий пул.

    Смена IP у самих адресов — дело провайдера (ферма модемов меняет его по
    расписанию): пул только перебирает адреса и ничего не переподключает.
    """

    def __init__(
        self,
        urls: list[str],
        cooldown_store: ProxyCooldownStore | None = None,
        cooldown: float = 1800.0,
    ) -> None:
        if not urls:
            raise ValueError("пул прокси пуст")
        self.urls = urls
        self.cooldown_store = cooldown_store
        self.cooldown = cooldown
        self._index = 0
        self._rotations = 0
        self._skip_cooled_down()

    def _blocked(self) -> set[str]:
        if self.cooldown_store is None:
            return set()
        try:
            blocked = self.cooldown_store.blocked_proxies(self.cooldown)
        except Exception as exc:  # noqa: BLE001 — память об IP не критична
            log.warning("не удалось прочитать cooldown прокси: %s", exc)
            return set()
        return set(blocked)

    def _skip_cooled_down(self) -> None:
        """Встать на адрес вне cooldown; если остывают все — работаем как есть."""
        blocked = self._blocked()
        if not blocked:
            return
        for offset in range(len(self.urls)):
            candidate = (self._index + offset) % len(self.urls)
            # Сверяем по тому же ключу, каким писали, — маскированному адресу.
            if mask_proxy(self.urls[candidate]) not in blocked:
                self._index = candidate
                return

    def httpx_proxy(self) -> str | None:
        return with_scheme(self.urls[self._index])

    def _remember_block(self, index: int) -> None:
        """Запомнить выжженный адрес между запусками (если есть чем)."""
        if self.cooldown_store is None:
            return
        try:
            # В базу — БЕЗ учётных данных: пароль прокси не должен уезжать
            # в облачный Postgres. Ключ cooldown — host:port.
            self.cooldown_store.mark_proxy_blocked(mask_proxy(self.urls[index]))
        except Exception as exc:  # noqa: BLE001
            log.warning("не удалось запомнить блокировку прокси: %s", exc)

    def rotate(self) -> bool:
        # rotate() вызывается именно после блокировки — помечаем текущий адрес,
        # чтобы следующий запуск не тратил на него попытки.
        self._remember_block(self._index)
        self._index = (self._index + 1) % len(self.urls)
        self._rotations += 1
        self._skip_cooled_down()
        # Другой адрес пула — сразу другой выходной IP: пауза не нужна. Круг
        # замкнулся — прокси кончились, вызывающему нужен сигнал.
        self.rotation_was_instant = self._rotations % len(self.urls) != 0
        return self.rotation_was_instant


class ChainProxy(Proxy):
    """Упорядоченная цепочка транспортов: сначала быстрые, потом дорогие.

    Замер 2026-07-20 на живом Avito: прямое соединение с куками spfa отдаёт
    каталог за 0.63 с, а купленная мобильная подсеть — 403 на любом выходном
    адресе и с любым отпечатком. Qrator банит подсеть целиком, поэтому ротация
    IP внутри неё меняет адрес, но не репутацию. Клиент, знающий только про
    прокси, честно выбирал весь бюджет времени на заведомо мёртвых попытках.

    Отсюда порядок: ``[NoProxy(), <прокси>]`` — пробуем напрямую, а прокси
    держим как фоллбэк на случай, когда забанен уже наш собственный IP.

    Смена звена мгновенна и бесплатна (это сразу другой выходной адрес), тогда
    как ротация IP внутри звена — сетевой запрос в кабинет провайдера на
    3.6–4.3 с. Поэтому сначала перебираются звенья и только после — ротируется
    последнее из них; ``rotation_was_instant`` сообщает вызывающему, нужен ли
    backoff.
    """

    def __init__(self, links: list[Proxy]) -> None:
        if not links:
            raise ValueError("цепочка транспортов пуста")
        self.links = links
        self._index = 0

    def _current(self) -> Proxy:
        return self.links[self._index]

    def httpx_proxy(self) -> str | None:
        return self._current().httpx_proxy()

    def rotate(self) -> bool:
        if self._index + 1 < len(self.links):
            self._index += 1
            self.rotation_was_instant = True
            log.info(
                "переключаюсь на следующий транспорт: %s",
                mask_proxy(self.httpx_proxy() or "") or "прямое соединение",
            )
            return True
        # Звенья кончились — остаётся дорогая смена IP внутри последнего.
        last = self.links[-1]
        rotated = last.rotate()
        # Последнее звено само знает, была ли смена мгновенной (пул адресов
        # переключается без похода в кабинет).
        self.rotation_was_instant = rotated and last.rotation_was_instant
        return rotated

    def escalate(self) -> bool:
        """Эскалация касается только последнего звена — у прямого её нет."""
        return self.links[-1].escalate()
