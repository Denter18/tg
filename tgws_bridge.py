"""Модуль моста Telegram через внешний WebSocket-релей (Cloudflare Worker).

Смысл: прямые адреса Telegram (149.154.x.x и др.) у провайдера могут быть
заблокированы по IP — тогда шлюз kwsN.web.telegram.org тоже не открывается,
потому что обслуживается теми же адресами. Мост — сторонний сервер с
"чистым" IP: приложение открывает wss:// к нему, а он пересылает кадры
в kwsN.web.telegram.org (см. worker/worker.js).

Этот модуль — переезжаемое ядро: в основном приложении (Denter18/Dpi) он
включается как дополнительный транспорт в tgws-логике (фолбэк
«мост -> нативные шлюзы»), здесь — единственный транспорт.

Чистая логика (AES/детект DC/PacketSplitter/WebSocket-клиент) берётся из
tgws.py без изменений; здесь только выбор адреса моста и рукопожатие.
"""

import tgws

# Заглушка по умолчанию: приложение отказывается стартовать, пока адрес
# не заменён на реальный (см. README worker/).
BRIDGE_DEFAULT = "wss://CHANGE-ME.workers.dev"


def normalize_base(url: str) -> str:
    """Приводит адрес моста к виду host[/prefix] без схемы.

    Примеры:
        "wss://abc.workers.dev"      -> ("abc.workers.dev", "")
        "wss://abc.workers.dev/x"    -> ("abc.workers.dev", "/x")
        "abc.workers.dev"            -> ("abc.workers.dev", "")
    """
    url = (url or "").strip()
    for scheme in ("wss://", "ws://", "https://", "http://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break

    url = url.strip("/")
    host, _, prefix = url.partition("/")
    return host, ("/" + prefix if prefix else "")


def bridge_path(dc: int, media: bool) -> str:
    """Путь маршрута на Worker'е для дата-центра (см. worker.js)."""
    return "/dc/{}{}".format(dc, "m" if media else "")


async def open_bridge_ws(connect_tcp, base_url, dc, media, timeout=8.0):
    """Открывает WebSocket к мосту: wss://<host><prefix>/dc/<N>[m].

    connect_tcp(ip, port, timeout, use_ssl, server_hostname) — функция
    движка, возвращает (reader, writer); use_ssl — TLS-контекст.
    Возвращает готовый tgws.WebSocket или бросает исключение.
    """
    host, prefix = normalize_base(base_url)

    try:
        conn = await connect_tcp(
            host, 443,
            timeout=timeout,
            use_ssl="tls",  # движок сам создаёт контекст (без проверки имени:
            # содержимое защищает MTProto, как у нативных шлюзов)
            server_hostname=host,
        )
    except TimeoutError as e:
        raise TimeoutError(f"TCP к {host}:443") from e
    except Exception as e:
        raise type(e)(f"TCP/TLS к {host}: {str(e)[:48]}") from e

    ws = tgws.WebSocket(*conn)

    try:
        await ws.handshake(host, prefix + bridge_path(dc, media))
    except Exception as e:
        try:
            ws.writer.close()
        except Exception:
            pass

        raise OSError(f"WS-рукопожатие: {str(e)[:48] or type(e).__name__}") from e

    return ws
