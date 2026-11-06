"""NoDPI TG Bridge (Android) — отдельное приложение: Telegram через внешний
WebSocket-релей (Cloudflare Worker), когда провайдер блокирует IP Telegram.

Архитектура
-----------
* VPN-сервис (java_src/) маршрутизирует в туннель ТОЛЬКО подсети Telegram;
  весь остальной трафик устройства не трогаем.
* tunnel.py (как в основном приложении) заворачивает TCP в локальный сервер
  движка; движок видит адрес назначения из таблицы потоков.
* Каждое соединение к серверу Telegram — это MTProto (obfuscated2):
  движок определяет дата-центр из первых 64 байт, упаковывает поток в
  бинарные WebSocket-кадры и шлёт на wss://<мост>/dc/<N>[m]. Мост (Worker)
  пересылает кадры в kwsN.web.telegram.org — тот же байт-поток принимает
  и веб-клиент Telegram.
* DNS (UDP/53 на 10.111.222.2) пересылается на публичные резолверы через
  защищённые сокеты; AAAA/прочие типы отвечаются пустым ответом (NODATA).

Часть этого файла (TgBridgeEngine._telegram_bridge и ниже) — кандидат на
перенос в основное приложение как фолбэк-транспорт для tgws.
"""

import asyncio
import random
import socket
import ssl
import struct
import threading
import time

import tgws
import tgws_bridge

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.switch import Switch
from kivy.uix.textinput import TextInput
from kivy.utils import platform


Window.clearcolor = (0.12, 0.12, 0.14, 1)

# Сколько ждать первый ответ шлюза после отправки init-пакета (сек).
REPLY_TIMEOUT = 6.0
# Пул заранее открытых WebSocket на DC (экономит 3-4 обмена на соединение).
POOL_TTL = 20.0

# Публичные DNS, куда пересылаем запросы приложений из туннеля.
UDP_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "77.88.8.8", "9.9.9.9"]
UDP_TIMEOUT = 2.5


class TgBridgeEngine:
    """Движок standalone-приложения: все TCP-потоки из туннеля — Telegram."""

    def __init__(
        self,
        bridge_url,
        log_cb=None,
        stopped_cb=None,
        protect_cb=None,
        tun_fd_cb=None,
    ):
        self.bridge_url = bridge_url
        self.log_cb = log_cb or (lambda msg: None)
        self.stopped_cb = stopped_cb
        self.protect_cb = protect_cb
        self.tun_fd_cb = tun_fd_cb
        self._tun_task = None
        self.relay = None
        self.loop = None
        self._main_task = None
        self.running = False

    # ---------------------------------------------------------------
    # Инфраструктура (как в NoDPIEngine основного приложения)
    # ---------------------------------------------------------------

    def log(self, msg):
        self.log_cb(msg)

    def _note_once(self, key, message):
        seen = self.__dict__.setdefault("_noted", set())

        if key not in seen and len(seen) < 500:
            seen.add(key)
            self.log(message)

    def new_socket(self, kind: str, ip: str = "0.0.0.0"):
        """Неблокирующий сокет; в VPN-режиме выведен из туннеля через protect()."""
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(
            family,
            socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM,
        )
        sock.setblocking(False)

        if self.protect_cb:
            try:
                self.protect_cb(sock.fileno())
            except Exception:
                pass

        return sock

    def _ws_ssl_context(self):
        """TLS к мосту без проверки имени: содержимое защищает MTProto.

        Аналог _ws_ssl_context основного приложения: сертификаты *.workers.dev
        валидны, но имя меняется при переносе моста на свой VPS, а доверие
        обеспечивает собственное шифрование Telegram, а не этот TLS.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def connect_tcp(self, ip, port, timeout=8.0, use_ssl=None, server_hostname=None):
        sock = self.new_socket("tcp", ip)

        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(sock, (ip, port)), timeout
            )
        except BaseException:
            sock.close()
            raise

        if use_ssl is not None:
            return await asyncio.open_connection(
                sock=sock,
                ssl=self._ws_ssl_context(),
                server_hostname=server_hostname,
                ssl_shutdown_timeout=1.0,
            )

        return await asyncio.open_connection(sock=sock)

    async def pipe(self, reader, writer):
        try:
            while self.running:
                data = await reader.read(16384)

                if not data:
                    break

                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---------------------------------------------------------------
    # DNS для tunnel.py (пересылка UDP-запросов на публичные резолверы)
    # ---------------------------------------------------------------

    @staticmethod
    def _dns_build(name: str, tid: int):
        q = bytearray(struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0))

        for part in name.strip(".").split("."):
            b = part.encode("idna")[:63]
            q.append(len(b))
            q += b

        q += b"\x00" + struct.pack("!HH", 1, 1)  # A, IN
        return bytes(q)

    @staticmethod
    def _dns_parse(data: bytes, tid: int):
        if len(data) < 12:
            return []

        rid, _flags, qd, an = struct.unpack("!HHHH", data[:8])

        if rid != tid:
            return []

        pos = 12

        def skip_name(pos):
            while True:
                if pos >= len(data):
                    raise ValueError
                n = data[pos]
                if n == 0:
                    return pos + 1
                if n & 0xC0:
                    return pos + 2
                pos += 1 + n

        try:
            for _ in range(qd):
                pos = skip_name(pos) + 4

            ips = []

            for _ in range(an):
                pos = skip_name(pos)
                rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
                pos += 10

                if rtype == 1 and rclass == 1 and rdlen == 4:
                    ips.append(socket.inet_ntoa(data[pos : pos + 4]))

                pos += rdlen

            return ips
        except (ValueError, struct.error):
            return []

    async def _udp_query(self, server: str, packet: bytes):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        sock = self.new_socket("udp", server)
        transport, _ = await loop.create_datagram_endpoint(Proto, sock=sock)

        try:
            transport.sendto(packet)

            return await asyncio.wait_for(fut, UDP_TIMEOUT)
        finally:
            transport.close()

    async def resolve_ips(self, host: str):
        """A-записи через публичные резолверы или None."""
        tid = random.randrange(65536)
        packet = self._dns_build(host.lower(), tid)

        async def one(server):
            try:
                return self._dns_parse(await self._udp_query(server, packet), tid)
            except Exception:
                return []

        results = await asyncio.gather(*(one(s) for s in UDP_DNS_SERVERS))

        for ips in results:
            if ips:
                return ips

        return None

    # ---------------------------------------------------------------
    # Точка входа из tunnel.py
    # ---------------------------------------------------------------

    async def serve_tunnel(self, client_reader, client_writer, host, port):
        """Соединение из VPN-режима: адрес назначения известен заранее."""
        if port in tgws.TG_PORTS and tgws.is_telegram_ip(host):
            await self._telegram_bridge(client_reader, client_writer, host, port)
            return

        # Сюда попадать не должны (маршруты только TG), но на всякий случай
        # проксируем как есть, не ломая приложение.
        remote_reader = remote_writer = None

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
            await asyncio.gather(
                self.pipe(client_reader, remote_writer),
                self.pipe(remote_reader, client_writer),
            )
        except Exception as e:
            self.log(f"[Ошибка] {host}:{port} - {type(e).__name__}")
        finally:
            for w in (client_writer, remote_writer):
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass

    # ---------------------------------------------------------------
    # Telegram: obfuscated2 -> WebSocket-кадры -> мост (см. tgws_bridge.py)
    # ---------------------------------------------------------------

    async def _tg_open_bridge(self, dc, media, first, tag):
        """Открывает WebSocket к мосту и отправляет init-пакет.

        Возвращает (ws, первый ответ, splitter) или (None, None, None).
        Per-DC состояние: сбой одного DC не отключает остальные.
        """
        now = time.time()
        state = self.__dict__.setdefault("_tg_dc_state", {}).setdefault(
            dc, {"fails": 0, "ok": 0.0, "pause": 0.0}
        )

        if now < state["pause"]:
            return None, None, None

        # Готовое соединение из пула: рукопожатие уже сделано.
        pool = self.__dict__.setdefault("_tg_pool", {}).setdefault(dc, [])

        while pool:
            cand, ts = pool.pop()

            if time.time() - ts < POOL_TTL and not cand.reader.at_eof():
                try:
                    splitter = tgws.PacketSplitter(first[:64], tag) if tag else None
                    chunks = (
                        splitter.feed(first[64:])
                        if splitter
                        else ([first[64:]] if len(first) > 64 else [])
                    )
                    cand.send(first[:64] + (chunks[0] if chunks else b""))

                    for chunk in chunks[1:]:
                        cand.send(chunk)

                    await cand.writer.drain()
                    reply = await asyncio.wait_for(cand.recv(), REPLY_TIMEOUT)
                except Exception:
                    reply = None

                if reply:
                    state["fails"] = 0
                    state["ok"] = time.time()
                    self._tg_stat("ws")
                    self._tg_stat("pool")
                    asyncio.ensure_future(self._fill_pool(dc))
                    return cand, reply, splitter

                cand.close()
            else:
                cand.close()

        errors = []

        for _attempt in range(2):
            t_open = time.time()

            try:
                cand = await tgws_bridge.open_bridge_ws(
                    self.connect_tcp, self.bridge_url, dc, media
                )
            except Exception as e:
                errors.append(type(e).__name__ + " " + str(e)[:40])
                await asyncio.sleep(0.3)
                continue

            try:
                splitter = tgws.PacketSplitter(first[:64], tag) if tag else None

                if splitter:
                    chunks = splitter.feed(first[64:])
                else:
                    chunks = [first[64:]] if len(first) > 64 else []

                cand.send(first[:64] + (chunks[0] if chunks else b""))

                for chunk in chunks[1:]:
                    cand.send(chunk)

                await cand.writer.drain()
                reply = await asyncio.wait_for(cand.recv(), REPLY_TIMEOUT)
            except Exception as e:
                errors.append(str(e)[:40] or type(e).__name__)
                cand.close()
                continue

            if reply:
                state["fails"] = 0
                state["ok"] = time.time()
                self._tg_stat("ws")
                self._tg_stat("open_ms", int((time.time() - t_open) * 1000))
                asyncio.ensure_future(self._fill_pool(dc))
                self._note_once(
                    ("tg-bridge", dc),
                    f"[Telegram] DC{dc}{'m' if media else ''} через мост "
                    f"{tgws_bridge.normalize_base(self.bridge_url)[0]}",
                )
                return cand, reply, splitter

            errors.append("нет ответа")
            cand.close()
            await asyncio.sleep(0.3)

        state["fails"] += 1
        self._tg_stat("fail")

        # Пауза только если DC давно не работал: иначе это случайный сбой сети.
        if state["fails"] >= 4 and time.time() - state["ok"] > 60:
            state["pause"] = time.time() + 10
            state["fails"] = 0

        self.log(
            f"[Telegram] мост DC{dc} не отвечает ({'; '.join(errors[:2])}), "
            "сбой соединения"
        )
        return None, None, None

    async def _fill_pool(self, dc):
        """Заранее открывает WebSocket к мосту для следующего соединения."""
        filling = self.__dict__.setdefault("_tg_filling", set())

        if dc in filling or not self.running:
            return

        filling.add(dc)

        try:
            pool = self.__dict__.setdefault("_tg_pool", {}).setdefault(dc, [])

            while len(pool) < 1:
                try:
                    cand = await tgws_bridge.open_bridge_ws(
                        self.connect_tcp, self.bridge_url, dc, False
                    )
                except Exception:
                    return

                pool.append((cand, time.time()))
        except Exception:
            pass
        finally:
            filling.discard(dc)

    def _tg_stat(self, key, n=1):
        """Счётчики Telegram; раз в 30 с выводим сводку в лог."""
        st = self.__dict__.setdefault("_tg_stats", {})
        st[key] = st.get(key, 0) + n
        now = time.time()
        last = self.__dict__.get("_tg_stats_t")

        if last is None:
            self._tg_stats_t = now
        elif now - last >= 30 and (st.get("ws") or st.get("fail")):
            self._tg_stats_t = now
            self.log(
                f"[Telegram] за 30с: мост {st.get('ws', 0)} (пул {st.get('pool', 0)}), "
                f"сбоев {st.get('fail', 0)}, "
                f"{st.get('open_ms', 0) // max(st.get('ws', 1), 1)}мс на открытие, "
                f"вниз {st.get('down', 0) // 1024}К вверх {st.get('up', 0) // 1024}К"
            )
            st.clear()

    async def _telegram_bridge(self, client_reader, client_writer, host, port):
        """MTProto-поток заворачиваем в WebSocket на мост.

        Fail-fast, без прямого fallback: если провайдер режет IP Telegram,
        прямое подключение всё равно бесполезно, а быстрый сбой даёт
        клиенту Telegram шанс тут же перейти на другое соединение.
        """
        try:
            first = await asyncio.wait_for(client_reader.readexactly(64), 5.0)
        except asyncio.IncompleteReadError as e:
            first = e.partial
        except asyncio.TimeoutError:
            first = b""

        if len(first) == 64:
            try:
                first += await asyncio.wait_for(client_reader.read(65536), 0.05)
            except asyncio.TimeoutError:
                pass

        if not first:
            try:
                client_writer.close()
            except Exception:
                pass

            return

        info = tgws.parse_obfuscated_init(first) if len(first) >= 64 else None

        if info is not None and info[0] is None:
            info = (tgws.dc_for_ip(host), False, info[2])

        if info is None and len(first) >= 64:
            self._note_once(
                ("tg-plain", host, port),
                f"[Telegram] {host}:{port} разбор init: {tgws.describe_init(first)}, "
                f"байт {first[:1].hex()}; мост DC{tgws.dc_for_ip(host)}",
            )
            info = (tgws.dc_for_ip(host), False, None)
        elif info is None:
            self._note_once(
                ("tg-short", host, port),
                f"[Telegram] {host}:{port} - первые байты короче 64 ({len(first)}), сбой",
            )

        if info is None:
            client_writer.close()
            return

        dc, media, tag = info
        ws, reply, splitter = await self._tg_open_bridge(dc, media, first, tag)

        if ws is None:
            client_writer.close()
            return

        try:
            client_writer.write(reply)
            await client_writer.drain()

            async def up():
                while self.running:
                    data = await client_reader.read(16384)

                    if not data:
                        break

                    self._tg_stat("up", len(data))

                    if splitter:
                        for chunk in splitter.feed(data):
                            ws.send(chunk)
                    else:
                        ws.send(data)

                    await ws.writer.drain()

            async def down():
                while self.running:
                    data = await ws.recv()

                    if data is None:
                        break

                    self._tg_stat("down", len(data))
                    client_writer.write(data)
                    await client_writer.drain()

            tasks = [asyncio.ensure_future(up()), asyncio.ensure_future(down())]
            _, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )

            for t in pending:
                t.cancel()
        except Exception:
            pass
        finally:
            ws.close()

            try:
                client_writer.close()
            except Exception:
                pass

    # ---------------------------------------------------------------
    # Запуск/остановка
    # ---------------------------------------------------------------

    async def _run_tun(self):
        from tunnel import TunRelay

        fd, deadline, err_logged = -1, time.time() + 120, False

        while self.running and time.time() < deadline:
            try:
                fd = int(self.tun_fd_cb())
            except Exception as e:
                fd = -1

                if not err_logged:
                    err_logged = True
                    self.log(f"VPN: не получить дескриптор туннеля ({e})")

            if fd >= 0:
                break

            await asyncio.sleep(0.2)

        if fd < 0:
            self.log("VPN: туннель не поднялся")
            return

        relay = TunRelay(self, fd)

        try:
            await relay.start()
            self.relay = relay
            self.log("VPN: трафик Telegram идёт через мост")
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log(f"VPN: ошибка туннеля ({type(e).__name__} {e})")
        finally:
            relay.stop()

    async def _run(self):
        self.log(f"Мост: {self.bridge_url}")

        if self.tun_fd_cb:
            self._tun_task = asyncio.get_running_loop().create_task(self._run_tun())

        await asyncio.Event().wait()

    def start_in_thread(self):
        self.running = True

        def target():
            loop = asyncio.new_event_loop()
            self.loop = loop
            asyncio.set_event_loop(loop)

            try:
                self._main_task = loop.create_task(self._run())

                if not self.running:
                    self._main_task.cancel()

                loop.run_until_complete(self._main_task)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.running:
                    self.log(f"Ошибка: {e}")
            finally:
                try:
                    pending = asyncio.all_tasks(loop)

                    for task in pending:
                        task.cancel()

                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )

                    loop.run_until_complete(asyncio.sleep(0.05))
                except Exception:
                    pass

                loop.close()
                died_on_its_own = self.running
                self.running = False

                if died_on_its_own and self.stopped_cb:
                    try:
                        self.stopped_cb()
                    except Exception:
                        pass

        t = threading.Thread(target=target, daemon=True)
        t.start()

    def stop(self):
        was_running = self.running
        self.running = False

        loop, task = self.loop, self._main_task

        if loop and task and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass

        if was_running:
            self.log("Остановлен.")


# =====================================================================
# Запуск/остановка Java-сервиса NoDpiVpnService (см. java_src/)
# =====================================================================


class AndroidVpn:
    """Обёртка над VpnService: сервис маршрутизирует только подсети Telegram."""

    REQUEST_CODE = 0x4E44
    RESULT_OK = -1
    SERVICE_CLASS = "org.gvcoder.tgbridge.NoDpiVpnService"

    def __init__(self, log_cb):
        self.log = log_cb
        self._cls = None

        if self.available():
            try:
                self._service_cls()
            except Exception as e:
                self.log(f"VPN: не найден класс сервиса ({e})")

    @staticmethod
    def available():
        return platform == "android"

    def _service_cls(self):
        if self._cls is None:
            from jnius import autoclass

            self._cls = autoclass(self.SERVICE_CLASS)

        return self._cls

    # Вызываются из потока движка ---------------------------------------

    def protect(self, fd):
        return bool(self._service_cls().protectSocket(int(fd)))

    def tun_fd(self):
        return int(self._service_cls().getTunFd())

    # -------------------------------------------------------------------

    def start(self):
        if not self.available():
            return

        try:
            from android import activity
            from jnius import autoclass

            self._service_cls()
            activity_cls = autoclass("org.kivy.android.PythonActivity")
            vpn_service = autoclass("android.net.VpnService")
            current = activity_cls.mActivity

            prepare_intent = vpn_service.prepare(current)

            if prepare_intent is None:
                self._launch()
            else:
                activity.bind(on_activity_result=self._on_activity_result)
                current.startActivityForResult(
                    prepare_intent, self.REQUEST_CODE
                )
        except Exception as e:
            self.log(f"VPN: не удалось запустить ({e})")

    def stop(self):
        if not self.available():
            return

        try:
            from jnius import autoclass

            activity_cls = autoclass("org.kivy.android.PythonActivity")
            intent_cls = autoclass("android.content.Intent")
            current = activity_cls.mActivity

            intent = intent_cls()
            intent.setClassName(current.getPackageName(), self.SERVICE_CLASS)
            intent.setAction("STOP")
            current.startService(intent)
        except Exception as e:
            self.log(f"VPN: не удалось остановить ({e})")

    def _on_activity_result(self, request_code, result_code, intent):
        if request_code != self.REQUEST_CODE:
            return

        try:
            from android import activity

            activity.unbind(on_activity_result=self._on_activity_result)
        except Exception:
            pass

        if result_code == self.RESULT_OK:
            self._launch()
        else:
            self.log("VPN: разрешение не выдано")

    def _launch(self):
        try:
            from jnius import autoclass

            activity_cls = autoclass("org.kivy.android.PythonActivity")
            intent_cls = autoclass("android.content.Intent")
            current = activity_cls.mActivity

            intent = intent_cls()
            intent.setClassName(current.getPackageName(), self.SERVICE_CLASS)
            current.startService(intent)
        except Exception as e:
            self.log(f"VPN: не удалось запустить сервис ({e})")


# =====================================================================
# Интерфейс
# =====================================================================


class TgBridgeApp(App):
    def build(self):
        self.engine = None
        self.vpn = AndroidVpn(self.append_log)
        self.vpn_active = False
        root = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))

        title = Label(
            text="NoDPI TG Bridge",
            font_size=dp(22),
            bold=True,
            size_hint_y=None,
            height=dp(36),
            color=(0.3, 0.8, 1, 1),
        )
        root.add_widget(title)

        root.add_widget(
            Label(
                text="Адрес моста (Worker, wss://):",
                size_hint_y=None,
                height=dp(24),
                halign="left",
            )
        )
        self.bridge_input = TextInput(
            text=tgws_bridge.BRIDGE_DEFAULT, multiline=False, size_hint_y=None,
            height=dp(40),
        )
        root.add_widget(self.bridge_input)

        vpn_box = BoxLayout(size_hint_y=None, height=dp(40))
        vpn_box.add_widget(
            Label(text="VPN (только трафик Telegram):", size_hint_x=0.75)
        )
        self.vpn_switch = Switch(
            active=AndroidVpn.available(),
            size_hint_x=0.25,
            disabled=not AndroidVpn.available(),
        )
        vpn_box.add_widget(self.vpn_switch)
        root.add_widget(vpn_box)

        self.btn_toggle = Button(
            text="ЗАПУСТИТЬ",
            size_hint_y=None,
            height=dp(52),
            background_normal="",
            background_color=(0.18, 0.65, 0.32, 1),
            bold=True,
            font_size=dp(16),
        )
        self.btn_toggle.bind(on_press=self.toggle)
        root.add_widget(self.btn_toggle)

        # Панель Telegram (последние строки [Telegram]).
        self.tg_lines = []
        self.tg_label = Label(
            text="Telegram: ждём соединений...",
            size_hint_y=None,
            height=dp(150),
            halign="left",
            valign="top",
            font_size=dp(10),
            color=(0.6, 0.85, 1, 1),
        )
        self.tg_label.bind(
            width=lambda *x: self.tg_label.setter("text_size")(
                self.tg_label, (self.tg_label.width, None)
            )
        )
        root.add_widget(self.tg_label)

        self.log_label = Label(
            text="Укажите адрес моста (см. worker/README.md) и нажмите кнопку.\n",
            size_hint_y=None,
            halign="left",
            valign="top",
            font_size=dp(12),
        )
        self.log_label.bind(
            width=lambda *x: self.log_label.setter("text_size")(
                self.log_label, (self.log_label.width, None)
            ),
            texture_size=lambda *x: self.log_label.setter("height")(
                self.log_label, self.log_label.texture_size[1]
            ),
        )

        scroll = ScrollView(size_hint_y=0.35)
        scroll.add_widget(self.log_label)
        root.add_widget(scroll)

        return root

    def append_log(self, msg):
        def _update(dt):
            if "[Telegram]" in msg or "149.154." in msg or "91.108." in msg:
                key = msg[:110]
                counts = self.__dict__.setdefault("_tg_counts", {})
                counts[key] = counts.get(key, 0) + 1
                order = [k for k in self.tg_lines if k != key] + [key]
                self.tg_lines = order[-9:]
                self.tg_label.text = "\n".join(
                    k + (f" (x{counts[k]})" if counts[k] > 1 else "")
                    for k in self.tg_lines
                )

            lines = (self.log_label.text + "\n" + msg).split("\n")[-60:]
            self.log_label.text = "\n".join(lines)

        Clock.schedule_once(_update, 0)

    def _set_idle_ui(self):
        self.btn_toggle.text = "ЗАПУСТИТЬ"
        self.btn_toggle.background_color = (0.18, 0.65, 0.32, 1)

    def _set_running_ui(self):
        self.btn_toggle.text = "ОСТАНОВИТЬ"
        self.btn_toggle.background_color = (0.8, 0.22, 0.22, 1)

    def _on_engine_stopped(self):
        def _reset(dt):
            if self.vpn_active:
                self.vpn.stop()
                self.vpn_active = False

            self.engine = None
            self._set_idle_ui()

        Clock.schedule_once(_reset, 0)

    def stop_bridge(self):
        if self.vpn_active:
            self.vpn.stop()
            self.vpn_active = False

        if self.engine:
            self.engine.stop()
            self.engine = None

        self._set_idle_ui()

    def toggle(self, instance):
        if self.engine and self.engine.running:
            self.stop_bridge()
            return

        bridge = self.bridge_input.text.strip()

        if "CHANGE-ME" in bridge:
            self.append_log(
                "Ошибка: впишите адрес вашего Worker'а "
                "(см. worker/README.md: wrangler deploy)"
            )
            return

        if not tgws_bridge.normalize_base(bridge)[0]:
            self.append_log("Ошибка: пустой адрес моста")
            return

        use_vpn = bool(self.vpn_switch.active and AndroidVpn.available())

        if not use_vpn:
            self.append_log("Ошибка: без VPN трафик Telegram не попадёт в движок")
            return

        self.engine = TgBridgeEngine(
            bridge_url=bridge,
            log_cb=self.append_log,
            stopped_cb=self._on_engine_stopped,
            protect_cb=self.vpn.protect if use_vpn else None,
            tun_fd_cb=self.vpn.tun_fd if use_vpn else None,
        )

        self.engine.start_in_thread()
        self._set_running_ui()

        if use_vpn:
            self.vpn.start()
            self.vpn_active = True

    def on_pause(self):
        return True

    def on_resume(self):
        pass

    def on_stop(self):
        self.stop_bridge()


if __name__ == "__main__":
    TgBridgeApp().run()
