# Как влить мост в основное приложение (Denter18/Dpi)

Мост задуман как фолбэк-транспорт: сначала нативные шлюзы kwsN (как сейчас),
если они не открываются (провайдер режет IP Telegram) — Worker-мост.
Если мост не настроен, поведение приложения не меняется.

## 1. Файлы, которые копируются без изменений

```
worker/                 -> worker/          # см. worker/README.md
tgws_bridge.py          -> tgws_bridge.py
tests/test_tg_bridge.py -> tests/test_tg_bridge.py
```

`tgws.py` и `tunnel.py` уже есть в основном приложении — не копировать.

## 2. Патч main.py (NoDPIEngine)

**2.1. Параметр в `__init__`:**

```python
        strategy="",
        protect_cb=None,
        tun_fd_cb=None,
        bridge_url="",          # wss://<worker>.workers.dev, "" = мост выключен
    ):
        ...
        self.bridge_url = (bridge_url or "").strip()
```

**2.2. Новый метод (переносится из TgBridgeEngine._open_bridge этого проекта):**

```python
    async def _open_bridge_ws(self, dc, media, first, tag):
        """WebSocket к Worker-мосту: wss://<host>/dc/<N>[m]."""
        import tgws_bridge

        t0 = time.time()
        cand = await tgws_bridge.open_bridge_ws(
            self.connect_tcp, self.bridge_url, dc, media
        )
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
        reply = await asyncio.wait_for(cand.recv(), 6.0)

        if reply:
            self._tg_stat("ws")
            self._tg_stat("open_ms", int((time.time() - t0) * 1000))
            self._note_once(
                ("tg-bridge", dc, media),
                f"[Telegram] DC{dc}{'m' if media else ''} через мост "
                f"{tgws_bridge.normalize_base(self.bridge_url)[0]}",
            )
            return cand, reply, splitter

        cand.close()
        return None, None, None
```

**2.3. В `_telegram_bridge` перед вызовом `_tg_open_ws` добавить попытку моста:**

```python
        if info is not None and self.bridge_url:
            dc, media, tag = info
            try:
                ws, reply, splitter = await self._open_bridge_ws(dc, media, first, tag)
            except Exception as e:
                self._note_once(
                    ("tg-bridge-err", dc),
                    f"[Telegram] мост недоступен ({type(e).__name__}), шлюзы как раньше",
                )
                ws, reply, splitter = None, None, None

            if ws is not None:
                # дальше тот же пайп up()/down(), что и для шлюза —
                # вынести существующий код пайпа в общий хелпер и вызвать здесь
                ...
                return

        # существующий код: ws, reply, ws_splitter = await self._tg_open_ws(...)
```

**2.4. UI:** добавить в `build()` TextInput «Мост (необязательно):» и передавать
`bridge_url=self.bridge_input.text` в `NoDPIEngine`. Пустое поле = старое поведение.

## 3. Что НЕ переносится

- `java_src/org/gvcoder/tgbridge/` — основному приложению не нужен второй
  сервис; маршруты там уже 0.0.0.0/0.
- `TgBridgeEngine` целиком — переносится только `_open_bridge_ws` + попытка
  моста в `_telegram_bridge` (пункт 2.3).

## 4. Проверка после слияния

```
python tests/test_tg_bridge.py
# на устройстве: поле моста пустое -> лог как раньше;
# мост заполнен, шлюзы доступны -> всё равно предпочитаем шлюзы или мост
# (см. порядок в 2.3: мост пробуется первым — поменяйте, если нужно иначе)
```
