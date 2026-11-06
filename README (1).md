# Worker: NoDPI TG Bridge

WebSocket-мост, который принимает соединения приложения (`wss://<имя>.workers.dev/dc/<1-5>[m]`) и пересылает бинарные кадры в веб-шлюз Telegram `kwsN.web.telegram.org/apiws`. С точки зрения провайдера — обычный HTTPS к Cloudflare, блокировки IP Telegram не задействованы.

## Развёртывание (первый раз, ~5 минут)

1. Установите Wrangler: `npm i -g wrangler`
2. Войдите в Cloudflare: `wrangler login`
3. (Опционально) поменяйте `name` в `wrangler.toml`
4. `wrangler deploy`
5. Возьмите URL из вывода (вида `https://nodpi-tg-bridge.<пользователь>.workers.dev`) и введите его в приложении в поле «Адрес моста» (приложение само добавит `wss://` и путь `/dc/N`).

## Проверка без приложения

```bash
# должно вернуть 426/WebSocket only
curl -i https://<имя>.workers.dev/dc/2
# рукопожатие с шлюзом Telegram (101 внутри Worker; снаружи 101 после upgrade)
```

Логи: `wrangler tail`.

## Как это работает

```
Telegram app → MTProto/obfuscated2 → [Android app] → wss://*.workers.dev/dc/2
     (TCP, видит только 10.111.222.1)                     (TLS к Cloudflare)
                                                Worker → wss://kws2.web.telegram.org/apiws
     (MTProto внутри WS-кадров, шифрование Telegram несёт с собой)
```

Worker не видит содержимое MTProto-потока: тот защищён собственным шифрованием Telegram поверх этой транспортной обёртки. TLS-сертификат шлюзов Telegram на имя `kwsN` не выпускается, поэтому веб-клиенты его не проверяют — доверие обеспечивает MTProto.

## Ограничения

- 100 000 запросов/день на бесплатном тарифе (запрос = открытие соединения; для Telegram хватает с запасом).
- Если Cloudflare окажется заблокирован провайдером, мост переносится на любой VPS за 10 минут: замените тело Worker'а на WebSocket-релей к своему серверу (тот же протокол пути `/dc/N[m]`).
