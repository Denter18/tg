// NoDPI TG Bridge — WebSocket-мост к веб-шлюзам Telegram.
//
// Приложение на Android подключается сюда по wss:// (SNI *.workers.dev,
// который провайдер не режет), а Worker пересылает бинарные кадры в
// kwsN.web.telegram.org/apiws — веб-шлюз Telegram, принимающий тот же
// MTProto-поток (obfuscated2), что и нативные серверы 149.154.x.x.
// Так обходится блокировка Telegram по IP-адресам: снаружи виден только
// обычный HTTPS-трафик к Cloudflare.
//
// Маршруты:
//   /dc/1 ... /dc/5    — дата-центр N        -> kws{N}.web.telegram.org
//   /dc/1m ... /dc/5m  — медиа-центр DC N    -> kws{N}-1.web.telegram.org
//
// Деплой: см. README (npm i -g wrangler && wrangler deploy).

const DC_PATH = /^\/dc\/([1-5])(m?)$/;

// Заголовки как у веб-клиента Telegram (web.telegram.org): шлюз может
// отвечать 302/404 на рукопожатия без "правильного" Origin.
const UPSTREAM_HEADERS = {
  "Upgrade": "websocket",
  "Connection": "Upgrade",
  "Sec-WebSocket-Protocol": "binary",
  "Origin": "https://web.telegram.org",
  "User-Agent":
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
};

// Связка a<->b: сообщения одного сокета -> другой, закрытие/ошибка
// одного закрывают другой. allowHalfOpen: закрытие пересылаем явно,
// чтобы MTProto-поток корректно доотправился в обе стороны.
function pipe(a, b) {
  a.addEventListener("message", (event) => {
    try {
      b.send(event.data);
    } catch {
      try { b.close(1011); } catch {}
    }
  });
  a.addEventListener("close", (event) => {
    try { b.close(event.code || 1000, event.reason); } catch {}
  });
  a.addEventListener("error", () => {
    try { b.close(1011); } catch {}
  });
}

export default {
  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response(
        "NoDPI TG Bridge: WebSocket only. Paths: /dc/<1-5>[m]",
        { status: 426 }
      );
    }

    const m = DC_PATH.exec(new URL(request.url).pathname);
    if (!m) {
      return new Response("bad path, expected /dc/<1-5>[m]", { status: 404 });
    }

    const dc = Number(m[1]);
    const media = m[2] === "m";
    const upstreamName = media
      ? `kws${dc}-1.web.telegram.org`
      : `kws${dc}.web.telegram.org`;

    let upstream;
    try {
      const resp = await fetch(`https://${upstreamName}/apiws`, {
        headers: UPSTREAM_HEADERS,
      });
      upstream = resp.status === 101 && resp.webSocket ? resp.webSocket : null;
    } catch (e) {
      return new Response(`upstream ${upstreamName}: ${e}`, { status: 502 });
    }

    if (!upstream) {
      return new Response(`upstream ${upstreamName}: no 101`, { status: 502 });
    }

    // Бинарные кадры доставляем как ArrayBuffer (умолчание на новых
    // compatibility_date — Blob, что сломало бы прозрачную пересылку).
    upstream.binaryType = "arraybuffer";
    upstream.accept({ allowHalfOpen: true });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept({ allowHalfOpen: true });

    pipe(server, upstream);
    pipe(upstream, server);

    return new Response(null, { status: 101, webSocket: client });
  },
};
