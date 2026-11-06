"""Тесты чистой логики моста (без Kivy, сети и Android).

Запуск на ПК из корня репозитория:
    python -m pytest tests/ -v
    # или без pytest:
    python tests/test_tg_bridge.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tgws
import tgws_bridge


def make_obfuscated_init(dc, media=False, tag=b"\xef\xef\xef\xef"):
    """Собирает валидные первые 64 байта obfuscated2 с известным DC."""
    key = os.urandom(32)
    iv = os.urandom(16)
    plain = bytearray(os.urandom(64))
    plain[56:60] = tag
    plain[60:62] = struct.pack("<h", -dc if media else dc)

    ks = tgws.aes256_ctr_keystream(key, iv, 64)
    init = bytes(a ^ b for a, b in zip(plain, ks))
    init = init[:8] + key + iv + init[56:]
    return init


def xor_stream(init, data, start):
    """Шифрует участок потока гаммой с позиции start (для PacketSplitter)."""
    ks = tgws.aes256_ctr_keystream(init[8:40], init[40:56], start + len(data))
    return bytes(a ^ b for a, b in zip(data, ks[start:]))


def test_parse_dc():
    init = make_obfuscated_init(2)
    dc, media, tag = tgws.parse_obfuscated_init(init)
    assert dc == 2 and media is False and tag == b"\xef\xef\xef\xef"


def test_parse_dc_media():
    init = make_obfuscated_init(4, media=True)
    dc, media, tag = tgws.parse_obfuscated_init(init)
    assert dc == 4 and media is True


def test_parse_rejects_garbage():
    assert tgws.parse_obfuscated_init(os.urandom(128)) is None
    assert tgws.parse_obfuscated_init(b"\x00" * 32) is None


def test_dc_for_ip():
    assert tgws.dc_for_ip("149.154.175.10") == 1
    assert tgws.dc_for_ip("149.154.175.120") == 3
    assert tgws.dc_for_ip("149.154.167.95") == 4
    assert tgws.dc_for_ip("91.108.56.100") == 5
    assert tgws.dc_for_ip("91.108.8.50") == 3
    assert tgws.dc_for_ip("10.0.0.1") == 2  # запасной ответ


def test_packet_splitter_aligned():
    # Поток из двух пакетов MTProto (тег ef): короткий заголовок и длинный.
    p1 = bytes([5]) + os.urandom(20)          # длина 5*4 = 20, с заголовком 21 байт
    p2 = bytes([0x7F]) + struct.pack("<H", 2) + b"\x00" + os.urandom(8)
    stream = p1 + p2

    init = make_obfuscated_init(2)
    enc = xor_stream(init, stream, 64)
    sp = tgws.PacketSplitter(init[:64], b"\xef\xef\xef\xef")
    chunks = sp.feed(enc)
    assert chunks == [enc[: len(p1)], enc[len(p1):]], "границы кадров = границы пакетов"


def test_packet_splitter_by_byte():
    # Кормим по одному байту: куски сливаются в те же пакеты.
    p1 = bytes([3]) + os.urandom(11)
    p2 = bytes([1]) + os.urandom(3)
    stream = p1 + p2

    init = make_obfuscated_init(3)
    enc = xor_stream(init, stream, 64)
    sp = tgws.PacketSplitter(init[:64], b"\xef\xef\xef\xef")
    out = b""
    chunk_sizes = []
    for i in range(len(enc)):
        for chunk in sp.feed(enc[i : i + 1]):
            out += chunk
            chunk_sizes.append(len(chunk))
    assert out == enc
    # кормим по байту: куски дробные, но сливаются ровно в пакеты
    assert sum(chunk_sizes[: len(p1)]) == len(p1), "первый пакет собрался целиком"


def test_frame_roundtrip():
    payload = os.urandom(300)
    frame = tgws.build_frame(payload)
    assert frame[0] == 0x82  # FIN + binary
    n = frame[1] & 0x7F
    off = 2
    if n == 126:
        (n,) = struct.unpack("!H", frame[2:4])
        off = 4
    key = frame[off : off + 4]
    masked = frame[off + 4 : off + 4 + n]
    assert tgws._mask(masked, key) == payload and n == 300


def test_normalize_base():
    assert tgws_bridge.normalize_base("wss://a.workers.dev") == ("a.workers.dev", "")
    assert tgws_bridge.normalize_base("https://a.workers.dev/x") == ("a.workers.dev", "/x")
    assert tgws_bridge.normalize_base("a.workers.dev/") == ("a.workers.dev", "")
    assert tgws_bridge.normalize_base("") == ("", "")


def test_bridge_path():
    assert tgws_bridge.bridge_path(2, False) == "/dc/2"
    assert tgws_bridge.bridge_path(5, True) == "/dc/5m"


def test_is_telegram_ip():
    assert tgws.is_telegram_ip("149.154.167.50")
    assert tgws.is_telegram_ip("91.108.4.1")
    assert not tgws.is_telegram_ip("8.8.8.8")
    assert not tgws.is_telegram_ip("example.com")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("ok", fn.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL", fn.__name__, "-", e)
    sys.exit(1 if failed else 0)
