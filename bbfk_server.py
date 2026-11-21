#!/usr/bin/env python3
"""
Bubble Bobble for Kakao (BBFK) - Fake Custom Server
--------------------------------------------------
Zero-dependency Python 3 mock server reverse-engineered from BBFK_sourcecode.

Protocol (from NRequestBase.cs & BoxingPacker.cs):
  - API base:      http://<host>:<port>/index.php/<endpoint>
  - Request:       POST application/x-www-form-urlencoded with field `param`
                   `param` = urlsafe_b64(zlib.compress(msgpack_pack(dict)))
  - Response:      JSON {"bin_response": urlsafe_b64(zlib.compress(msgpack_pack(dict)))}
  - Resources:     GET http://<host>:<port>/resource/resources/<Platform>/<file>
                   Episode .bin files are Protobuf (SerializeEpisodeData) encrypted
                   with BinaryConverter.Encryption + MyRand.
  - Policy pages:  GET /view/a/policy_service, /view/a/policy_privacy

Usage:
  python3 bbfk_server.py --host 0.0.0.0 --port 8080
  (or --port 80 with sudo/root if redirecting 14.63.200.180 via hosts/DNS)
"""

import argparse
import base64
import json
import math
import os
import struct
import threading
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# 1. Pure-Python MessagePack Encoder / Decoder (matches MsgPack/BoxingPacker)
# ---------------------------------------------------------------------------

def msgpack_pack(obj) -> bytes:
    out = bytearray()
    _mp_pack(obj, out)
    return bytes(out)


def _mp_pack(obj, out: bytearray):
    if obj is None:
        out.append(0xC0)
    elif isinstance(obj, bool):
        out.append(0xC3 if obj else 0xC2)
    elif isinstance(obj, int):
        if 0 <= obj <= 0x7F:
            out.append(obj)
        elif -32 <= obj < 0:
            out.append(obj & 0xFF)
        elif 0 <= obj <= 0xFF:
            out.extend((0xCC, obj))
        elif 0 <= obj <= 0xFFFF:
            out.append(0xCD)
            out.extend(struct.pack(">H", obj))
        elif 0 <= obj <= 0xFFFFFFFF:
            out.append(0xCE)
            out.extend(struct.pack(">I", obj))
        elif 0 <= obj <= 0xFFFFFFFFFFFFFFFF:
            out.append(0xCF)
            out.extend(struct.pack(">Q", obj))
        elif -128 <= obj < 0:
            out.append(0xD0)
            out.extend(struct.pack(">b", obj))
        elif -32768 <= obj < 0:
            out.append(0xD1)
            out.extend(struct.pack(">h", obj))
        elif -2147483648 <= obj < 0:
            out.append(0xD2)
            out.extend(struct.pack(">i", obj))
        else:
            out.append(0xD3)
            out.extend(struct.pack(">q", obj))
    elif isinstance(obj, float):
        out.append(0xCB)
        out.extend(struct.pack(">d", obj))
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        n = len(b)
        if n <= 31:
            out.append(0xA0 | n)
        elif n <= 0xFFFF:
            out.append(0xDA)
            out.extend(struct.pack(">H", n))
        else:
            out.append(0xDB)
            out.extend(struct.pack(">I", n))
        out.extend(b)
    elif isinstance(obj, (bytes, bytearray)):
        n = len(obj)
        if n <= 31:
            out.append(0xA0 | n)
        elif n <= 0xFFFF:
            out.append(0xDA)
            out.extend(struct.pack(">H", n))
        else:
            out.append(0xDB)
            out.extend(struct.pack(">I", n))
        out.extend(obj)
    elif isinstance(obj, (list, tuple)):
        n = len(obj)
        if n <= 15:
            out.append(0x90 | n)
        elif n <= 0xFFFF:
            out.append(0xDC)
            out.extend(struct.pack(">H", n))
        else:
            out.append(0xDD)
            out.extend(struct.pack(">I", n))
        for item in obj:
            _mp_pack(item, out)
    elif isinstance(obj, dict):
        n = len(obj)
        if n <= 15:
            out.append(0x80 | n)
        elif n <= 0xFFFF:
            out.append(0xDE)
            out.extend(struct.pack(">H", n))
        else:
            out.append(0xDF)
            out.extend(struct.pack(">I", n))
        for k, v in obj.items():
            _mp_pack(k, out)
            _mp_pack(v, out)
    else:
        raise TypeError(f"Unsupported msgpack type: {type(obj)}")


def msgpack_unpack(data: bytes):
    val, _ = _mp_unpack(data, 0)
    return val


def _mp_unpack(buf: bytes, pos: int):
    b = buf[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return struct.unpack_from(">b", bytes([b]))[0], pos
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
        return _mp_unpack_map(buf, pos, n)
    if 0x90 <= b <= 0x9F:
        n = b & 0x0F
        return _mp_unpack_array(buf, pos, n)
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return buf[pos:pos + n].decode("utf-8", errors="replace"), pos + n
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if b == 0xCA:
        return struct.unpack_from(">f", buf, pos)[0], pos + 4
    if b == 0xCB:
        return struct.unpack_from(">d", buf, pos)[0], pos + 8
    if b == 0xCC:
        return buf[pos], pos + 1
    if b == 0xCD:
        return struct.unpack_from(">H", buf, pos)[0], pos + 2
    if b == 0xCE:
        return struct.unpack_from(">I", buf, pos)[0], pos + 4
    if b == 0xCF:
        return struct.unpack_from(">Q", buf, pos)[0], pos + 8
    if b == 0xD0:
        return struct.unpack_from(">b", buf, pos)[0], pos + 1
    if b == 0xD1:
        return struct.unpack_from(">h", buf, pos)[0], pos + 2
    if b == 0xD2:
        return struct.unpack_from(">i", buf, pos)[0], pos + 4
    if b == 0xD3:
        return struct.unpack_from(">q", buf, pos)[0], pos + 8
    if b == 0xDA:
        n = struct.unpack_from(">H", buf, pos)[0]
        pos += 2
        return buf[pos:pos + n].decode("utf-8", errors="replace"), pos + n
    if b == 0xDB:
        n = struct.unpack_from(">I", buf, pos)[0]
        pos += 4
        return buf[pos:pos + n].decode("utf-8", errors="replace"), pos + n
    if b == 0xDC:
        n = struct.unpack_from(">H", buf, pos)[0]
        return _mp_unpack_array(buf, pos + 2, n)
    if b == 0xDD:
        n = struct.unpack_from(">I", buf, pos)[0]
        return _mp_unpack_array(buf, pos + 4, n)
    if b == 0xDE:
        n = struct.unpack_from(">H", buf, pos)[0]
        return _mp_unpack_map(buf, pos + 2, n)
    if b == 0xDF:
        n = struct.unpack_from(">I", buf, pos)[0]
        return _mp_unpack_map(buf, pos + 4, n)
    raise ValueError(f"Unknown msgpack prefix: 0x{b:02x} at {pos - 1}")


def _mp_unpack_array(buf: bytes, pos: int, n: int):
    arr = []
    for _ in range(n):
        v, pos = _mp_unpack(buf, pos)
        arr.append(v)
    return arr, pos


def _mp_unpack_map(buf: bytes, pos: int, n: int):
    mp = {}
    for _ in range(n):
        k, pos = _mp_unpack(buf, pos)
        v, pos = _mp_unpack(buf, pos)
        mp[k] = v
    return mp, pos


# ---------------------------------------------------------------------------
# 2. NRequestBase Wire Encoding / Decoding
# ---------------------------------------------------------------------------

def encode_bin_response(payload: dict) -> str:
    packed = msgpack_pack(payload)
    compressed = zlib.compress(packed)
    b64 = base64.b64encode(compressed).decode("ascii")
    b64_urlsafe = b64.replace("+", "-").replace("/", "_")
    return json.dumps({"bin_response": b64_urlsafe})


def decode_bin_param(param_str: str) -> dict:
    b64 = param_str.replace("-", "+").replace("_", "/")
    pad = (-len(b64)) % 4
    if pad:
        b64 += "=" * pad
    raw = base64.b64decode(b64)
    decompressed = zlib.decompress(raw)
    return msgpack_unpack(decompressed)


# ---------------------------------------------------------------------------
# 3. BinaryConverter + MyRand + Protobuf Episode Generator
# ---------------------------------------------------------------------------

MYRAND_ARRAYS = [
    88, 208, 6, 145, 183, 230, 53, 234, 135, 156, 62, 155, 161, 116, 12, 169,
    39, 131, 27, 15, 212, 87, 164, 225, 137, 185, 0, 166, 33, 37, 78, 50,
    40, 86, 57, 107, 60, 207, 113, 220, 248, 222, 187, 92, 200, 42, 147, 14,
    177, 210, 163, 178, 98, 181, 218, 158, 99, 108, 24, 231, 139, 71, 129, 153,
    48, 65, 85, 13, 252, 249, 184, 16, 103, 82, 59, 49, 112, 232, 221, 196,
    182, 56, 154, 67, 226, 58, 206, 51, 159, 38, 36, 219, 110, 95, 236, 160,
    213, 198, 240, 151, 11, 195, 174, 73, 114, 91, 130, 25, 141, 241, 233, 162,
    3, 223, 168, 143, 109, 9, 244, 170, 52, 106, 80, 194, 189, 255, 5, 245,
    190, 146, 214, 133, 197, 123, 224, 101, 1, 152, 10, 79, 204, 254, 111, 192,
    242, 68, 18, 70, 93, 125, 205, 45, 28, 105, 157, 89, 19, 55, 119, 246,
    4, 32, 191, 250, 128, 132, 173, 150, 124, 44, 21, 35, 22, 66, 2, 217,
    96, 69, 90, 26, 63, 172, 243, 171, 209, 47, 238, 46, 76, 54, 23, 199,
    188, 127, 215, 100, 29, 122, 253, 142, 239, 83, 102, 227, 251, 149, 94, 203,
    179, 81, 97, 144, 202, 216, 228, 120, 75, 7, 167, 84, 148, 175, 126, 118,
    8, 104, 237, 72, 229, 186, 17, 180, 31, 136, 211, 61, 115, 176, 41, 77,
    117, 74, 64, 247, 134, 20, 121, 30, 34, 201, 235, 140, 43, 138, 165, 193,
]


def binary_converter_encrypt(raw_bytes: bytes) -> bytes:
    buf = bytearray(raw_bytes)
    n = len(buf)
    if n == 0:
        return bytes(buf)
    for i in range(n - 1, 0, -1):
        buf[i - 1] = (buf[i - 1] + buf[i]) & 0xFF
    seed = (89890 + buf[0]) & 0xFF
    for i in range(1, n):
        rnd = MYRAND_ARRAYS[seed]
        seed = (seed + 1) & 0xFF
        buf[i] = (buf[i] + rnd) & 0xFF
    return bytes(buf)


def binary_converter_decrypt(enc_bytes: bytes) -> bytes:
    buf = bytearray(enc_bytes)
    n = len(buf)
    if n == 0:
        return bytes(buf)
    seed = (89890 + buf[0]) & 0xFF
    for i in range(1, n):
        rnd = MYRAND_ARRAYS[seed]
        seed = (seed + 1) & 0xFF
        buf[i] = (buf[i] - rnd) & 0xFF
    for i in range(1, n):
        buf[i - 1] = (buf[i - 1] - buf[i]) & 0xFF
    return bytes(buf)


def _pb_varint(val: int) -> bytes:
    if val < 0:
        val &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_key(field_num: int, wire_type: int) -> bytes:
    return _pb_varint((field_num << 3) | wire_type)


def _pb_int(field_num: int, val: int) -> bytes:
    return _pb_key(field_num, 0) + _pb_varint(val)


def _pb_float(field_num: int, val: float) -> bytes:
    return _pb_key(field_num, 5) + struct.pack("<f", val)


def _pb_bytes(field_num: int, b: bytes) -> bytes:
    return _pb_key(field_num, 2) + _pb_varint(len(b)) + b


def _pb_str(field_num: int, s: str) -> bytes:
    return _pb_bytes(field_num, s.encode("utf-8"))


def _pb_header(name: str, obj_id: int = 1, ver: int = 4, ver_time: int = 1) -> bytes:
    return (
        _pb_bytes(1, name.encode("utf-8"))
        + _pb_int(2, obj_id)
        + _pb_int(3, ver)
        + _pb_int(4, ver_time)
    )


def _build_map_data(map_name: str, stage_idx: int, part_idx: int) -> bytes:
    """
    Builds one 32x34 SerializeMapData part with reachable platforms (4-5 rows apart
    from bottom floor y=33) and varied enemy counts/types.
    """
    width, height = 32, 34
    layout = (stage_idx * 3 + part_idx) % 8
    tip_msgs = []
    air_ints = []

    for y in range(height):
        for x in range(width):
            is_border = (x == 0 or x == width - 1 or y == 0 or y == height - 1)
            is_plat = False
            if layout == 0:
                # Classic Bubble Bobble 4-tier ledges (easy jump from floor y=33)
                is_plat = (y in (28, 22, 16, 10) and 4 <= x <= 27 and not (14 <= x <= 17))
            elif layout == 1:
                # Ascending pyramid steps
                is_plat = (
                    (y == 28 and 3 <= x <= 28)
                    or (y == 23 and 6 <= x <= 25)
                    or (y == 18 and 9 <= x <= 22)
                    or (y == 13 and 12 <= x <= 19)
                )
            elif layout == 2:
                # Alternating zig-zag ledges
                is_plat = (
                    (y == 28 and 2 <= x <= 18)
                    or (y == 23 and 13 <= x <= 29)
                    or (y == 18 and 2 <= x <= 18)
                    or (y == 13 and 13 <= x <= 29)
                    or (y == 8 and 8 <= x <= 23)
                )
            elif layout == 3:
                # Twin side towers + center bridges
                is_plat = (
                    (y in (28, 19, 10) and (2 <= x <= 10 or 21 <= x <= 29))
                    or (y in (24, 15) and 11 <= x <= 20)
                )
            elif layout == 4:
                # Stepped staircase valley
                is_plat = (
                    (y == 29 and (2 <= x <= 8 or 23 <= x <= 29))
                    or (y == 24 and (6 <= x <= 13 or 18 <= x <= 25))
                    or (y == 19 and 10 <= x <= 21)
                    or (y == 14 and (4 <= x <= 11 or 20 <= x <= 27))
                )
            elif layout == 5:
                # Checkerboard floating islands
                is_plat = (
                    (y in (28, 18) and (3 <= x <= 9 or 13 <= x <= 18 or 22 <= x <= 28))
                    or (y in (23, 13) and (7 <= x <= 13 or 18 <= x <= 24))
                )
            elif layout == 6:
                # Wide center arena with side perches
                is_plat = (
                    (y == 28 and 7 <= x <= 24)
                    or (y == 23 and (2 <= x <= 8 or 23 <= x <= 29))
                    or (y == 18 and 9 <= x <= 22)
                    or (y == 12 and (3 <= x <= 10 or 21 <= x <= 28))
                )
            else:
                # Castle battlements
                is_plat = (
                    (y == 28 and 3 <= x <= 28 and not (10 <= x <= 12) and not (19 <= x <= 21))
                    or (y == 22 and 5 <= x <= 26 and not (14 <= x <= 17))
                    or (y == 16 and (2 <= x <= 11 or 20 <= x <= 29))
                    or (y == 11 and 11 <= x <= 20)
                )

            if is_border or is_plat:
                tip_msgs.append(_pb_int(1, 0) + _pb_int(2, 0))
                air_ints.append(1)
            else:
                tip_msgs.append(_pb_int(1, -1) + _pb_int(2, -1))
                air_ints.append(0)

    # 2 entries required (player + pet) on bottom floor
    player_msg_1 = _pb_int(1, 1) + _pb_float(2, 5.0) + _pb_float(3, 30.0) + _pb_int(4, 1)
    player_msg_2 = _pb_int(1, 2) + _pb_float(2, 7.0) + _pb_float(3, 30.0) + _pb_int(4, 1)

    # Varied enemy counts (3 to 6) and enemy IDs (1..8)
    enemy_count = 3 + ((stage_idx + part_idx) % 4)
    spawn_spots = [
        (16.0, 20.0, -1), (22.0, 26.0, -1), (10.0, 15.0, 1),
        (24.0, 15.0, -1), (14.0, 10.0, 1), (8.0, 26.0, 1),
    ]
    enemies = []
    enemy_ids = set()
    for i in range(enemy_count):
        eid = 1 + ((stage_idx + i) % 8)
        enemy_ids.add(eid)
        sx, sy, sdir = spawn_spots[i % len(spawn_spots)]
        enemies.append(
            _pb_int(1, eid) + _pb_float(2, sx) + _pb_float(3, sy) + _pb_int(4, sdir) + _pb_int(5, i // 2)
        )

    map_msg = bytearray()
    map_msg += _pb_bytes(1, _pb_header("map"))
    map_msg += _pb_int(2, width)
    map_msg += _pb_int(3, height)
    map_msg += _pb_bytes(4, _pb_header("tip"))
    for tm in tip_msgs:
        map_msg += _pb_bytes(5, tm)
    map_msg += _pb_bytes(6, _pb_header("air"))
    for a in air_ints:
        map_msg += _pb_int(7, a)
    map_msg += _pb_bytes(8, _pb_header("enemy"))
    map_msg += _pb_int(9, len(enemies))
    for em in enemies:
        map_msg += _pb_bytes(10, em)
    map_msg += _pb_bytes(11, _pb_header("item"))
    map_msg += _pb_int(12, 0)
    map_msg += _pb_bytes(14, _pb_header("player"))
    map_msg += _pb_int(15, 2)
    map_msg += _pb_bytes(16, player_msg_1)
    map_msg += _pb_bytes(16, player_msg_2)
    map_msg += _pb_bytes(17, _pb_header("hole"))
    map_msg += _pb_int(18, 0)
    map_msg += _pb_bytes(20, _pb_header("bubble"))
    map_msg += _pb_int(21, 0)
    map_msg += _pb_bytes(26, _pb_header("bg"))
    map_msg += _pb_int(27, 1)
    map_msg += _pb_str(28, "mp_0021_0")
    map_msg += _pb_bytes(29, _pb_header("filename"))
    map_msg += _pb_str(30, map_name)
    map_msg += _pb_bytes(31, _pb_header("hurryup"))
    map_msg += _pb_int(32, 60)
    map_msg += _pb_bytes(33, _pb_header("bspeed"))
    map_msg += _pb_float(34, 100.0)
    map_msg += _pb_bytes(35, _pb_header("bsec"))
    map_msg += _pb_float(36, 1.0)
    map_msg += _pb_bytes(37, _pb_header("extend"))
    map_msg += _pb_int(38, 0)
    return bytes(map_msg)


def build_sample_episode_bin(episode_bin_name: str, dungeon_count: int = 10, maps_per_dungeon: int = 2) -> bytes:
    """
    Constructs a valid SerializeEpisodeData protobuf (schema from MySerializeDll.dll)
    with varied multi-part dungeons (2-3 maps each) and encrypts it.
    """
    dungeons_bytes = bytearray()
    buttons_bytes = bytearray()
    btn_coords = [
        (-420.0, -140.0), (-320.0, 20.0), (-220.0, 140.0), (-110.0, -30.0), (0.0, -150.0),
        (110.0, 30.0), (220.0, 150.0), (320.0, -20.0), (410.0, -130.0), (460.0, 80.0),
    ]

    for d_idx in range(1, dungeon_count + 1):
        parts = 1 if dungeon_count == 1 else (2 + (d_idx % 2))  # 2 or 3 parts per stage
        d_msg = bytearray()
        d_msg += _pb_bytes(1, _pb_header("dungeon"))
        d_msg += _pb_bytes(2, _pb_header("map"))
        d_msg += _pb_int(3, parts)
        for m_idx in range(parts):
            m_bytes = _build_map_data(f"{episode_bin_name}_d{d_idx}_m{m_idx+1}", d_idx, m_idx)
            d_msg += _pb_bytes(4, m_bytes)
        bonus_bytes = _build_map_data(f"{episode_bin_name}_d{d_idx}_bonus", d_idx, 99)
        d_msg += _pb_bytes(7, _pb_header("bonus"))
        d_msg += _pb_bytes(9, bonus_bytes)
        d_msg += _pb_bytes(5, _pb_header("filename"))
        d_msg += _pb_str(6, f"{episode_bin_name}_d{d_idx}")
        d_msg += _pb_bytes(10, _pb_header("enemylist"))
        eids = [1 + ((d_idx + k) % 8) for k in range(4)]
        d_msg += _pb_int(11, len(eids))
        for eid in eids:
            d_msg += _pb_int(12, eid)
        d_msg += _pb_bytes(16, _pb_header("icon"))
        d_msg += _pb_str(17, "0032")
        d_msg += _pb_bytes(18, _pb_header("dtext"))
        d_msg += _pb_str(19, f"Stage {d_idx}")
        dungeons_bytes += _pb_bytes(4, bytes(d_msg))

        bx, by = btn_coords[(d_idx - 1) % len(btn_coords)]
        btn_msg = _pb_int(1, d_idx) + _pb_float(2, bx) + _pb_float(3, by)
        buttons_bytes += _pb_bytes(11, btn_msg)

    ep_msg = bytearray()
    ep_msg += _pb_bytes(1, _pb_header("episode", 1, 4, 1))
    ep_msg += _pb_bytes(2, _pb_header("dungeon"))
    ep_msg += _pb_int(3, dungeon_count)
    ep_msg += dungeons_bytes
    ep_msg += _pb_bytes(5, _pb_header("filename"))
    ep_msg += _pb_str(6, episode_bin_name)
    ep_msg += _pb_bytes(7, _pb_header("mapimg"))
    ep_msg += _pb_str(8, "ep_map_01")
    ep_msg += _pb_bytes(9, _pb_header("mapbtn"))
    ep_msg += _pb_int(10, dungeon_count)
    ep_msg += buttons_bytes
    ep_msg += _pb_bytes(12, _pb_header("mapbg"))
    ep_msg += _pb_str(13, "ep_bg_01")

    return binary_converter_encrypt(bytes(ep_msg))


def build_sample_map_png(width: int = 1280, height: int = 720) -> bytes:
    """Generates a valid 1280x720 RGB PNG with a sky-to-meadow gradient (zero dependencies)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)  # filter type 0
        if y < height // 2:
            r, g, b = 135, 206, 250  # sky blue
        else:
            r, g, b = 120, 200, 110  # meadow green
        raw_rows.extend(bytes((r, g, b)) * width)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), 6)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


# ---------------------------------------------------------------------------
# 4. In-Memory Game State & Master Data
# ---------------------------------------------------------------------------

class GameServerState:
    def __init__(self, base_url: str, save_file: str = "bbfk_save.json"):
        self.save_file = save_file
        self.lock = threading.Lock()
        self.base_url = base_url.rstrip("/")
        self.user_id = 100001
        self.viewer_id = "100001"
        self.gold = 99999          # Cash currency (Sujung / Diamonds)
        self.coin = 500000         # Gold coins
        self.friend_point = 10000
        self.heart = 99
        self.heart_max = 99
        self.level = 1
        self.exp = 0
        self.exp_max = 100
        self.tutorial_status = -1  # -1 = completed (goes straight to lobby Select)
        self.game_tutorial_status = 0
        self.equipped_user_character_id = 1

        self.episode_bins = {
            "episode_tutorial.bin": build_sample_episode_bin("episode_tutorial", 1, 1),
            "episode_001.bin": build_sample_episode_bin("episode_001", 10, 2),
            "ep_map_01.png": build_sample_map_png(),
            "ep_bg_01.png": build_sample_map_png(),
            "ep_end.png": build_sample_map_png(),
            "mp_0021_0.png": build_sample_map_png(512, 512),
        }

        self.user_characters = [
            {
                "user_character_id": 1,
                "mst_character_id": 1,
                "mst_character_grade_id": 1,
                "life": 3,
                "level": 1,
                "exp": 0,
                "enchant_level": 0,
                "enchant_correction": 0,
            }
        ]
        self.user_pets = [
            {
                "user_pet_id": 1,
                "user_id": self.user_id,
                "mst_pet_id": 1,
                "enable_use_count": 5,
                "create_date": "2026-11-20 00:00:00",
                "status": 1,
                "get_type": 1,
            }
        ]
        self.user_items = [
            {"user_id": self.user_id, "mst_item_id": i, "item_num": 10}
            for i in range(1, 10)
        ]
        self.progress_episode = [
            {"user_id": self.user_id, "mst_episode_id": 1, "is_unlock": 1, "clear_total": 0, "is_check_guide": 1}
        ]
        self.progress_dungeon = [
            {
                "user_id": self.user_id,
                "mst_dungeon_id": i,
                "is_enable_play": 1 if i == 1 else 0,
                "is_clear": 0,
                "best_score": 0,
                "extend_bubble_list": "",
                "clear_rank": 0,
                "dungeon_date": "2026-11-20 00:00:00",
            }
            for i in range(1, 11)
        ]
        self._load_save()

    def _load_save(self):
        if not self.save_file or not os.path.exists(self.save_file):
            return
        try:
            with open(self.save_file, "r", encoding="utf-8") as f:
                s = json.load(f)
            for k in (
                "gold", "coin", "friend_point", "heart", "level", "exp", "exp_max",
                "tutorial_status", "game_tutorial_status", "equipped_user_character_id",
                "user_characters", "user_pets", "user_items", "progress_episode",
            ):
                if k in s:
                    setattr(self, k, s[k])
            if "progress_dungeon" in s:
                by_id = {d["mst_dungeon_id"]: d for d in s["progress_dungeon"]}
                for d in self.progress_dungeon:
                    if d["mst_dungeon_id"] in by_id:
                        d.update(by_id[d["mst_dungeon_id"]])
            print(f"[SAVE] Loaded progress from {self.save_file}")
        except Exception as exc:
            print(f"[SAVE] Failed to load {self.save_file}: {exc}")

    def _write_save(self):
        if not self.save_file:
            return
        try:
            data = {
                "gold": self.gold,
                "coin": self.coin,
                "friend_point": self.friend_point,
                "heart": self.heart,
                "level": self.level,
                "exp": self.exp,
                "exp_max": self.exp_max,
                "tutorial_status": self.tutorial_status,
                "game_tutorial_status": self.game_tutorial_status,
                "equipped_user_character_id": self.equipped_user_character_id,
                "user_characters": self.user_characters,
                "user_pets": self.user_pets,
                "user_items": self.user_items,
                "progress_episode": self.progress_episode,
                "progress_dungeon": self.progress_dungeon,
            }
            tmp = self.save_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.save_file)
        except Exception as exc:
            print(f"[SAVE] Failed to write {self.save_file}: {exc}")

    def now_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def header(self, error_code: int = 0, error_message: str = "") -> dict:
        return {
            "time": int(time.time()),
            "error_code": error_code,
            "error_message": error_message,
            "status_code": 0,
            "master_data_version": 1,
            "is_retry_request": 0,
        }

    def user_obj(self) -> dict:
        now = self.now_str()
        return {
            "user_id": self.user_id,
            "login": {"last_login_date": now, "login_total": 1, "event_login_total": 1},
            "episode": {"progress_mst_dungeon_id": 1, "progress_dungeon_date": now},
            "currency": {"gold": self.gold, "friend_point": self.friend_point, "coin": self.coin},
            "option": {
                "is_autojump": False,
                "is_autoshot": False,
                "is_bgm_on": True,
                "is_se_on": True,
                "is_push_on": False,
                "joystick_type": 0,
                "button_type": 0,
                "message_blocked": False,
            },
            "detail": {
                "is_post_review": False,
                "tutorial_status": self.tutorial_status,
                "information_off_date": "2000-01-01 00:00:00",
                "active_bubble_attendance_id": 0,
                "game_tutorial_status": self.game_tutorial_status,
                "equipped_user_character_id": self.equipped_user_character_id,
                "count_character_slot": 10,
                "character_book": "1",
                "story_progress_id": 135,
                "story_progress_dungeon_id": 0,
                "toast_update_date": now,
            },
            "heart": {
                "heart": self.heart,
                "heart_max": self.heart_max,
                "heart_update_date": now,
                "recovery_time": 1,
                "life_free_ticket_end_time": "2000-01-01 00:00:00",
            },
            "level": {"level": self.level, "exp": self.exp, "exp_max": self.exp_max, "score_multiply": 1.0},
            "boss": {"boss_clear_ticket": 3, "boss_clear_ticket_update_time": now},
        }

    def handle_api(self, endpoint: str, params: dict) -> dict:
        resp = self._handle_api_inner(endpoint, params)
        if endpoint in (
            "game/start", "game/dungeon_clear", "game/continue_start",
            "coin/buy_item", "coin/exchange_gold", "heart/exchange_gold",
            "character/level_up_by_currency", "user/update_game_tutorial",
            "gacha/exec_pet_gacha", "gacha/exec_character_gacha",
        ):
            self._write_save()
        return resp

    def _handle_api_inner(self, endpoint: str, params: dict) -> dict:
        with self.lock:
            now = self.now_str()
            h = self.header()

            if endpoint == "bbsystem/start":
                return {
                    "header": h,
                    "resources_host": f"{self.base_url}/resource/",
                    "game_config_list": [
                        {"config_key": "CONTINUE_PRICE_GOLD", "config_value": "3/5,10/15,20/30", "config_sale_info": ""},
                        {"config_key": "CONTINUE_PRICE_GOLD_BOSS", "config_value": "5/10,15/20,25/30", "config_sale_info": ""},
                        {"config_key": "SERVER_ENVIRONMENT", "config_value": "local", "config_sale_info": ""},
                        {"config_key": "REVIEW_IN_PROGRESS", "config_value": "false", "config_sale_info": ""},
                        {"config_key": "NOTICE_POPUP_OPEN", "config_value": "0", "config_sale_info": ""},
                        {"config_key": "IOS_CONFIG", "config_value": "1,1,1,1", "config_sale_info": ""},
                    ],
                }

            if endpoint == "master_data/get_episode_master":
                return {
                    "header": h,
                    "episode_list": [
                        {
                            "mst_episode_id": -1,
                            "unlock_gold": 0,
                            "unlock_friend_point": 0,
                            "lang_name": "Tutorial",
                            "is_event": 0,
                            "episode_bin": "episode_tutorial",
                            "version": 5,
                            "weight_exp": 1.0,
                            "start_date": "2020-01-01 00:00:00",
                            "end_date": "2099-12-31 23:59:59",
                        },
                        {
                            "mst_episode_id": 1,
                            "unlock_gold": 0,
                            "unlock_friend_point": 0,
                            "lang_name": "Episode 1",
                            "is_event": 0,
                            "episode_bin": "episode_001",
                            "version": 5,
                            "weight_exp": 1.0,
                            "start_date": "2020-01-01 00:00:00",
                            "end_date": "2099-12-31 23:59:59",
                        },
                    ],
                    "dungeon_list": [
                        {"mst_dungeon_id": -1, "mst_episode_id": -1, "play_order": 1, "lang_name": "Tutorial", "goal_score_1": 1000, "goal_score_2": 2000, "goal_score_3": 3000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Tutorial"},
                        {"mst_dungeon_id": 1, "mst_episode_id": 1, "play_order": 1, "lang_name": "Stage 1-1", "goal_score_1": 1000, "goal_score_2": 2000, "goal_score_3": 3000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-1"},
                        {"mst_dungeon_id": 2, "mst_episode_id": 1, "play_order": 2, "lang_name": "Stage 1-2", "goal_score_1": 1500, "goal_score_2": 3000, "goal_score_3": 4500, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-2"},
                        {"mst_dungeon_id": 3, "mst_episode_id": 1, "play_order": 3, "lang_name": "Stage 1-3", "goal_score_1": 2000, "goal_score_2": 4000, "goal_score_3": 6000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-3"},
                        {"mst_dungeon_id": 4, "mst_episode_id": 1, "play_order": 4, "lang_name": "Stage 1-4", "goal_score_1": 2500, "goal_score_2": 5000, "goal_score_3": 7500, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-4"},
                        {"mst_dungeon_id": 5, "mst_episode_id": 1, "play_order": 5, "lang_name": "Stage 1-5", "goal_score_1": 3000, "goal_score_2": 6000, "goal_score_3": 9000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-5"},
                        {"mst_dungeon_id": 6, "mst_episode_id": 1, "play_order": 6, "lang_name": "Stage 1-6", "goal_score_1": 3500, "goal_score_2": 7000, "goal_score_3": 10500, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-6"},
                        {"mst_dungeon_id": 7, "mst_episode_id": 1, "play_order": 7, "lang_name": "Stage 1-7", "goal_score_1": 4000, "goal_score_2": 8000, "goal_score_3": 12000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-7"},
                        {"mst_dungeon_id": 8, "mst_episode_id": 1, "play_order": 8, "lang_name": "Stage 1-8", "goal_score_1": 4500, "goal_score_2": 9000, "goal_score_3": 13500, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-8"},
                        {"mst_dungeon_id": 9, "mst_episode_id": 1, "play_order": 9, "lang_name": "Stage 1-9", "goal_score_1": 5000, "goal_score_2": 10000, "goal_score_3": 15000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-9"},
                        {"mst_dungeon_id": 10, "mst_episode_id": 1, "play_order": 10, "lang_name": "Stage 1-10", "goal_score_1": 6000, "goal_score_2": 12000, "goal_score_3": 18000, "bonus_coin_rate": 100, "unlock_gold": 0, "unlock_friend_point": 0, "lang_description": "Stage 1-10"},
                    ],
                    "weekly_reward": [],
                }

            if endpoint == "master_data/get_item_master":
                return {
                    "header": h,
                    "pet_list": [
                        {"mst_pet_id": 1, "pet_code": "pet_01", "kind": 1, "rarity": 2, "lang_name": "Chackn", "enable_use_count": 5, "image_file": "pet_01", "lang_description": "Collects coins", "gold_sale_price": 0, "coin_sale_price": 500, "fpoint_sale_price": 0, "event_sale_price": 0, "support_sale_price": 0, "collect_power": 10, "generate_item_table_id": 1, "lang_skill_description": "Coin magnet"},
                    ],
                    "shop_gacha_list": [],
                    "item_list": [
                        {"mst_item_id": 1, "item_code": "item_bspeed", "lang_name": "Bubble Speed", "image_file": "item_01", "type": 2, "kind": 1, "value": 10, "client_item_id": 1, "lang_description": "Faster bubbles"},
                        {"mst_item_id": 2, "item_code": "item_rapid", "lang_name": "Rapid Fire", "image_file": "item_02", "type": 2, "kind": 2, "value": 10, "client_item_id": 2, "lang_description": "Shoot faster"},
                        {"mst_item_id": 3, "item_code": "item_range", "lang_name": "Bubble Range", "image_file": "item_03", "type": 2, "kind": 3, "value": 10, "client_item_id": 3, "lang_description": "Longer bubble range"},
                        {"mst_item_id": 4, "item_code": "item_pspeed", "lang_name": "Move Speed", "image_file": "item_04", "type": 2, "kind": 4, "value": 10, "client_item_id": 4, "lang_description": "Move faster"},
                        {"mst_item_id": 5, "item_code": "item_time", "lang_name": "Extend Time", "image_file": "item_05", "type": 2, "kind": 5, "value": 30, "client_item_id": 5, "lang_description": "+30s stage timer"},
                        {"mst_item_id": 6, "item_code": "item_magnet", "lang_name": "Auto Collect", "image_file": "item_06", "type": 2, "kind": 6, "value": 1, "client_item_id": 6, "lang_description": "Auto-collect items"},
                        {"mst_item_id": 7, "item_code": "item_ap", "lang_name": "Attack Up", "image_file": "item_07", "type": 2, "kind": 7, "value": 20, "client_item_id": 7, "lang_description": "Higher attack power"},
                        {"mst_item_id": 8, "item_code": "item_bosshp", "lang_name": "Boss HP Down", "image_file": "item_08", "type": 2, "kind": 8, "value": 20, "client_item_id": 8, "lang_description": "Reduce boss HP"},
                        {"mst_item_id": 9, "item_code": "item_life", "lang_name": "Extra Life +1", "image_file": "item_09", "type": 2, "kind": 9, "value": 1, "client_item_id": 9, "lang_description": "Start stage with +1 life"},
                    ],
                    "shop_item_list": [
                        {"mst_shop_item_id": 1, "type": 2, "kind": 1, "mst_id": 1, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Bubble Speed", "lang_description": "Faster bubbles", "image_file": "item_01"},
                        {"mst_shop_item_id": 2, "type": 2, "kind": 1, "mst_id": 2, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Rapid Fire", "lang_description": "Shoot faster", "image_file": "item_02"},
                        {"mst_shop_item_id": 3, "type": 2, "kind": 1, "mst_id": 3, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Bubble Range", "lang_description": "Longer bubble range", "image_file": "item_03"},
                        {"mst_shop_item_id": 4, "type": 2, "kind": 1, "mst_id": 4, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Move Speed", "lang_description": "Move faster", "image_file": "item_04"},
                        {"mst_shop_item_id": 5, "type": 2, "kind": 1, "mst_id": 5, "num": 1, "gold": 0, "coin": 800, "is_sale": 1, "lang_name": "Extend Time", "lang_description": "+30s stage timer", "image_file": "item_05"},
                        {"mst_shop_item_id": 6, "type": 2, "kind": 1, "mst_id": 6, "num": 1, "gold": 0, "coin": 1000, "is_sale": 1, "lang_name": "Auto Collect", "lang_description": "Auto-collect items", "image_file": "item_06"},
                        {"mst_shop_item_id": 7, "type": 2, "kind": 1, "mst_id": 7, "num": 1, "gold": 0, "coin": 800, "is_sale": 1, "lang_name": "Attack Up", "lang_description": "Higher attack power", "image_file": "item_07"},
                        {"mst_shop_item_id": 8, "type": 2, "kind": 1, "mst_id": 8, "num": 1, "gold": 0, "coin": 1000, "is_sale": 1, "lang_name": "Boss HP Down", "lang_description": "Reduce boss HP", "image_file": "item_08"},
                        {"mst_shop_item_id": 9, "type": 2, "kind": 1, "mst_id": 9, "num": 1, "gold": 0, "coin": 1200, "is_sale": 1, "lang_name": "Extra Life +1", "lang_description": "Start stage with +1 life", "image_file": "item_09"},
                    ],
                    "shop_item_discount_list": [],
                    "shop_set_list": [],
                    "shop_set_item_list": [],
                    "shop_currency_list": [],
                    "shop_currency_discount_list": [],
                    "character_list": [
                        {"mst_character_id": 1, "lang_name": "Bubblun", "grade": 1, "level_max": 10, "price_gold": 0, "price_coin": 0, "price_fpoint": 0, "sale_price_gold": 0, "sale_price_coin": 1000, "sale_price_fpoint": 0, "mst_cash_product_id": 0, "upgrade_gold_base": 100, "upgrade_gold_multiply": 1.1, "upgrade_gold_limit": 1000, "upgrade_stat_base": 10, "upgrade_stat_increase": 2, "lang_desc": "Classic Bubblun", "is_production": 1},
                    ],
                }

            if endpoint == "master_data/get_file_master":
                return {
                    "header": h,
                    "file_list": [
                        {"mst_file_id": 1, "file": "ep_map_01", "ext": "png", "version": 3, "type": "image"},
                        {"mst_file_id": 2, "file": "ep_bg_01", "ext": "png", "version": 3, "type": "image"},
                        {"mst_file_id": 3, "file": "ep_end", "ext": "png", "version": 3, "type": "image"},
                        {"mst_file_id": 4, "file": "mp_0021_0", "ext": "png", "version": 3, "type": "image"},
                    ],
                }

            if endpoint == "master_data/get_boss_master":
                return {"header": h, "boss_dungeon_list": [], "boss_reward_list": [], "boss_event_reward_list": []}

            if endpoint == "master_data/get_gacha_coupon_master":
                return {"header": h, "gacha_coupon_list": [], "gacha_coupon_item_list": []}

            if endpoint == "user_login/login":
                return {
                    "header": h,
                    "user": self.user_obj(),
                    "possess_pets": self.user_pets,
                    "possess_items": self.user_items,
                    "progress_episode": self.progress_episode,
                    "progress_dungeon": self.progress_dungeon,
                    "possess_characters": self.user_characters,
                    "new_viewer_id": self.viewer_id,
                    "is_need_regist": False,
                }

            if endpoint in ("user/regist", "user/regist_guest"):
                return {
                    "header": h,
                    "user": self.user_obj(),
                    "platform_uid": str(params.get("platform_uid", "guest_100001")),
                }

            if endpoint == "user/guest_account_check":
                return {"header": h, "guest_account_status": 0}

            if endpoint == "user/guest_data_check":
                return {"header": h, "guest_data_status": 0}

            if endpoint == "user/guest_data_transfer":
                return {"header": h, "transfer_ok": True}

            if endpoint == "user/update_game_tutorial":
                self.game_tutorial_status = int(params.get("game_tutorial_status", -1))
                return {"header": h, "detail_param": self.user_obj()["detail"]}

            if endpoint == "character/get_list":
                return {
                    "header": h,
                    "character_list": [
                        {"mst_character_id": 1, "lang_name": "Bubblun", "grade": 1, "level_max": 10, "price_gold": 0, "price_coin": 0, "price_fpoint": 0, "sale_price_gold": 0, "sale_price_coin": 1000, "sale_price_fpoint": 0, "mst_cash_product_id": 0, "upgrade_gold_base": 100, "upgrade_gold_multiply": 1.1, "upgrade_gold_limit": 1000, "upgrade_stat_base": 10, "upgrade_stat_increase": 2, "lang_desc": "Classic Bubblun", "is_production": 1},
                    ],
                    "cash_character_list": [],
                    "character_grade_list": [
                        {"mst_character_grade_id": 1, "lang_name": "C", "max_level": 10, "max_life": 3, "max_enchant": 5, "evolution_coin": 5000, "evolution_rate": 100},
                    ],
                    "character_level_list": [
                        {"mst_character_level_id": i, "exp": i * 100} for i in range(1, 11)
                    ],
                    "character_enchant_list": [
                        {"mst_character_enchant_id": i, "mst_character_grade_id": 1, "enchant_level": i, "enchant_coin": i * 500} for i in range(1, 6)
                    ],
                    "character_v2_list": [
                        {"mst_character_v2_id": 1, "lang_name": "Bubblun", "mst_character_id": 1, "mst_character_grade_id": 1, "base_ap": 10, "critical_rate": 5, "critical_damage_rate": 150, "prefer_food": 1, "sale_price_coin": 1000},
                    ],
                }

            if endpoint == "mission/achivement_get":
                return {"header": h, "mst_achivement": [], "user_achivement": []}

            if endpoint == "mission/book_get":
                return {
                    "header": h,
                    "mst_book": [],
                    "mst_book_mission": [],
                    "user_progress_mst_book_id": 0,
                    "user_book_rewarded": False,
                    "user_book_mission": [],
                }

            if endpoint == "mission/daily_get":
                return {"header": h, "mst_daily_mission": [], "user_daily_mission": []}

            if endpoint == "collabo_pb/get":
                return {
                    "header": h,
                    "mission_list": [],
                    "android_package_name_list": [],
                    "ios_url_scheme": "",
                    "download_url": "",
                }

            if endpoint == "boss/get_boss_dungeon_progress":
                return {
                    "header": h,
                    "boss_dungeon_progress_list": [],
                    "boss_event": {"platform_uid": self.viewer_id, "rank_point": 0, "mst_character_id": 1, "mst_character_grade_id": 1, "character_level": 1},
                    "boss_param": {"boss_clear_ticket": 3, "boss_clear_ticket_update_time": now},
                }

            if endpoint == "top/update_information":
                return {
                    "header": h,
                    "is_change_day": False,
                    "attendance_reward_list": [],
                    "attendance_login_total": 1,
                }

            if endpoint == "gacha/get_shop_gacha_info":
                return {
                    "header": h,
                    "mst_shop_gacha_list": [
                        {"mst_shop_gacha_id": 1, "use_gold": 0, "use_coin": 1000, "use_friend_point": 0, "use_gold_sale": 0, "use_coin_sale": 0, "use_friend_point_sale": 0, "get_gacha_type": 1, "get_gacha_kind": 2, "get_gacha_num": 1, "start_date": "2020-01-01 00:00:00", "end_date": "2099-12-31 23:59:59", "image_file": "", "free_gacha_term": 86400, "free_gacha_daily_limit": 1},
                    ],
                    "user_free_gacha_progress_list": [],
                }

            if endpoint == "cash_product/get_package_info":
                return {"header": h, "package_list": [], "package_content_list": [], "cash_product_list": []}

            if endpoint == "message/get_new_count":
                return {"header": h, "new_count": 0}

            if endpoint == "message_heart/get_list":
                return {"header": h, "message_heart_list": []}

            if endpoint == "message/get_message_list":
                return {"header": h, "message_list": []}

            if endpoint == "gacha/get_coupon_list":
                return {"header": h, "gacha_coupon_list": []}

            if endpoint == "coin/get_shop_item_info":
                return {
                    "header": h,
                    "shop_item_list": [
                        {"mst_shop_item_id": 1, "type": 2, "kind": 1, "mst_id": 1, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Bubble Speed", "lang_description": "Faster bubbles", "image_file": "item_01"},
                        {"mst_shop_item_id": 2, "type": 2, "kind": 1, "mst_id": 2, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Rapid Fire", "lang_description": "Shoot faster", "image_file": "item_02"},
                        {"mst_shop_item_id": 3, "type": 2, "kind": 1, "mst_id": 3, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Bubble Range", "lang_description": "Longer bubble range", "image_file": "item_03"},
                        {"mst_shop_item_id": 4, "type": 2, "kind": 1, "mst_id": 4, "num": 1, "gold": 0, "coin": 500, "is_sale": 1, "lang_name": "Move Speed", "lang_description": "Move faster", "image_file": "item_04"},
                        {"mst_shop_item_id": 5, "type": 2, "kind": 1, "mst_id": 5, "num": 1, "gold": 0, "coin": 800, "is_sale": 1, "lang_name": "Extend Time", "lang_description": "+30s stage timer", "image_file": "item_05"},
                        {"mst_shop_item_id": 6, "type": 2, "kind": 1, "mst_id": 6, "num": 1, "gold": 0, "coin": 1000, "is_sale": 1, "lang_name": "Auto Collect", "lang_description": "Auto-collect items", "image_file": "item_06"},
                        {"mst_shop_item_id": 7, "type": 2, "kind": 1, "mst_id": 7, "num": 1, "gold": 0, "coin": 800, "is_sale": 1, "lang_name": "Attack Up", "lang_description": "Higher attack power", "image_file": "item_07"},
                        {"mst_shop_item_id": 8, "type": 2, "kind": 1, "mst_id": 8, "num": 1, "gold": 0, "coin": 1000, "is_sale": 1, "lang_name": "Boss HP Down", "lang_description": "Reduce boss HP", "image_file": "item_08"},
                        {"mst_shop_item_id": 9, "type": 2, "kind": 1, "mst_id": 9, "num": 1, "gold": 0, "coin": 1200, "is_sale": 1, "lang_name": "Extra Life +1", "lang_description": "Start stage with +1 life", "image_file": "item_09"},
                    ],
                    "shop_item_discount_list": [],
                    "shop_set_list": [],
                    "shop_set_item_list": [],
                }

            if endpoint == "coin/get_shop_coin_info":
                return {
                    "header": h,
                    "shop_coin_list": [
                        {"mst_shop_currency_id": 1, "use_gold": 10, "get_coin": 10000, "sale_percent": 0, "description": "10,000 Coins"},
                        {"mst_shop_currency_id": 2, "use_gold": 30, "get_coin": 35000, "sale_percent": 15, "description": "35,000 Coins"},
                        {"mst_shop_currency_id": 3, "use_gold": 50, "get_coin": 65000, "sale_percent": 25, "description": "65,000 Coins"},
                        {"mst_shop_currency_id": 4, "use_gold": 100, "get_coin": 150000, "sale_percent": 35, "description": "150,000 Coins"},
                    ],
                    "shop_coin_desc": "Exchange Diamonds for Coins",
                }

            if endpoint == "heart/get_shop_heart_info":
                return {
                    "header": h,
                    "shop_heart_list": [
                        {"mst_shop_currency_id": 1, "product_id": "heart_5", "use_cash": 0, "use_gold": 5, "get_heart": 5, "sale_percent": 0, "description": "5 Hearts"},
                        {"mst_shop_currency_id": 2, "product_id": "heart_15", "use_cash": 0, "use_gold": 12, "get_heart": 15, "sale_percent": 20, "description": "15 Hearts"},
                        {"mst_shop_currency_id": 3, "product_id": "heart_50", "use_cash": 0, "use_gold": 35, "get_heart": 50, "sale_percent": 30, "description": "50 Hearts"},
                        {"mst_shop_currency_id": 4, "product_id": "heart_100", "use_cash": 0, "use_gold": 60, "get_heart": 100, "sale_percent": 40, "description": "100 Hearts"},
                    ],
                    "shop_heart_desc": "Refill Hearts",
                }

            if endpoint == "charge/get_shop_gold_info":
                return {
                    "header": h,
                    "shop_gold_list": [
                        {"mst_shop_currency_id": 1, "product_id": "gold_100", "use_cash": 1000, "get_gold": 100, "sale_percent": 0, "description": "100 Diamonds"},
                    ],
                    "shop_gold_desc": "Diamond Shop",
                }

            if endpoint == "friend/get_user_dungeon_score":
                return {"header": h, "dungeon_score_list": []}

            if endpoint == "friend/get_user_dungeon_progress":
                return {"header": h, "dungeon_progress_list": []}

            if endpoint == "friend/get_user_heart":
                return {"header": h, "send_heart_list": []}

            if endpoint == "game/continue_start":
                self.gold = max(0, self.gold - 3)
                return {"header": h, "ret_code": 0, "user_continue_ticket_id": 0, "gold": self.gold}

            if endpoint == "game/continue_end":
                return {"header": h}

            if endpoint == "game/report_over":
                return {"header": h, "ret_code": 0}

            if endpoint == "friend/get_message_block_info":
                return {"header": h, "message_block_info_list": []}

            if endpoint == "game/start":
                self.heart = max(0, self.heart - 1)
                return {
                    "header": h,
                    "after_heart": {
                        "heart": self.heart,
                        "heart_max": self.heart_max,
                        "heart_update_date": now,
                        "recovery_time": 1,
                        "life_free_ticket_end_time": "2000-01-01 00:00:00",
                    },
                    "user_item_list": self.user_items,
                }

            if endpoint == "game/dungeon_clear":
                dungeon_id = int(params.get("mst_dungeon_id", 1))
                score = int(params.get("score", 1000))
                self.coin += 500
                self.exp += 20
                for d in self.progress_dungeon:
                    if d["mst_dungeon_id"] == dungeon_id:
                        d["is_clear"] = 1
                        d["best_score"] = max(d["best_score"], score)
                        d["clear_rank"] = 3
                    elif d["mst_dungeon_id"] == dungeon_id + 1:
                        d["is_enable_play"] = 1
                return {
                    "header": h,
                    "progress_episode": self.progress_episode[0],
                    "progress_dungeon": self.progress_dungeon,
                    "after_user_coin": self.coin,
                    "reward_coin": 500,
                    "score_multiplied": score,
                    "score_life": 0,
                    "re_challenge_flag": False,
                    "detail_param": self.user_obj()["detail"],
                    "after_user_heart": {
                        "heart": self.heart,
                        "heart_max": self.heart_max,
                        "heart_update_date": now,
                        "recovery_time": 1,
                        "life_free_ticket_end_time": "2000-01-01 00:00:00",
                    },
                    "level_param": {"level": self.level, "exp": self.exp, "exp_max": self.exp_max, "score_multiply": 1.0},
                    "user_level_up_count": 0,
                    "new_mst_boss_dungeon_id": 0,
                    "after_user_character": self.user_characters[0],
                    "after_user_gold": self.gold,
                    "user_max_heart_add_count": 0,
                    "user_level_up_bonus_heart_count": 0,
                    "user_level_up_reward_gold": 0,
                    "character_level_up_count": 0,
                }

            if endpoint == "character/level_up_price":
                return {
                    "header": h,
                    "price_coin_level_up_1": 500,
                    "price_coin_level_up_max": 5000,
                    "price_gold_level_up_max": 10,
                    "gold_sale_percent": 0,
                }

            
            if endpoint == "gacha/exec_pet_gacha_free":
                return {
                    "header": h,
                    "user_free_gacha_progress": {
                        "user_free_gacha_progress_id": 1,
                        "user_id": self.user_id,
                        "mst_shop_gacha_id": int(params.get("mst_shop_gacha_id", 1)),
                        "free_gacha_count": 1,
                        "create_date": now,
                        "update_date": now,
                    },
                    "user_pet": self.user_pets[0],
                    "sale_coin": 0,
                    "is_get_new": True,
                    "after_user_currency": {"gold": self.gold, "friend_point": self.friend_point, "coin": self.coin},
                }

            if endpoint == "gacha/exec_pet_gacha":
                self.coin = max(0, self.coin - 1000)
                return {
                    "header": h,
                    "user_pet": self.user_pets[0],
                    "sale_coin": 0,
                    "is_get_new": False,
                    "after_user_currency": {"gold": self.gold, "friend_point": self.friend_point, "coin": self.coin},
                }

            if endpoint == "gacha/exec_character_gacha_free":
                return {
                    "header": h,
                    "user_free_gacha_progress": {
                        "user_free_gacha_progress_id": 2,
                        "user_id": self.user_id,
                        "mst_shop_gacha_id": int(params.get("mst_shop_gacha_id", 1)),
                        "free_gacha_count": 1,
                        "create_date": now,
                        "update_date": now,
                    },
                    "new_character_list": [],
                    "character_book": "1",
                }

            if endpoint == "gacha/exec_character_gacha":
                self.gold = max(0, self.gold - 10)
                return {
                    "header": h,
                    "after_user_currency": {"gold": self.gold, "friend_point": self.friend_point, "coin": self.coin},
                    "new_character_list": [],
                    "character_book": "1",
                }

            if endpoint == "gacha/exec_item_gacha":
                return {"header": h, "item": {"id": 1, "master_id": 1, "number": 1}}

            if endpoint == "coin/buy_item":
                item_id = int(params.get("mst_shop_item_id", 1))
                self.coin = max(0, self.coin - 500)
                for it in self.user_items:
                    if it["mst_item_id"] == item_id:
                        it["item_num"] += 1
                        break
                return {"header": h, "coin": self.coin, "user_item_list": self.user_items, "gold": self.gold}

            if endpoint == "coin/exchange_gold":
                self.gold = max(0, self.gold - 10)
                self.coin += 10000
                return {"header": h, "coin": self.coin, "gold": self.gold}

            if endpoint == "heart/exchange_gold":
                cid = int(params.get("mst_shop_currency_id", 1))
                packs = {1: (5, 5), 2: (12, 15), 3: (35, 50), 4: (60, 100)}
                cost, gain = packs.get(cid, (5, 5))
                self.gold = max(0, self.gold - cost)
                self.heart += gain
                return {
                    "header": h,
                    "user_param_heart": {
                        "heart": self.heart,
                        "heart_max": self.heart_max,
                        "heart_update_date": now,
                        "recovery_time": 1,
                        "life_free_ticket_end_time": "2000-01-01 00:00:00",
                    },
                    "gold": self.gold,
                }

            if endpoint == "character/level_up_by_currency":
                self.coin = max(0, self.coin - 500)
                self.user_characters[0]["level"] += 1
                return {
                    "header": h,
                    "after_user_character": self.user_characters[0],
                    "after_user_currency": {"gold": self.gold, "friend_point": self.friend_point, "coin": self.coin},
                }

            if endpoint == "game/game_over":
                return {
                    "header": h,
                    "after_user_coin": self.coin,
                    "reward_coin": 0,
                    "score_multiplied": int(params.get("score", 0)),
                }

            # Fallback for any other endpoint
            return {"header": h}


# ---------------------------------------------------------------------------
# 5. HTTP Request Handler
# ---------------------------------------------------------------------------

def make_handler(state: GameServerState):
    class BBFKHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} - {fmt % args}")

        def _send_bytes(self, code: int, content_type: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/resource/"):
                filename = path.rsplit("/", 1)[-1]
                if filename in state.episode_bins:
                    self._send_bytes(200, "application/octet-stream", state.episode_bins[filename])
                    return
                self._send_bytes(404, "text/plain", b"Resource not found")
                return

            if path.startswith("/view/a/policy_"):
                html = "<html><body><h3>Bubble Bobble for Kakao - Local Server</h3><p>Offline preservation mode.</p></body></html>"
                self._send_bytes(200, "text/html; charset=utf-8", html.encode("utf-8"))
                return

            self._send_bytes(200, "text/plain", b"BBFK Fake Server Running")

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length > 0 else b""
            form = urllib.parse.parse_qs(raw_body.decode("utf-8", errors="replace"))

            params = {}
            if "param" in form and form["param"]:
                try:
                    params = decode_bin_param(form["param"][0])
                except Exception as exc:
                    print(f"  [!] Failed to decode param: {exc}")
            else:
                params = {k: v[0] for k, v in form.items()}

            endpoint = path
            if "/index.php/" in endpoint:
                endpoint = endpoint.split("/index.php/", 1)[1]
            endpoint = endpoint.lstrip("/")

            print(f"  -> API {endpoint} | params={list(params.keys())}")
            resp_dict = state.handle_api(endpoint, params)
            resp_json = encode_bin_response(resp_dict).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", resp_json)

    return BBFKHandler


def main():
    parser = argparse.ArgumentParser(description="Bubble Bobble for Kakao Fake Custom Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--public-host", default=None, help="Public URL base for resources_host (e.g. http://192.168.1.10:8080)")
    args = parser.parse_args()

    public_url = args.public_host or f"http://127.0.0.1:{args.port}"
    state = GameServerState(public_url)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(f"BBFK Fake Server listening on http://{args.host}:{args.port} (resources_host={public_url}/resource/)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()