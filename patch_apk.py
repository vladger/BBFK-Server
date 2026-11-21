#!/usr/bin/env python3
"""
Bubble Bobble for Kakao (BBFK) - Automatic APK / Assembly-CSharp.dll Patcher
----------------------------------------------------------------------------
Zero-dependency Python 3 tool that patches an original (or previously modified)
BBFK APK or standalone Assembly-CSharp.dll to connect to your custom server.

What it patches in assets/bin/Data/Managed/Assembly-CSharp.dll:
  1. Relocates #US (User Strings) into a new .us PE section so any IP:port
     or hostname length works without overflowing existing string slots.
  2. Global.SysDef.URL..cctor -> sets APP_HOST_DATA & APP_HOST to http://<ip:port>/...
  3. Global.SysDef.GetAndroid_GuestMode() -> returns true (bypasses KakaoTalk login).
  4. Global.SysDef.isUseLocalResouce() -> returns false (downloads .bin & .png from server).
  5. Game.EndStateLoad() -> passes isSpine: false to Player.Create(...).
  6. Game.getBubblenTextureName() -> returns "root/game/enemy/zenchan" (bundled fallback).
  7. Game.getBubbleTextureName() -> maps "root/game/bubble0" to "root/game/bubble1".

Usage:
  python3 patch_apk.py BBFK.apk 192.168.0.71:8080 -o BBFK_patched.apk
  python3 patch_apk.py Assembly-CSharp.dll 192.168.0.71:8080 -o Assembly-CSharp_patched.dll
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import zipfile


def align_up(val: int, align: int) -> int:
    return ((val + align - 1) // align) * align


def encode_us_entry(text: str) -> bytes:
    """Encodes a .NET #US heap entry: compressed length + UTF-16LE + 0x00/0x01 terminal byte."""
    raw = text.encode("utf-16-le")
    has_high = any(b > 0x7F for b in raw)
    payload = raw + (b"\x01" if has_high else b"\x00")
    n = len(payload)
    if n < 0x80:
        hdr = bytes([n])
    elif n < 0x4000:
        hdr = struct.pack(">H", 0x8000 | n)
    else:
        hdr = struct.pack(">I", 0xC0000000 | n)
    return hdr + payload


def read_us_string(buf: bytes, us_off: int, token: int) -> str:
    off = us_off + (token & 0x00FFFFFF)
    b0 = buf[off]
    if (b0 & 0x80) == 0:
        l = b0
        p0 = off + 1
    elif (b0 & 0xC0) == 0x80:
        l = ((b0 & 0x3F) << 8) | buf[off + 1]
        p0 = off + 2
    else:
        l = ((b0 & 0x1F) << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]
        p0 = off + 4
    if l <= 1:
        return ""
    return buf[p0 : p0 + l - 1].decode("utf-16-le", "replace")


def parse_pe_and_metadata(data: bytes):
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Not a valid PE file")

    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_sz = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_align = struct.unpack_from("<I", data, pe_off + 56)[0]
    file_align = struct.unpack_from("<I", data, pe_off + 60)[0]
    sec_off = pe_off + 24 + opt_sz

    sections = []
    for i in range(num_sec):
        s = sec_off + i * 40
        name = data[s : s + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((name, vsize, vaddr, rsize, raddr))

    def rva_to_off(rva: int) -> int:
        for _, vsize, vaddr, rsize, raddr in sections:
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                return rva - vaddr + raddr
        raise ValueError(f"RVA 0x{rva:x} not in any section")

    def off_to_rva(off: int) -> int:
        for _, vsize, vaddr, rsize, raddr in sections:
            if raddr <= off < raddr + rsize:
                return off - raddr + vaddr
        raise ValueError(f"File offset 0x{off:x} not in any section")

    bsjb_off = data.find(b"BSJB")
    if bsjb_off == -1:
        raise ValueError("CLI BSJB metadata header not found")
    bsjb_rva = off_to_rva(bsjb_off)

    ver_len = struct.unpack_from("<I", data, bsjb_off + 12)[0]
    pos = bsjb_off + 16 + ver_len
    _, num_streams = struct.unpack_from("<HH", data, pos)
    pos += 4
    streams = {}
    for _ in range(num_streams):
        hdr_pos = pos
        off, size = struct.unpack_from("<II", data, pos)
        pos += 8
        nb = b""
        while data[pos] != 0:
            nb += bytes([data[pos]])
            pos += 1
        pos += 1
        while pos % 4 != 0:
            pos += 1
        streams[nb.decode()] = (off, size, hdr_pos)

    str_off = rva_to_off(bsjb_rva + streams["#Strings"][0])
    tilde_off = rva_to_off(bsjb_rva + streams["#~"][0])
    us_off = rva_to_off(bsjb_rva + streams["#US"][0])
    us_size = streams["#US"][1]

    def get_str(idx: int) -> str:
        if idx == 0:
            return ""
        return data[str_off + idx : data.index(0, str_off + idx)].decode("utf-8", "replace")

    heap_sizes = data[tilde_off + 6]
    valid_mask = struct.unpack_from("<Q", data, tilde_off + 8)[0]
    p = tilde_off + 24
    row_counts = {}
    for t in range(64):
        if valid_mask & (1 << t):
            row_counts[t] = struct.unpack_from("<I", data, p)[0]
            p += 4

    str_sz = 4 if (heap_sizes & 1) else 2
    guid_sz = 4 if (heap_sizes & 2) else 2
    blob_sz = 4 if (heap_sizes & 4) else 2

    def tbl_sz(t: int) -> int:
        return 4 if row_counts.get(t, 0) > 65535 else 2

    def coded_sz(tbls, bits: int) -> int:
        mx = max((row_counts.get(t, 0) for t in tbls), default=0)
        return 4 if mx >= (1 << (16 - bits)) else 2

    def read_u(sz: int) -> int:
        nonlocal p
        v = struct.unpack_from("<I" if sz == 4 else "<H", data, p)[0]
        p += sz
        return v

    for _ in range(row_counts.get(0x00, 0)):
        p += 2 + str_sz + guid_sz * 3
    tref_sz = coded_sz([0x00, 0x1A, 0x23, 0x01], 2)
    for _ in range(row_counts.get(0x01, 0)):
        p += tref_sz + str_sz * 2

    tdef_ext_sz = coded_sz([0x02, 0x01, 0x1B], 2)
    typedefs = []
    for _ in range(row_counts.get(0x02, 0)):
        _, nidx, nsidx = read_u(4), read_u(str_sz), read_u(str_sz)
        read_u(tdef_ext_sz)
        read_u(tbl_sz(0x04))
        mlist = read_u(tbl_sz(0x06))
        typedefs.append((get_str(nsidx), get_str(nidx), mlist))

    for _ in range(row_counts.get(0x04, 0)):
        p += 2 + str_sz + blob_sz

    methods = []
    for _ in range(row_counts.get(0x06, 0)):
        rva = read_u(4)
        read_u(2)
        read_u(2)
        nidx = read_u(str_sz)
        read_u(blob_sz)
        read_u(tbl_sz(0x08))
        methods.append((rva, get_str(nidx)))

    return {
        "pe_off": pe_off,
        "sec_off": sec_off,
        "sec_align": sec_align,
        "file_align": file_align,
        "sections": sections,
        "rva_to_off": rva_to_off,
        "bsjb_rva": bsjb_rva,
        "streams": streams,
        "us_off": us_off,
        "us_size": us_size,
        "typedefs": typedefs,
        "methods": methods,
    }


def get_method_code_slice(data: bytes, rva_to_off, rva: int):
    foff = rva_to_off(rva)
    b0 = data[foff]
    if (b0 & 3) == 2:
        codesz = b0 >> 2
        code_off = foff + 1
    else:
        hdr_sz = (data[foff + 1] >> 4) * 4
        codesz = struct.unpack_from("<I", data, foff + 4)[0]
        code_off = foff + hdr_sz
    return code_off, codesz


def patch_assembly_csharp(dll_bytes: bytes, server_host_port: str) -> bytes:
    host_port = server_host_port.strip().removeprefix("http://").removeprefix("https://").rstrip("/")
    base_url = f"http://{host_port}"
    meta = parse_pe_and_metadata(dll_bytes)

    # Relocate #US into a new .us PE section so we can append strings of any length
    us_buf = bytearray(dll_bytes[meta["us_off"] : meta["us_off"] + meta["us_size"]])
    new_tokens = {}

    def add_us(text: str) -> int:
        if text in new_tokens:
            return new_tokens[text]
        rel = len(us_buf)
        us_buf.extend(encode_us_entry(text))
        tok = 0x70000000 | rel
        new_tokens[text] = tok
        return tok

    tok_host_data = add_us(f"{base_url}/resource/")
    tok_host_api = add_us(f"{base_url}/index.php/")
    tok_host_root = add_us(f"{base_url}/")
    tok_zenchan = add_us("root/game/enemy/zenchan")
    tok_bubble1 = add_us("root/game/bubble1")

    # Ensure 4-byte padding for section
    while len(us_buf) % 4 != 0:
        us_buf.append(0)

    out = bytearray(dll_bytes)
    pe_off = meta["pe_off"]
    sec_off = meta["sec_off"]
    num_sec = len(meta["sections"])
    last_name, last_vsize, last_va, last_rsize, last_ra = meta["sections"][-1]

    # If already patched once with .us as last section, reuse its slot; else append new section
    if last_name == ".us":
        new_va = last_va
        new_ra = last_ra
        out = out[:new_ra]
        sec_idx = num_sec - 1
    else:
        new_va = align_up(last_va + max(last_vsize, last_rsize), meta["sec_align"])
        new_ra = align_up(len(out), meta["file_align"])
        while len(out) < new_ra:
            out.append(0)
        sec_idx = num_sec
        struct.pack_into("<H", out, pe_off + 6, num_sec + 1)

    new_vsize = len(us_buf)
    new_rsize = align_up(new_vsize, meta["file_align"])
    padded_us = bytes(us_buf) + (b"\x00" * (new_rsize - new_vsize))
    out.extend(padded_us)

    # Write .us section header
    hdr = sec_off + sec_idx * 40
    out[hdr : hdr + 8] = b".us\x00\x00\x00\x00\x00"
    struct.pack_into("<IIII", out, hdr + 8, new_vsize, new_va, new_rsize, new_ra)
    struct.pack_into("<IIHH", out, hdr + 24, 0, 0, 0, 0)
    struct.pack_into("<I", out, hdr + 36, 0x40000040)  # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

    # Update SizeOfImage
    new_img_size = align_up(new_va + new_vsize, meta["sec_align"])
    struct.pack_into("<I", out, pe_off + 80, new_img_size)

    # Update #US stream offset (relative to BSJB RVA) and size
    _, _, us_hdr_pos = meta["streams"]["#US"]
    new_us_rel = new_va - meta["bsjb_rva"]
    struct.pack_into("<II", out, us_hdr_pos, new_us_rel, len(us_buf))

    # Helper to find methods by TypeDef name
    def find_methods(type_name: str, method_name: str):
        found = []
        tdefs = meta["typedefs"]
        methods = meta["methods"]
        for i, (_, tname, mstart) in enumerate(tdefs):
            if tname == type_name:
                mend = tdefs[i + 1][2] if i + 1 < len(tdefs) else len(methods) + 1
                for midx in range(mstart, mend):
                    rva, mname = methods[midx - 1]
                    if mname == method_name and rva != 0:
                        found.append(rva)
        return found

    # 1. Patch Global.SysDef.URL..cctor
    patched_urls = 0
    for rva in find_methods("URL", ".cctor"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        j = 0
        while j + 5 <= sz:
            if out[off + j] == 0x72:
                tok = struct.unpack_from("<I", out, off + j + 1)[0]
                if (tok >> 24) == 0x70:
                    s = read_us_string(dll_bytes, meta["us_off"], tok)
                    if s.startswith("http://") and "cafe.naver.com" not in s:
                        if s.endswith("/resource/"):
                            struct.pack_into("<I", out, off + j + 1, tok_host_data)
                            patched_urls += 1
                        elif s.endswith("/index.php/"):
                            struct.pack_into("<I", out, off + j + 1, tok_host_api)
                            patched_urls += 1
                        else:
                            struct.pack_into("<I", out, off + j + 1, tok_host_root)
                            patched_urls += 1
            j += 1
    if patched_urls == 0:
        raise RuntimeError("Could not locate URL..cctor HTTP strings to patch")

    # 2. Patch SysDef.GetAndroid_GuestMode -> return true (17 2a)
    for rva in find_methods("SysDef", "GetAndroid_GuestMode"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        assert sz >= 2
        out[off : off + sz] = b"\x17\x2a" + (b"\x00" * (sz - 2))

    # 3. Patch SysDef.isUseLocalResouce -> return false (16 2a)
    for rva in find_methods("SysDef", "isUseLocalResouce"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        assert sz >= 2
        out[off : off + sz] = b"\x16\x2a" + (b"\x00" * (sz - 2))

    # 4. Patch Game.EndStateLoad -> Player.Create(..., isSpine: false)
    for rva in find_methods("Game", "EndStateLoad"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        # Look for: ldc.i4.1 (0x17), ldnull (0x14), call (0x28)
        for j in range(sz - 7):
            if out[off + j] == 0x17 and out[off + j + 1] == 0x14 and out[off + j + 2] == 0x28:
                out[off + j] = 0x16
                break

    # 5. Patch Game.getBubblenTextureName -> return "root/game/enemy/zenchan"
    for rva in find_methods("Game", "getBubblenTextureName"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        assert sz >= 6
        out[off : off + sz] = b"\x72" + struct.pack("<I", tok_zenchan) + b"\x2a" + (b"\x00" * (sz - 6))

    # 6. Patch Game.getBubbleTextureName -> replace "root/game/bubble0" with "root/game/bubble1"
    for rva in find_methods("Game", "getBubbleTextureName"):
        off, sz = get_method_code_slice(dll_bytes, meta["rva_to_off"], rva)
        j = 0
        while j + 5 <= sz:
            if out[off + j] == 0x72:
                tok = struct.unpack_from("<I", out, off + j + 1)[0]
                if (tok >> 24) == 0x70 and read_us_string(dll_bytes, meta["us_off"], tok) == "root/game/bubble0":
                    struct.pack_into("<I", out, off + j + 1, tok_bubble1)
            j += 1

    return bytes(out)


def patch_apk(apk_in: str, apk_out: str, server_host_port: str):
    target_entry = "assets/bin/Data/Managed/Assembly-CSharp.dll"
    with zipfile.ZipFile(apk_in, "r") as zin:
        if target_entry not in zin.namelist():
            raise FileNotFoundError(f"{target_entry} not found inside {apk_in}")
        orig_dll = zin.read(target_entry)
        patched_dll = patch_assembly_csharp(orig_dll, server_host_port)

        tmp_apk = apk_out + ".unsigned.tmp"
        with zipfile.ZipFile(tmp_apk, "w") as zout:
            for info in zin.infolist():
                # Strip old JAR signature files (META-INF/*.SF, *.RSA, *.DSA, MANIFEST.MF)
                if info.filename.startswith("META-INF/") and info.filename.endswith((".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF")):
                    continue
                if info.filename == target_entry:
                    new_info = zipfile.ZipInfo(target_entry, date_time=info.date_time)
                    new_info.compress_type = info.compress_type
                    zout.writestr(new_info, patched_dll)
                else:
                    raw = zin.read(info.filename)
                    new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    new_info.compress_type = info.compress_type
                    zout.writestr(new_info, raw)

    # Try auto-signing if apksigner is on PATH
    apksigner = shutil.which("apksigner")
    if apksigner:
        print(f"Patched DLL written; signing with {apksigner} requires a keystore.")
    os.replace(tmp_apk, apk_out)
    print(f"Patched APK saved to: {apk_out}")
    print("Note: Sign the APK before installing on Android (e.g. with uber-apk-signer or apksigner),")
    print("and ensure AndroidManifest.xml has android:usesCleartextTraffic=\"true\" for Android 9+.")


def main():
    parser = argparse.ArgumentParser(description="Patch BBFK APK or Assembly-CSharp.dll with custom server IP:port")
    parser.add_argument("input", help="Path to input .apk or Assembly-CSharp.dll")
    parser.add_argument("server", help="Server ip:port (e.g. 192.168.0.71:8080)")
    parser.add_argument("-o", "--output", default=None, help="Output file path")
    args = parser.parse_args()

    if args.input.lower().endswith(".apk"):
        out_path = args.output or (os.path.splitext(args.input)[0] + "_patched.apk")
        patch_apk(args.input, out_path, args.server)
    else:
        out_path = args.output or (os.path.splitext(args.input)[0] + "_patched.dll")
        raw = open(args.input, "rb").read()
        patched = patch_assembly_csharp(raw, args.server)
        with open(out_path, "wb") as f:
            f.write(patched)
        print(f"Patched DLL saved to: {out_path}")


if __name__ == "__main__":
    main()