#!/usr/bin/env python3
# Copyright (C) 2026 Hans Kristian Rosbach
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
"""Tests for zanalyze.py parser and alignment logic.

Run:  python3 test_zanalyze.py [LIB]
LIB defaults to the develop build of zlib-ng.
"""

import io
import itertools
import os
import re
import struct
import subprocess
import sys
import types
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zanalyze as z

LIB = sys.argv[1] if len(sys.argv) > 1 else \
    "/home/opencode/opencode/zlib-ng/build-develop/libz-ng.so"
# Path to a representative input file for the cross-check; overridable in CI
# (where the local default does not exist) via ZANALYZE_TEST_DATA.
DATA = os.environ.get(
    "ZANALYZE_TEST_DATA",
    "/home/opencode/opencode/zlib-ng/test/data/lcet10.txt")

FAILURES = []


def check(name, cond, extra=""):
    """Record and print a single assertion; collect failures in FAILURES."""
    status = "ok" if cond else "FAIL"
    print(f"  [{status}] {name}{(' ' + extra) if extra and not cond else ''}")
    if not cond:
        FAILURES.append(name)


def test_bitreader():
    """BitReader reads LSB-first bits, across byte boundaries and multi-byte."""
    print("BitReader")
    # 0xE3 -> bits (LSB first): 1,1,0,0,0,1,1,1
    br = z.BitReader(b"\xe3")
    check("read 1", br.read(1) == 1)
    check("read 2", br.read(2) == 1)
    check("read 3", br.read(3) == 4)
    check("read 2 tail", br.read(2) == 3)
    # 0x01: 1,0,0,0,0,0,0,0 ; 0x02: 0,1,0,0,0,0,0,0
    br2 = z.BitReader(b"\x01\x02")
    check("unaligned 3", br2.read(3) == 1)
    check("unaligned 13", br2.read(13) == 64)
    br3 = z.BitReader(b"\xab\xcd")
    check("16-bit", br3.read(16) == 0xcdab)


class _FakeTTY:
    """A stderr stand-in reporting isatty()==True, recording what is written."""

    def __init__(self):
        """Initialize with an empty written-records list."""
        self.written = []

    def write(self, s):
        """Record a write instead of emitting it."""
        self.written.append(s)

    def flush(self):
        """Do nothing (there is no underlying stream)."""

    def isatty(self):
        """Always report as a TTY so the bar enables."""
        return True

    def getvalue(self):
        """Return everything written so far as a single string."""
        return "".join(self.written)


def test_progress():
    """Progress renders a TTY-gated, time-throttled stderr bar, and the parser
    reports decoded byte counts within bounds."""
    print("Progress")
    # pylint: disable=protected-access
    check("human 0", z._human_bytes(0) == "0")
    check("human 999", z._human_bytes(999) == "999")
    check("human 1M", z._human_bytes(1_000_000) == "1M")
    check("human 3G", z._human_bytes(3_000_000_000) == "3G")
    # rate: one decimal, auto unit (so 1.6M/s is not rounded to 2M/s)
    check("rate 980B", z._human_rate(980) == "980.0B")
    check("rate 65.3K", z._human_rate(65_300) == "65.3K")
    check("rate 1.6M", z._human_rate(1_600_000) == "1.6M")
    check("rate 0", z._human_rate(0) == "0.0B")
    # enabled TTY: update renders a bar with a rate, finish adds a rate summary
    fh = _FakeTTY()
    bar = z.Progress(1000, interval=0.0, fh=fh, enabled=True)
    bar.update(500)
    bar.finish()
    text = fh.getvalue()
    check("renders bar", "50%" in text and "[" in text and "]" in text)
    check("shows rate", "/s" in text)
    check("finish summary", "Decoding finished" in text)
    check("finish newline", text.endswith("\n"))
    # disabled: nothing is written
    fh2 = _FakeTTY()
    bar2 = z.Progress(1000, interval=0.0, fh=fh2, enabled=False)
    bar2.update(500)
    bar2.finish()
    check("disabled silent", fh2.getvalue() == "")
    # zero total is treated as disabled
    fh3 = _FakeTTY()
    bar3 = z.Progress(0, fh=fh3, enabled=True)
    bar3.update(0)
    bar3.finish()
    check("zero total silent", fh3.getvalue() == "")
    # throttle: a second rapid update within the interval is suppressed
    fh4 = _FakeTTY()
    bar4 = z.Progress(100, interval=1.0, fh=fh4, enabled=True)
    bar4.update(10)
    bar4.update(20)
    check("throttle suppresses rapid updates", len(fh4.written) == 1)
    # padding: a frame whose text is shorter than the previous one is padded so
    # the terminal line never leaves residue (e.g. 999/1K -> 1K/1K)
    fhp = _FakeTTY()
    bp = z.Progress(1000, interval=0.0, fh=fhp, enabled=True)
    bp.update(999)
    bp.update(1000)
    frames = [f for f in fhp.getvalue().split("\r") if f]
    check("shorter frame padded",
          len(frames) == 2 and len(frames[1]) >= len(frames[0]))
    # parser gate: on_progress fires with bounded, non-decreasing values
    buf = b"abcde" * 60000  # 300 KiB
    dfl, _w, _t = z.split_wrapper(zlib.compress(buf, 6), 15)
    calls: list[int] = []
    z.parse_deflate(dfl, buf, True, on_progress=calls.append)
    check("progress called", len(calls) >= 1)
    check("progress bounded", all(0 < c <= len(buf) for c in calls))
    check("progress non-decreasing",
          all(a <= b for a, b in itertools.pairwise(calls)))


def test_build_huffman_fixed():
    """build_huffman reproduces the known fixed lit/len and dist code assignments."""
    print("build_huffman(fixed)")
    t = z.build_huffman(z.FIXED_LITLEN)
    # symbol 0: 8-bit code 00110000b
    check("sym 0 code", t[8].get(0b00110000) == 0)
    # symbol 255: 9-bit 111111111b
    check("sym 255 code", t[9].get(0b111111111) == 255)
    # symbol 256: 7-bit 0000000b
    check("sym 256 code", t[7].get(0) == 256)
    # symbol 285: 8-bit code 11000101b (280-287 -> 11000000b+0..7)
    check("sym 285 code", t[8].get(0b11000101) == 285)
    dt = z.build_huffman(z.FIXED_DIST)
    check("dist 0 code", dt[5].get(0) == 0)
    check("dist 29 code", dt[5].get(0b11101) == 29)


def test_stored_block():
    """A stored (uncompressed) block parses back to its raw bytes."""
    print("stored block parse")
    data = b"hello world"
    ln = len(data)
    nln = (~ln) & 0xFFFF
    stream = bytes([1, ln & 0xFF, (ln >> 8) & 0xFF,
                    nln & 0xFF, (nln >> 8) & 0xFF]) + data
    blocks, events, _trees = z.parse_deflate(stream, data, verify=True)
    check("blocks", blocks == ["stored"], str(blocks))
    check("events", events == [["L", ln]], str(events))
    check("stored tree bytes",
          _trees == [{"type": "stored", "bytes": ln,
                      "ev_start": 0, "ev_end": 1}], str(_trees))


def test_crafted_match_stream():
    """A hand-built fixed block (3 literals + one len-3/dist-3 match) parses."""
    print("crafted stream with a match (fixed block)")
    # data = "abcabc": literals a b c, then match len=3 dist=3, then EOB.
    # fixed lit/len codes: symbols 0..143 get 8-bit codes 0x30+sym, so
    # 'a'(97)=0x91, 'b'(98)=0x92, 'c'(99)=0x93.
    # len 3 -> symbol 257, 7-bit code 1 (256-279 -> codes 0..23), no extra bits.
    # dist 3 -> distance symbol 2 (base 3), 5-bit code 2, no extra bits.
    # EOB is symbol 256, 7-bit code 0.
    # In deflate, integer FIELDS are packed LSB-first, but Huffman CODES are
    # transmitted MSB-first (verified against a real zlib stream).
    bits: list[int] = []

    def add_field(val, n):
        bits.extend((val >> i) & 1 for i in range(n))

    def add_code(val, n):
        bits.extend((val >> i) & 1 for i in range(n - 1, -1, -1))

    add_field(1, 1)     # bfinal
    add_field(1, 2)     # btype = fixed
    add_code(0x91, 8)   # 'a'
    add_code(0x92, 8)   # 'b'
    add_code(0x93, 8)   # 'c'
    add_code(1, 7)      # len 3 (sym 257)
    add_code(2, 5)      # dist 3 (sym 2)
    add_code(0, 7)      # EOB
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    stream = bytes(out)
    src = b"abcabc"
    blocks, events, _trees = z.parse_deflate(stream, src, verify=True)
    check("blocks", blocks == ["fixed"], str(blocks))
    check("events", events == [["L", 3], ["M", 3, 3]], str(events))


def _check_sample(data, stream, wrapper, tag):
    """Parse one sample and report whether it reconstructs the source bytes."""
    try:
        d = stream[2:-4] if wrapper == "zlib" else stream
        blocks, events, _trees = z.parse_deflate(d, data, verify=True)
        total = sum(e[1] for e in events)
        check(tag, total == len(data),
              f"total={total} len={len(data)} blocks={blocks}")
    except z.DeflateError as e:
        check(tag, False, str(e))


def test_cross_check_python_zlib():
    """parse_deflate reconstructs streams made by Python zlib across levels/wrappers."""
    print("cross-check vs Python zlib (fixed/dynamic/stored)")
    with open(DATA, "rb") as fh:
        lcet10 = fh.read()
    samples = [
        b"",
        b"a",
        b"aaaaaaaaaa",
        b"the quick brown fox jumps over the lazy dog " * 37,
        os.urandom(10000),
        (b"abc" * 100000),
        lcet10,
    ]
    for i, data in enumerate(samples):
        if not data:
            continue
        for level in (0, 1, 6, 9):
            co = zlib.compressobj(level, zlib.DEFLATED, 15)
            comp = co.compress(data) + co.flush()
            raw = zlib.compressobj(level, zlib.DEFLATED, -15)
            comp_raw = raw.compress(data) + raw.flush()
            for stream, wrapper in ((comp, "zlib"), (comp_raw, "raw")):
                _check_sample(data, stream, wrapper,
                              f"sample{i} L{level} {wrapper}")


def test_wrapper_split():
    """split_wrapper extracts the deflate data and correct trailer (zlib/gzip/raw)."""
    print("wrapper split")
    lib = z.ZlibLib(LIB)
    src = b"hello " * 100
    for wb in (15, 31, -15):
        comp = lib.compress(src, 6, wb, 8, 0)
        d, wrapper, trailer = z.split_wrapper(comp, wb)
        expect = {15: "zlib", 31: "gzip", -15: "raw"}[wb]
        check(f"wb={wb} wrapper", wrapper == expect, wrapper)
        td = dict(trailer)
        if wrapper == "zlib":
            want = zlib.adler32(src)
            check(f"wb={wb} adler trailer", td.get("adler32") == want,
                  f"{td.get('adler32', 0):#x} vs {want:#x}")
        elif wrapper == "gzip":
            want = zlib.crc32(src) & 0xFFFFFFFF
            check(f"wb={wb} crc trailer", td.get("crc32") == want,
                  f"{td.get('crc32', 0):#x} vs {want:#x}")
            check(f"wb={wb} isize trailer", td.get("isize") == len(src),
                  str(td.get("isize")))
        _b, ev, _t = z.parse_deflate(d, src, verify=True)
        check(f"wb={wb} parse", sum(e[1] for e in ev) == len(src))


def test_inflate_check():
    """inflate_check re-inflates a stream with system zlib and verifies the content."""
    print("inflate_check")
    lib = z.ZlibLib(LIB)
    src = b"the quick brown fox jumps over the lazy dog " * 100
    for wb in (15, 31, -15):
        wrapper = {15: "zlib", 31: "gzip", -15: "raw"}[wb]
        comp = lib.compress(src, 6, wb, 8, 0)
        ok, produced = z.inflate_check(src, comp, wrapper)
        check(f"wb={wb} inflate", ok is True and produced == len(src),
              f"ok={ok} produced={produced} len={len(src)}")
    comp = lib.compress(src, 6, 15, 8, 0)
    ok, _ = z.inflate_check(src, comp[:len(comp) - 2], "zlib")
    check("truncated rejected", ok is False, f"ok={ok}")


def test_ctypes_binding():
    """Stream mirrors match the C structs, and the prefix picks struct+version."""
    import ctypes
    print("ctypes binding / api auto-detection")
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        check("sizeof(z_stream)==112", ctypes.sizeof(z.z_stream) == 112,
              str(ctypes.sizeof(z.z_stream)))
        check("sizeof(zng_stream)==104", ctypes.sizeof(z.zng_stream) == 104,
              str(ctypes.sizeof(z.zng_stream)))
    lib = z.ZlibLib(LIB)
    check("native prefix", lib.prefix == "zng_", lib.prefix)
    check("native stream_type", lib.stream_type is z.zng_stream)
    src = b"the quick brown fox jumps over the lazy dog " * 100
    comp = lib.compress(src, 6, 15, 8, 0)
    ok, produced = z.inflate_check(src, comp, "zlib")
    check("native compress+inflate", ok is True and produced == len(src))
    for cand in ("/usr/lib64/libz.so.1", "/usr/lib/libz.so.1",
                 "/lib/x86_64-linux-gnu/libz.so.1"):
        if not os.path.isfile(cand):
            continue
        plib = z.ZlibLib(cand)
        if plib.prefix != "":
            continue
        check("plain stream_type", plib.stream_type is z.z_stream, cand)
        pcomp = plib.compress(src, 6, 15, 8, 0)
        pok, pproduced = z.inflate_check(src, pcomp, "zlib")
        check("plain compress+inflate", pok is True and pproduced == len(src),
              cand)
        break


def test_detect_wrapper():
    """detect_wrapper identifies the wrapper from magic bytes and recovers the trailer."""
    print("detect_wrapper")
    import gzip
    src = b"hello world " * 50
    cases = []
    cases.append(("gzip", gzip.compress(src),
                  [("crc32", zlib.crc32(src) & 0xFFFFFFFF),
                   ("isize", len(src))]))
    cz = zlib.compressobj(6, zlib.DEFLATED, 15)
    cases.append(("zlib", cz.compress(src) + cz.flush(),
                  [("adler32", zlib.adler32(src))]))
    cr = zlib.compressobj(6, zlib.DEFLATED, -15)
    cases.append(("raw", cr.compress(src) + cr.flush(), []))
    for want_wrapper, comp, want_trailer in cases:
        d, wrapper, trailer = z.detect_wrapper(comp)
        check(f"{want_wrapper} wrapper", wrapper == want_wrapper, wrapper)
        check(f"{want_wrapper} trailer", trailer == want_trailer,
              f"{trailer} vs {want_trailer}")
        # the extracted deflate must parse back to the source
        _b, ev, _t = z.parse_deflate(d, src, verify=True)
        check(f"{want_wrapper} parse", sum(e[1] for e in ev) == len(src))


def _png_chunk(ctype, payload):
    """Build a PNG chunk: 4-byte length, type, payload, 4-byte CRC (big-endian)."""
    return (len(payload).to_bytes(4, "big") + ctype + payload
            + (zlib.crc32(ctype + payload) & 0xFFFFFFFF).to_bytes(4, "big"))


def _make_png(width, height, idat, bit_depth=8, color_type=6, interlace=0):
    """Assemble a minimal PNG from an IHDR and the given IDAT zlib payload."""
    ihdr = (width.to_bytes(4, "big") + height.to_bytes(4, "big")
            + bytes([bit_depth, color_type, 0, 0, interlace]))
    return (z.PNG_SIGNATURE
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", idat)
            + _png_chunk(b"IEND", b""))


def test_parse_png():
    """parse_png reads the IHDR fields and concatenates IDAT chunk payloads."""
    print("parse_png")
    src = b"scanline data " * 40
    idat = zlib.compress(src)  # a standard zlib stream
    png = _make_png(4, 4, idat)
    header, idat_out, n_idat = z.parse_png(png)
    check("width", header["width"] == 4, str(header["width"]))
    check("height", header["height"] == 4)
    check("bit_depth", header["bit_depth"] == 8)
    check("color_type", header["color_type"] == 6)
    check("n_idat", n_idat == 1)
    check("idat round-trip", idat_out == idat)
    check("idat is zlib", z.detect_wrapper(idat_out)[1] == "zlib")
    # multiple IDAT chunks concatenate in order
    half = len(idat) // 2
    ihdr = (4).to_bytes(4, "big") + (4).to_bytes(4, "big") + bytes([8, 6, 0, 0, 0])
    png2 = (z.PNG_SIGNATURE + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", idat[:half])
            + _png_chunk(b"IDAT", idat[half:])
            + _png_chunk(b"IEND", b""))
    _h, idat2, n2 = z.parse_png(png2)
    check("multi idat count", n2 == 2, str(n2))
    check("multi idat concat", idat2 == idat)
    # bad signature rejected
    try:
        z.parse_png(b"X" + png[1:])
        check("bad signature rejected", False, "no DeflateError")
    except z.DeflateError:
        check("bad signature rejected", True)
    # missing IDAT rejected
    nodat = (z.PNG_SIGNATURE
             + _png_chunk(b"IHDR", ihdr)
             + _png_chunk(b"IEND", b""))
    try:
        z.parse_png(nodat)
        check("missing idat rejected", False, "no DeflateError")
    except z.DeflateError:
        check("missing idat rejected", True)


def test_png_filter_stats():
    """png_filter_stats counts the per-scanline filter types (interlace 0/1)."""
    print("png_filter_stats")
    # 4x2 RGBA, interlace 0: each scanline is 1 filter byte + 4*4 pixel bytes.
    row_width = 1 + 4 * 4
    data = (bytes([0]) + b"\x00" * (row_width - 1)
            + bytes([2]) + b"\x00" * (row_width - 1))
    header = {"width": 4, "height": 2, "bit_depth": 8, "color_type": 6,
              "compression": 0, "filter": 0, "interlace": 0}
    counts, n_rows = z.png_filter_stats(header, data)
    check("i0 rows", n_rows == 2, str(n_rows))
    check("i0 none", counts.get(0) == 1, str(counts))
    check("i0 up", counts.get(2) == 1, str(counts))
    check("i0 bad size", z.png_filter_stats(header, data + b"\x00") is None)
    # 4x4 RGBA, Adam7: 7 non-empty scanlines; filter bytes at the row starts.
    offsets = [0, 5, 10, 19, 28, 37, 54]  # from the Adam7 pass layout (71 bytes)
    data2 = bytearray(71)
    for offset, ftype in zip(offsets, (0, 1, 2, 3, 4, 0, 1), strict=True):
        data2[offset] = ftype
    header2 = dict(header, width=4, height=4, interlace=1)
    counts2, n_rows2 = z.png_filter_stats(header2, bytes(data2))
    check("adam7 rows", n_rows2 == 7, str(n_rows2))
    check("adam7 none", counts2.get(0) == 2, str(counts2))
    check("adam7 paeth", counts2.get(4) == 1, str(counts2))
    check("adam7 bad size",
          z.png_filter_stats(header2, data2 + b"\x00") is None)


def _raw_deflate(data):
    """Compress ``data`` to a raw (unwrapped) deflate stream via system zlib."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _make_zip(entries, streamed_names=()):
    """Assemble a minimal ZIP archive from (name, data, method) entries.

    method 0 = stored, 8 = raw deflate. The central directory always carries
    the real sizes (the authoritative source parse_zip reads). For names in
    ``streamed_names`` the local header uses zero sizes and a data descriptor is
    appended after the data (bit 3), mimicking a streaming writer."""
    out = bytearray()
    central = bytearray()
    for name, data, method in entries:
        name_bytes = name.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = _raw_deflate(data) if method == z.ZIP_METHOD_DEFLATE else data
        lfh_offset = len(out)
        streamed = name in streamed_names
        flags = 0x08 if streamed else 0
        out += struct.pack("<IHHH", 0x04034b50, 20, flags, method)
        out += struct.pack("<HH", 0, 0x21)  # mod time, mod date
        if streamed:
            out += struct.pack("<III", 0, 0, 0)  # sizes deferred to descriptor
        else:
            out += struct.pack("<III", crc, len(comp), len(data))
        out += struct.pack("<HH", len(name_bytes), 0)  # name len, extra len
        out += name_bytes
        out += comp
        if streamed:
            out += struct.pack("<I", 0x08074b50)  # data descriptor magic
            out += struct.pack("<III", crc, len(comp), len(data))
        central += struct.pack("<IHHHH", 0x02014b50, 20, 20, flags, method)
        central += struct.pack("<HH", 0, 0x21)  # mod time, mod date
        central += struct.pack("<III", crc, len(comp), len(data))
        central += struct.pack("<HHH", len(name_bytes), 0, 0)  # n, extra, comment
        central += struct.pack("<HHI", 0, 0, 0)  # disk, internal, external
        central += struct.pack("<I", lfh_offset)
        central += name_bytes
    cd_offset = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries), len(entries),
                       len(central), cd_offset, 0)
    return bytes(out)


def test_parse_zip():
    """parse_zip reads entries from the central directory (authoritative sizes)."""
    print("parse_zip")
    data_a = b"hello world " * 50
    data_b = b"\x00\x01\x02" * 20
    archive = _make_zip([("a.txt", data_a, z.ZIP_METHOD_DEFLATE),
                         ("b.bin", data_b, z.ZIP_METHOD_STORED)])
    entries = z.parse_zip(archive)
    check("entry count", len(entries) == 2, str(len(entries)))
    entry_a = entries[0]
    entry_b = entries[1]
    check("a name", entry_a["name"] == "a.txt")
    check("a method", entry_a["method"] == z.ZIP_METHOD_DEFLATE)
    check("a usize", entry_a["usize"] == len(data_a), str(entry_a["usize"]))
    check("a csize", entry_a["csize"] < len(data_a), str(entry_a["csize"]))
    check("b method", entry_b["method"] == z.ZIP_METHOD_STORED)
    check("b usize", entry_b["usize"] == len(data_b))
    raw_a = archive[entry_a["data_offset"]:entry_a["data_offset"] + entry_a["csize"]]
    check("a data offset", zlib.decompress(raw_a, -15) == data_a)
    raw_b = archive[entry_b["data_offset"]:entry_b["data_offset"] + entry_b["csize"]]
    check("b data offset", raw_b == data_b)
    # streamed entry (bit 3): local header sizes are zero, but the central
    # directory still reports the real sizes and the correct data offset
    streamed = _make_zip([("s.bin", data_b, z.ZIP_METHOD_DEFLATE)],
                         streamed_names=("s.bin",))
    entry_s = z.parse_zip(streamed)[0]
    check("streamed usize", entry_s["usize"] == len(data_b), str(entry_s["usize"]))
    check("streamed csize", entry_s["csize"] < len(data_b), str(entry_s["csize"]))
    raw_s = streamed[entry_s["data_offset"]:entry_s["data_offset"] + entry_s["csize"]]
    check("streamed data", zlib.decompress(raw_s, -15) == data_b)
    # a header without an EOCD is rejected
    try:
        z.parse_zip(b"\x50\x4b\x03\x04" + b"\x00" * 40)
        check("no eocd rejected", False, "no DeflateError")
    except z.DeflateError:
        check("no eocd rejected", True)
    # a corrupt central directory magic is rejected
    bad = bytearray(archive)
    bad[archive.rfind(z.ZIP_CDH_MAGIC)] = 0xFF
    try:
        z.parse_zip(bytes(bad))
        check("bad cd rejected", False, "no DeflateError")
    except z.DeflateError:
        check("bad cd rejected", True)


def test_aggregate_analyses():
    """aggregate_analyses merges per-entry events/trees into summed metrics."""
    print("aggregate_analyses")
    src1 = b"aaaabbbbaaabccdd" * 20
    src2 = b"the quick brown fox jumps over the lazy dog " * 30

    def make_analysis(src):
        raw = _raw_deflate(src)
        return z.Analysis(None, (None, None, None, None), src, raw,
                          detected=(raw, "raw", []))
    analyses = [make_analysis(src1), make_analysis(src2)]
    agg = z.aggregate_analyses(analyses, None)
    check("n_match sum",
          agg["n_match"] == sum(a.stats["n_match"] for a in analyses))
    check("n_lit sum", agg["n_lit"] == sum(a.stats["n_lit"] for a in analyses))
    check("comp sum", agg["comp_size"] == sum(a.comp_size for a in analyses))
    check("src sum", agg["src_size"] == sum(a.src_size for a in analyses))
    combined_len: z.Counter = z.Counter()
    combined_dist: z.Counter = z.Counter()
    for a in analyses:
        combined_len.update(a.stats["len_hist"])
        combined_dist.update(a.stats["dist_hist"])
    check("len_hist sum", agg["len_hist"] == combined_len)
    check("dist_hist sum", agg["dist_hist"] == combined_dist)
    for name in ("litlen", "dist"):
        exp_actual = sum(a.stats["huff"][name]["total"][0] for a in analyses)
        exp_ideal = sum(a.stats["huff"][name]["total"][1] for a in analyses)
        exp_count = sum(a.stats["huff"][name]["total"][2] for a in analyses)
        got = agg["huff"][name]["total"]
        check(f"huff {name} actual", got[0] == exp_actual, str(got))
        check(f"huff {name} ideal", abs(got[1] - exp_ideal) < 1e-6, str(got))
        check(f"huff {name} count", got[2] == exp_count)
    exp_total = sum(a.stats["budget"]["total"] for a in analyses)
    check("budget total bits", agg["budget"]["total"] == exp_total,
          str(agg["budget"]["total"]))


def test_zip_real_files():
    """Parse the provided real .zip/.jar/.apk (guarded by file presence)."""
    print("zip real files")
    base = "/home/opencode/opencode"
    cases = [("cpu-z_2.15-en.zip", 4, 4),
             ("jsse.jar", 162, 0),
             ("com.freepie.android.imu.apk", 15, 7)]
    for fname, n_total, n_deflate in cases:
        path = os.path.join(base, fname)
        if not os.path.isfile(path):
            print(f"  [skip] {fname} not present")
            continue
        with open(path, "rb") as fh:
            entries = z.parse_zip(fh.read())
        got_deflate = sum(1 for e in entries
                          if e["method"] == z.ZIP_METHOD_DEFLATE)
        check(f"{fname} entries", len(entries) == n_total, str(len(entries)))
        check(f"{fname} deflate", got_deflate == n_deflate, str(got_deflate))


def test_zip_progress():
    """analyze-file on a zip shows one cumulative bar across its deflate entries."""
    print("zip progress")
    path = "/home/opencode/opencode/cpu-z_2.15-en.zip"
    if not os.path.isfile(path):
        print("  [skip] cpu-z zip not present")
        return
    args = types.SimpleNamespace(
        file=os.path.basename(path), json=False, window_bits=15, progress=True,
        length_full=False, dist_log2=False, map_axis_linear=False,
        map_scale_log2=False, map_colors=None, huff_symbols=False,
        events=False, max_events=0,
        show_bytes=False, json_full=False)
    with open(path, "rb") as fh:
        comp = fh.read()
    buf = _FakeTTY()
    old_err, old_out = sys.stderr, sys.stdout
    sys.stderr, sys.stdout = buf, io.StringIO()
    try:
        z.analyze_zip_file(args, comp, os.path.basename(path), zlib)
    finally:
        sys.stderr, sys.stdout = old_err, old_out
    percents = []
    for frame in buf.getvalue().split("\r"):
        match = re.search(r"(\d{1,3})%", frame)
        if match:
            percents.append(int(match.group(1)))
    check("bar rendered", len(percents) >= 1, str(len(percents)))
    check("bar monotonic",
          all(a <= b for a, b in itertools.pairwise(percents)))
    check("bar reaches 100%", bool(percents) and percents[-1] == 100)


def test_parse_libs():
    """parse_libs accepts one or two paths and rejects three."""
    print("parse_libs")
    check("single", z.parse_libs("/p/lib.so") == ("/p/lib.so", "/p/lib.so"),
          str(z.parse_libs("/p/lib.so")))
    check("pair", z.parse_libs("/a.so, /b.so") == ("/a.so", "/b.so"),
          str(z.parse_libs("/a.so, /b.so")))
    try:
        z.parse_libs("a,b,c")
        check("three paths rejected", False, "no SystemExit raised")
    except SystemExit:
        check("three paths rejected", True)


def test_divergences():
    """find_divergences locates divergent regions and their event ranges/offsets."""
    print("find_divergences / first_divergence_offset")
    a = [["L", 5], ["M", 10, 3], ["L", 2], ["M", 7, 1], ["L", 4]]
    b = [["L", 5], ["M", 10, 3], ["M", 9, 2], ["L", 4]]
    regions, n, _cov = z.find_divergences(a, b)
    check("one region", n == 1, str(regions))
    if n == 1:
        s, e, i0, ia, j0, ib = regions[0]
        check("region start", s == 15, str(s))
        check("region end", e == 24, str(e))
        check("a range", (i0, ia) == (2, 4), str((i0, ia)))
        check("b range", (j0, ib) == (2, 3), str((j0, ib)))
    check("first off", z.first_divergence_offset(a, b) == 15)
    check("identical", z.first_divergence_offset(a, a) is None)
    _same, n2, c2 = z.find_divergences(a, a)
    check("no regions", n2 == 0 and c2 == 0)
    # divergence to end of input
    c = [["L", 5], ["M", 10, 3], ["L", 2], ["M", 7, 2], ["L", 4]]
    r, n3, _ = z.find_divergences(a, c)
    check("region to end", n3 == 1 and r[0][1] == 24, str(r))


def test_first_byte_diff():
    """first_byte_diff finds the first differing byte (same/length/large inputs)."""
    print("first_byte_diff")
    check("same", z.first_byte_diff(b"abc", b"abc") is None)
    check("diff", z.first_byte_diff(b"abc", b"axc") == 1)
    check("len", z.first_byte_diff(b"ab", b"abc") == 2)
    big_a = b"0" * (2 ** 20 + 5) + b"1"
    big_b = b"0" * (2 ** 20 + 5) + b"2"
    check("large", z.first_byte_diff(big_a, big_b) == 2 ** 20 + 5)


def test_histograms():
    """length/dist histogram rows bucket correctly (code buckets default,
    log2/full opt-in)."""
    print("histograms")
    from collections import Counter
    rows = z.dist_hist_rows(Counter({1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 8: 6, 9: 7,
                                     16: 8, 17: 9, 32: 10, 33: 11}), log2=True)
    check("dist rows log2",
          rows == [("[1,1]", 1), ("[2,2]", 2), ("[3,4]", 7), ("[5,8]", 11),
                   ("[9,16]", 15), ("[17,32]", 19), ("[33,64]", 11)], str(rows))
    # default: bucketed by deflate distance code (sans extra bits)
    rows = z.dist_hist_rows(Counter({1: 1, 2: 2, 5: 3, 6: 4, 9: 5, 10: 6}))
    check("dist rows code",
          rows == [("1", 1), ("2", 2), ("[5,6]", 7), ("[9,12]", 11)], str(rows))
    # default: bucketed by deflate length code (sans extra bits)
    rows = z.length_hist_rows(Counter({3: 1, 19: 5, 20: 3}))
    check("len rows bucketed", rows == [("3", 1), ("[19,22]", 8)], str(rows))
    # full: one row per individual length
    rows = z.length_hist_rows(Counter({3: 1, 5: 2}), full=True)
    check("len rows full", rows == [("3", 1), ("5", 2)], str(rows))


def test_match_map():
    """distance x length map: grid binning (encoding + linear) and glyph scaling."""
    # pylint: disable=protected-access
    print("match map")
    from collections import Counter
    grid, row_labels, tick_cols, tick_vals = z.match_map_grid(
        Counter({(1, 4): 5, (5, 11): 3, (300, 258): 1}), False)
    check("map enc size", len(grid) == 29 and len(grid[0]) == 30,
          f"{len(grid)}x{len(grid[0])}")
    check("map enc cells",
          grid[1][0] == 5 and grid[8][4] == 3 and grid[28][16] == 1,
          str([grid[1][0], grid[8][4], grid[28][16]]))
    check("map enc total", sum(sum(row) for row in grid) == 9)
    check("map enc row labels", row_labels[1] == "4" and row_labels[8] == "11-12",
          f"{row_labels[1]},{row_labels[8]}")
    check("map enc ticks", len(tick_cols) == 6 and tick_cols[-1] == 29
          and tick_vals == z.MAP_TICKS_ENC, str(tick_cols))
    grid, row_labels, _ticks, _vals = z.match_map_grid(
        Counter({(1, 4): 5, (32768, 258): 2}), True)
    check("map lin size", len(grid) == z.MAP_LIN_ROWS
          and len(grid[0]) == z.MAP_LIN_COLS, f"{len(grid)}x{len(grid[0])}")
    check("map lin cells", grid[0][0] == 5 and grid[z.MAP_LIN_ROWS - 1]
          [z.MAP_LIN_COLS - 1] == 2, str([grid[0][0], grid[z.MAP_LIN_ROWS - 1]
          [z.MAP_LIN_COLS - 1]]))
    # even-bucket shading: 0 blank, low end level 1, the max is the top step,
    # and each of the 6 glyph bands spans exactly 5 of the 30 thermal steps
    check("map level linear",
          z._map_level_linear(0, 100, 6) == 0 and z._map_level_linear(1, 100, 6) == 1
          and z._map_level_linear(17, 100, 6) == 2
          and z._map_level_linear(50, 100, 6) == 4
          and z._map_level_linear(100, 100, 6) == 6
          and z._map_level_linear(100, 100, len(z.MAP_THERMAL))
          == len(z.MAP_THERMAL))
    check("map level log2",
          z._map_level_log2(0, 100, 6) == 0 and z._map_level_log2(1, 100, 6) == 1
          and z._map_level_log2(8, 10000, 6) == 2
          and z._map_level_log2(100, 100, 6) == 6 and z._map_level_log2(1, 1, 6) == 6)
    # plain cells: a blank space for a zero count, density glyphs otherwise
    check("map cell blank", z._map_cell(0, 100, z._map_level_linear, False) == " ")
    check("map cell plain",
          z._map_cell(1, 100, z._map_level_linear, False) == z.MAP_GLYPH[1]
          and z._map_cell(100, 100, z._map_level_linear, False) == z.MAP_GLYPH[6])
    # cell rendering: plain density glyphs, a solid heat cell (fg=bg), a blank
    # cell on the dark background, and the dim frame
    glyph = z._map_level_linear(50, 100, 6)
    tint = z._map_level_linear(50, 100, len(z.MAP_THERMAL))
    code = z.MAP_THERMAL[tint - 1]
    heat = f"\x1b[38;5;{code};48;5;{code}m{z.MAP_GLYPH[glyph]}\x1b[0m"
    check("map cell heat", z._map_cell(50, 100, z._map_level_linear, True) == heat)
    check("map cell blank colored",
          z._map_cell(0, 100, z._map_level_linear, True)
          == "\x1b[48;5;234m \x1b[0m")
    check("map frame dim",
          "\x1b[38;5;240m" in z._map_top_border(30, True)
          and "\x1b" not in z._map_top_border(30, False))
    # legend: the plain glyph ramp off, the 30-step thermal ramp (fg=bg) + blank
    check("map legend plain",
          "\u00b7" in z._map_legend(False) and "\x1b" not in z._map_legend(False))
    check("map legend colored",
          z._map_legend(True).count("\x1b[38;5;") == len(z.MAP_THERMAL))
    check("map legend blank swatch", "\x1b[48;5;234m" in z._map_legend(True))
    # frame + side-by-side A vs B map: shared scale, middle labels, per-side ruler
    import contextlib
    from types import SimpleNamespace
    buf1 = io.StringIO()
    with contextlib.redirect_stdout(buf1):
        z.print_match_map(Counter({(1, 4): 5, (5, 11): 3, (300, 258): 1}),
                          False, False, False)
    out1 = buf1.getvalue()
    check("map frame", z.MAP_TOP_LEFT in out1 and z.MAP_TOP_RIGHT in out1
          and z.MAP_SIDE in out1)
    side_a = SimpleNamespace(stats={"pair_hist": Counter({(1, 4): 5, (300, 258): 1})})
    side_b = SimpleNamespace(stats={"pair_hist": Counter({(1, 4): 2})})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        z.print_match_map_diff(side_a, side_b, False, False, False)
    out = buf.getvalue()
    check("map diff header",
          "=== match distance x length map (A vs B, encoding buckets) ===" in out)
    check("map diff labels", "A:" in out and "B:" in out)
    check("map diff shared max", "shared max cell = 5" in out)
    check("map diff rulers", out.count(z.MAP_MARKER) == 12)
    check("map diff frame", z.MAP_TOP_LEFT in out and z.MAP_SIDE in out)


def test_window_size():
    """window_size maps windowBits to a window size (zlib/gzip/raw) or None."""
    print("window_size")
    # zlib wrapper
    check("zlib 15", z.window_size(15) == 32768, str(z.window_size(15)))
    check("zlib 8", z.window_size(8) == 256, str(z.window_size(8)))
    # gzip wrapper (window = 2**(wbits-16))
    check("gzip 31", z.window_size(31) == 32768, str(z.window_size(31)))
    check("gzip 17", z.window_size(17) == 2, str(z.window_size(17)))
    # raw deflate (window = 2**(-wbits))
    check("raw -15", z.window_size(-15) == 32768, str(z.window_size(-15)))
    check("raw -12", z.window_size(-12) == 4096, str(z.window_size(-12)))
    # out of range (below 8, above 31, below -15)
    check("out of range", z.window_size(32) is None and z.window_size(7) is None
          and z.window_size(-16) is None)


def test_huffman():
    """Huffman efficiency and bit budget match exact crafted values + invariants."""
    print("huffman efficiency + bit budget")
    # exact values from the crafted fixed block 'abcabc'
    # (3 literals a/b/c, one len-3 match, EOB)
    bits: list[int] = []

    def field(val, n):
        bits.extend((val >> i) & 1 for i in range(n))

    def code(val, n):
        bits.extend((val >> i) & 1 for i in range(n - 1, -1, -1))

    field(1, 1)
    field(1, 2)
    code(0x91, 8)
    code(0x92, 8)
    code(0x93, 8)
    code(1, 7)
    code(2, 5)
    code(0, 7)
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    src = b"abcabc"
    a = z.Analysis(None, (None, -15, None, None), src, bytes(out))
    check("one fixed block", a.blocks == ["fixed"], str(a.blocks))
    h = a.stats["huff"]
    # a,b,c -> 8b each; eob + len257 -> 7b each => actual 38, n 5
    check("litlen actual", h["litlen"]["total"][0] == 38,
          str(h["litlen"]["total"]))
    check("litlen n", h["litlen"]["total"][2] == 5, str(h["litlen"]["total"]))
    check("dist actual", h["dist"]["total"][0] == 5, str(h["dist"]["total"]))
    check("dist n", h["dist"]["total"][2] == 1, str(h["dist"]["total"]))

    lib = z.ZlibLib(LIB)
    data = (b"hello world, this phrase repeats over and over " * 300)
    for level in (1, 6, 9):
        comp = lib.compress(data, level, 15, 8, 0)
        a = z.Analysis(lib, (level, 15, 8, 0), data, comp)
        h = a.stats["huff"]
        b = a.stats["budget"]
        for name in ("litlen", "dist"):
            act, ide, _n = h[name]["total"]
            check(f"L{level} {name} overhead>=0", act >= ide - 1e-6,
                  f"{act} vs {ide}")
        dyn = h["litlen"]["dynamic"]
        if dyn[2]:
            ovs = (dyn[0] - dyn[1]) / dyn[2]
            check(f"L{level} litlen dynamic<1b/sym", ovs < 1.0, f"{ovs:.3f}")
        accounted = (b["litlen"] + b["len_extra"] + b["dist"]
                     + b["dist_extra"] + b["stored"])
        check(f"L{level} header>=0", b["header"] >= 0, f"{b['header']}")
        check(f"L{level} budget<=total", accounted <= b["total"],
              f"{accounted} vs {b['total']}")


def test_match_costs():
    # pylint: disable=protected-access
    """_match_costs computes per-match bits, the literal baseline, wastefulness."""
    print("match costs / cost-benefit boundary")
    # non-wasteful: a fixed-block len-3/dist-3 match (the abcabc stream)
    lit_len = list(z.FIXED_LITLEN)
    dist_len = list(z.FIXED_DIST)
    lit_freq = [0] * len(lit_len)
    for sym in (97, 98, 99, 256, 257):
        lit_freq[sym] = 1
    dist_freq = [0] * len(dist_len)
    dist_freq[2] = 1
    trees = [{"type": "fixed", "lit_len": lit_len, "dist_len": dist_len,
              "lit_freq": lit_freq, "dist_freq": dist_freq,
              "ev_start": 0, "ev_end": 2}]
    eco = z._match_costs([["L", 3], ["M", 3, 3]], trees)
    check("abcabc literal_bpb", abs(eco["literal_bpb"] - 8.0) < 1e-9,
          f"{eco['literal_bpb']}")
    check("abcabc n_match", eco["n_match"] == 1, str(eco["n_match"]))
    check("abcabc match bits", eco["total_match_bits"] == 12,
          str(eco["total_match_bits"]))  # 7 (len code) + 0 + 5 (dist code) + 0
    check("abcabc bpb", abs(eco["bits_per_matched_byte"] - 4.0) < 1e-9,
          f"{eco['bits_per_matched_byte']}")
    check("abcabc not wasteful", eco["n_wasteful"] == 0, str(eco["n_wasteful"]))
    check("abcabc cost_hist", eco["cost_hist"].get((3, 3)) == [12, 3],
          str(eco["cost_hist"].get((3, 3))))
    # wasteful: cheap literals (4 bits/byte) make a len-3 match (13 bits) > 12
    ll = [0] * 286
    for sym in range(256):
        ll[sym] = 4
    ll[257] = 8
    dl = [5] * 30
    lf = [0] * 286
    lf[0] = lf[256] = lf[257] = 1
    trees2 = [{"type": "dynamic", "lit_len": ll, "dist_len": dl,
               "lit_freq": lf, "dist_freq": [0] * 30,
               "ev_start": 0, "ev_end": 2}]
    eco2 = z._match_costs([["L", 1], ["M", 3, 4]], trees2)
    check("cheap literal_bpb", abs(eco2["literal_bpb"] - 4.0) < 1e-9,
          f"{eco2['literal_bpb']}")
    check("cheap match bits", eco2["total_match_bits"] == 13,
          str(eco2["total_match_bits"]))  # 8 (len code) + 0 + 5 (dist code) + 0
    check("cheap wasteful", eco2["n_wasteful"] == 1, str(eco2["n_wasteful"]))
    check("cheap bytes wasted", eco2["bytes_wasteful"] == 3,
          str(eco2["bytes_wasteful"]))
    check("cheap overpayment", abs(eco2["overpayment_bits"] - 1.0) < 1e-9,
          f"{eco2['overpayment_bits']}")
    check("cheap dominant cell", eco2["dominant_cell"] is not None)
    rows = {dc: be for dc, _n, be, _w, _b, _o in eco2["dist_rows"]}
    check("cheap boundary row", rows.get(z.DIST_CODE_OF[4]) == 3, str(rows))


def test_event_bounds():
    """parse_deflate tags each block with an ev_start/ev_end span that tiles."""
    print("parse_deflate event bounds")
    with open(DATA, "rb") as fh:
        src = fh.read()
    lib = z.ZlibLib(LIB)
    comp = lib.compress(src, 6, 15, 8, 0)
    deflate, _wrapper, _trailer = z.split_wrapper(comp, 15)
    _blocks, events, trees = z.parse_deflate(deflate, src, verify=True)
    check("n blocks >= 2", len(trees) >= 2, str(len(trees)))
    tiled = trees[0]["ev_start"] == 0 and trees[-1]["ev_end"] == len(events)
    for k in range(1, len(trees)):
        tiled = tiled and trees[k - 1]["ev_end"] == trees[k]["ev_start"]
    check("ev spans tile", tiled, str([t["ev_start"] for t in trees]))
    check("each block has events", all(t["ev_end"] > t["ev_start"]
          for t in trees))


def test_cost_map_grid():
    """cost_map_grid bins cost data into bits/byte cells (encoding + linear)."""
    print("cost map grid")
    # two (dist=10) matches both in length code 12 (19-22): aggregate to 6.0
    hist = {(10, 19): [40, 10], (10, 20): [80, 10]}
    grid, _labels, _tick_cols, _tick_vals = z.cost_map_grid(hist, False)
    check("cost grid shape", len(grid) == len(z.LENGTH_BASE)
          and len(grid[0]) == len(z.DIST_BASE), f"{len(grid)}x{len(grid[0])}")
    r = z.bisect.bisect_right(z.LENGTH_BASE, 20) - 1
    c = z.bisect.bisect_right(z.DIST_BASE, 10) - 1
    check("cost cell avg", abs(grid[r][c] - 6.0) < 1e-9, f"{grid[r][c]}")
    check("cost cell empty", grid[0][0] == 0.0, f"{grid[0][0]}")
    grid2, _l2, _tc2, _tv2 = z.cost_map_grid(hist, True)
    check("cost grid linear shape", len(grid2) == z.MAP_LIN_ROWS
          and len(grid2[0]) == z.MAP_LIN_COLS, f"{len(grid2)}x{len(grid2[0])}")


def test_cost_level_fixed():
    # pylint: disable=protected-access
    """_cost_level_fixed shades the fixed 0..COST_MAX_BITS ramp linearly."""
    print("cost map fixed levels")
    fn = z._cost_level_fixed
    check("cost fixed zero blank", fn(0, z.COST_MAX_BITS, 6) == 0,
          str(fn(0, z.COST_MAX_BITS, 6)))
    check("cost fixed tiny -> 1", fn(0.1, z.COST_MAX_BITS, 6) == 1,
          str(fn(0.1, z.COST_MAX_BITS, 6)))
    check("cost fixed tiny 30 steps -> 1", fn(0.001, z.COST_MAX_BITS, 30) == 1,
          str(fn(0.001, z.COST_MAX_BITS, 30)))
    check("cost fixed max -> steps", fn(8.0, z.COST_MAX_BITS, 6) == 6,
          str(fn(8.0, z.COST_MAX_BITS, 6)))
    check("cost fixed max 30 -> steps", fn(8.0, z.COST_MAX_BITS, 30) == 30,
          str(fn(8.0, z.COST_MAX_BITS, 30)))
    check("cost fixed monotonic",
          fn(2.0, z.COST_MAX_BITS, 6) <= fn(4.0, z.COST_MAX_BITS, 6)
          <= fn(8.0, z.COST_MAX_BITS, 6))
    check("cost fixed overpaid sentinel", fn(8.0001, z.COST_MAX_BITS, 6) == 7,
          str(fn(8.0001, z.COST_MAX_BITS, 6)))
    check("cost fixed overpaid 30 steps", fn(12.0, z.COST_MAX_BITS, 30) == 31,
          str(fn(12.0, z.COST_MAX_BITS, 30)))


def test_cost_cell_scaling():
    # pylint: disable=protected-access
    """_map_cell renders blanks, first-glyph non-zeros, and the white 'X'
    overpaid cell on the cost map's fixed scale."""
    print("cost map cell scaling")
    fn = z._cost_level_fixed
    blank = z._map_cell(0, z.COST_MAX_BITS, fn, False)
    check("cell blank space", blank == " ", repr(blank))
    first = z._map_cell(0.1, z.COST_MAX_BITS, fn, False)
    check("cell first glyph", first == z.MAP_GLYPH[1], repr(first))
    dense = z._map_cell(8.0, z.COST_MAX_BITS, fn, False)
    check("cell 8.0 densest", dense == z.MAP_GLYPH[6], repr(dense))
    over = z._map_cell(12.0, z.COST_MAX_BITS, fn, False)
    check("cell overpaid X plain", over == "X", repr(over))
    blob = z._map_cell(12.0, z.COST_MAX_BITS, fn, True)
    check("cell overpaid X white",
          z._MAP_ANSI_FG_BG.format(z.MAP_OVERPAID, z.MAP_OVERPAID) in blob
          and "X" in blob,
          repr(blob))
    blank_c = z._map_cell(0, z.COST_MAX_BITS, fn, True)
    check("cell blank color", "\x1b[48;5;234m" in blank_c, repr(blank_c))


def test_compact_json():
    # pylint: disable=protected-access
    """_compact_json emits valid, round-tripping JSON and inlines flat data."""
    print("compact json")
    import json
    doc = {"a": 1, "b": [1, 2, 3], "c": {"x": 1, "y": [2, 3]},
           "d": {"1": [5, 6], "2": [7, 8]}, "e": [], "f": {"empty": {}}}
    out = z._compact_json(doc)
    try:
        back = json.loads(out)
    except json.JSONDecodeError as exc:
        check("compact json valid", False, f"{exc}\n{out}")
        return
    check("compact json valid", True)
    check("compact json round-trip", back == doc, out)
    check("compact json scalar list inline", '"b": [1, 2, 3]' in out, out)
    check("compact json flat dict inline",
          '"d": {"1": [5, 6], "2": [7, 8]}' in out, out)
    check("compact json nested indented", '\n  "c":' in out, out)
    check("compact json empty list", '"e": []' in out, out)


def test_metrics_diff():
    """metrics_diff_rows builds the neutral A/B table from two analyses."""
    print("metrics diff table")
    lib = z.ZlibLib(LIB)
    src = b"the quick brown fox jumps over the lazy dog " * 200
    a = z.Analysis(lib, (1, 15, 8, 0), src, lib.compress(src, 1, 15, 8, 0))
    b = z.Analysis(lib, (6, 15, 8, 0), src, lib.compress(src, 6, 15, 8, 0))
    rows = z.metrics_diff_rows(a, b)
    by = {name: (va, vb) for name, va, vb in rows}
    check("metrics has rows", len(rows) >= 15, str(len(rows)))
    check("metrics size row", by["compressed (wrapper)"]
          == (a.comp_size, b.comp_size), str(by["compressed (wrapper)"]))
    check("metrics size differs", a.comp_size != b.comp_size)
    check("metrics matches row", by["matches"]
          == (a.stats["n_match"], b.stats["n_match"]), str(by["matches"]))
    check("metrics coverage is float",
          isinstance(by["matched coverage %"][0], float))


def test_economics_diff_rows():
    # pylint: disable=protected-access
    """economics_diff_rows builds the A/B match-cost rows from two analyses."""
    print("economics diff rows")
    lib = z.ZlibLib(LIB)
    src = b"the quick brown fox jumps over the lazy dog " * 200
    a = z.Analysis(lib, (1, 15, 8, 0), src, lib.compress(src, 1, 15, 8, 0))
    b = z.Analysis(lib, (6, 15, 8, 0), src, lib.compress(src, 6, 15, 8, 0))
    eco_a = z._match_costs(a.events, a.block_trees)
    eco_b = z._match_costs(b.events, b.block_trees)
    rows = z.economics_diff_rows(eco_a, eco_b)
    by = {name: (va, vb) for name, va, vb in rows}
    check("eco row count", len(rows) == 8, str(len(rows)))
    check("eco matches row", by["matches"] ==
          (eco_a["n_match"], eco_b["n_match"]), str(by["matches"]))
    check("eco bits row", by["match bits"] ==
          (eco_a["total_match_bits"], eco_b["total_match_bits"]),
          str(by["match bits"]))
    check("eco float rows",
          isinstance(by["bits/matched byte"][0], float)
          and isinstance(by["literal cost (b/byte)"][0], float)
          and isinstance(by["wasteful bytes %"][0], float))
    check("eco wasteful row", by["wasteful matches"] ==
          (eco_a["n_wasteful"], eco_b["n_wasteful"]), str(by["wasteful matches"]))


def test_cost_map_diff():
    """print_cost_map_diff renders two cost grids side-by-side on a shared
    scale, and handles the empty case."""
    print("cost map diff")
    hist_a = {(3, 3): [10, 4], (10, 5): [20, 5]}
    hist_b = {(3, 3): [40, 4], (100, 9): [60, 6]}
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        z.print_cost_map_diff(hist_a, hist_b, False, False)
    finally:
        sys.stdout = old
    text = out.getvalue()
    check("cost map diff header",
          "=== match cost map (A vs B, encoding buckets, "
          "bits / matched byte) ===" in text, text[:80])
    check("cost map diff shared max", "shared max cell = " in text)
    check("cost map diff scale note", "scale: 0.0-8.0 bits/byte" in text)
    check("cost map diff overpaid note", "overpaid > 8.0" in text)
    check("cost map diff overpaid cell", "X" in text)
    check("cost map diff legend", "bits per matched byte" in text)
    check("cost map diff labels", "A:" in text and "B:" in text)
    out = io.StringIO()
    sys.stdout = out
    try:
        z.print_cost_map_diff({}, {}, True, False)
    finally:
        sys.stdout = old
    check("cost map diff no matches", "(no matches)" in out.getvalue())


def test_match_economics_render():
    # pylint: disable=protected-access
    """print_match_economics renders the two-line boundary-table header and a
    3-decimal overpay for fractional wasteful matches."""
    print("match economics render")
    ll = [0] * 286
    for sym in range(4):
        ll[sym] = 4
    ll[3] = 5
    ll[257] = 8
    lf = [0] * 286
    for sym in range(4):
        lf[sym] = 1
    lf[256] = 1
    trees = [{"type": "dynamic", "lit_len": ll, "dist_len": [5] * 30,
              "lit_freq": lf, "dist_freq": [0] * 30,
              "ev_start": 0, "ev_end": 2}]
    events = [["L", 1], ["M", 3, 4]]
    eco = z._match_costs(events, trees)
    check("render fractional overpay",
          abs(eco["overpayment_bits"] - 0.25) < 1e-9,
          f"{eco['overpayment_bits']}")
    out = io.StringIO()
    old_out = sys.stdout
    sys.stdout = out
    try:
        z.print_match_economics(types.SimpleNamespace(events=events,
                                                      block_trees=trees),
                                False, False)
    finally:
        sys.stdout = old_out
    text = out.getvalue()
    check("boundary table shown",
          "=== match cost/benefit boundary (by distance) ===" in text)
    check("boundary header distance/band",
          "distance" in text and "band" in text)
    check("boundary header match/count",
          "match" in text and "count" in text)
    check("boundary header overpay/bits",
          "overpay" in text and "bits" in text)
    check("boundary overpay 3-dec", "0.250" in text)
    check("summary overpay 3-dec", "0.250 bits" in text)


def test_region_effect():
    # pylint: disable=protected-access
    """_region_effect summarizes a divergent region's per-side split."""
    print("region effect")
    a = [["L", 5], ["M", 10, 3], ["L", 2], ["M", 7, 1], ["L", 4]]
    b = [["L", 5], ["M", 10, 3], ["M", 9, 2], ["L", 4]]
    span, sa, sb = z._region_effect(a[2:4], b[2:3], 15, 24)
    check("region span", span == 9, str(span))
    check("region a split", (sa[0], sa[1], sa[2]) == (1, 7, 2), str(sa))
    check("region b split", (sb[0], sb[1], sb[2]) == (1, 9, 0), str(sb))


def test_cli_smoke():
    """Run the CLI end-to-end (analyze / analyze-file / diff) via subprocess."""
    print("cli smoke (analyze / analyze-file / diff)")
    tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zanalyze.py")
    # analyze: compress the input file with the library and print a report
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA],
                       capture_output=True, text=True, check=False)
    check("analyze exit 0", r.returncode == 0, r.stderr[-300:])
    check("analyze summary", "=== analysis" in r.stdout)
    check("analyze blocks", "blocks:" in r.stdout)
    check("analyze inflate ok", "inflate check: ok" in r.stdout)
    check("analyze length buckets",
          "=== match length encoding histogram (sans extra bits) ===" in r.stdout)
    check("analyze distance encoding",
          "=== match distance encoding histogram (sans extra bits) ===" in r.stdout)
    check("analyze map default",
          "=== match distance x length map (encoding buckets) ===" in r.stdout
          and "32K" in r.stdout and "scale: linear" in r.stdout)
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--length-full"], capture_output=True, text=True,
                       check=False)
    check("analyze length full", "=== match length histogram ===" in r.stdout,
          r.stderr[-300:])
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--dist-log2"], capture_output=True, text=True,
                       check=False)
    check("analyze distance log2",
          "=== match distance histogram (log2 buckets) ===" in r.stdout,
          r.stderr[-300:])
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--map-axis-linear"], capture_output=True, text=True,
                       check=False)
    check("analyze map linear axis",
          "=== match distance x length map (linear 40x56) ===" in r.stdout,
          r.stderr[-300:])
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--map-scale-log2"], capture_output=True, text=True,
                       check=False)
    check("analyze map log2 scale",
          "scale: log2" in r.stdout and "encoding buckets" in r.stdout,
          r.stderr[-300:])
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--map-colors-on"], capture_output=True, text=True,
                       check=False)
    check("analyze map colors on", "\x1b[38;5;" in r.stdout, r.stderr[-300:])
    r = subprocess.run([sys.executable, tool, "analyze", "--lib", LIB, DATA,
                        "--map-colors-off"], capture_output=True, text=True,
                       check=False)
    check("analyze map colors off", "\x1b" not in r.stdout, r.stderr[-300:])
    # analyze-file: write a gzip of the input, then analyze that file
    with open(DATA, "rb") as src_fh:
        src = src_fh.read()
    import gzip
    gz = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cli_smoke.gz")
    with open(gz, "wb") as fh:
        fh.write(gzip.compress(src))
    try:
        r = subprocess.run([sys.executable, tool, "analyze-file", gz,
                            "--window-bits", "15"],
                           capture_output=True, text=True, check=False)
        check("analyze-file exit 0", r.returncode == 0, r.stderr[-300:])
        check("analyze-file cross-check", "system zlib inflate: ok" in r.stdout)
    finally:
        os.unlink(gz)
    # analyze-file: a PNG whose IDAT is a zlib stream (image header + deflate)
    # 8x8 RGBA, interlace 0: each scanline is 1 filter byte + 8*4 pixel bytes.
    row_width = 1 + 8 * 4
    png_data = bytearray()
    for scan in range(8):
        png_data.append(scan % 5)  # per-scanline filter type
        png_data.extend(b"\x00" * (row_width - 1))
    ihdr = (8).to_bytes(4, "big") + (8).to_bytes(4, "big") + bytes([8, 6, 0, 0, 0])
    png = (z.PNG_SIGNATURE + _png_chunk(b"IHDR", ihdr)
           + _png_chunk(b"IDAT", zlib.compress(bytes(png_data)))
           + _png_chunk(b"IEND", b""))
    pngf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cli_smoke.png")
    with open(pngf, "wb") as fh:
        fh.write(png)
    try:
        r = subprocess.run([sys.executable, tool, "analyze-file", pngf],
                           capture_output=True, text=True, check=False)
        check("analyze-file png exit 0", r.returncode == 0, r.stderr[-300:])
        check("analyze-file png header", "=== png:" in r.stdout)
        check("analyze-file png filters", "filters:" in r.stdout)
        check("analyze-file png deflate", "system zlib inflate: ok" in r.stdout)
    finally:
        os.unlink(pngf)
    # analyze-file: a ZIP with one deflate entry and one stored entry
    base = os.path.dirname(os.path.abspath(__file__))
    zipf = os.path.join(base, "_cli_smoke.zip")
    zip_data = _make_zip([("one.txt", b"the quick brown fox jumps " * 40,
                           z.ZIP_METHOD_DEFLATE),
                          ("two.bin", b"\x00" * 64, z.ZIP_METHOD_STORED)])
    with open(zipf, "wb") as fh:
        fh.write(zip_data)
    try:
        r = subprocess.run([sys.executable, tool, "analyze-file", zipf],
                           capture_output=True, text=True, check=False)
        check("analyze-file zip exit 0", r.returncode == 0, r.stderr[-300:])
        check("analyze-file zip header", "=== zip:" in r.stdout)
        check("analyze-file zip entries", "1 deflate, 1 stored" in r.stdout)
        check("analyze-file zip aggregate", "=== aggregate deflate" in r.stdout)
        check("analyze-file zip per-entry", "=== per-entry" in r.stdout)
        check("analyze-file zip cross-check", "system zlib inflate: ok" in r.stdout)
        check("analyze-file zip huff-symbols default",
              "symbols by frequency" in r.stdout)
        r = subprocess.run([sys.executable, tool, "analyze-file", zipf,
                            "--no-huff-symbols"], capture_output=True, text=True,
                           check=False)
        check("analyze-file zip no-huff-symbols",
              "symbols by frequency" not in r.stdout)
    finally:
        os.unlink(zipf)
    # analyze-file: an all-stored ZIP has no deflate to analyze
    with open(zipf, "wb") as fh:
        fh.write(_make_zip([("x.bin", b"\x01\x02\x03" * 10,
                             z.ZIP_METHOD_STORED)]))
    try:
        r = subprocess.run([sys.executable, tool, "analyze-file", zipf],
                           capture_output=True, text=True, check=False)
        check("analyze-file zip stored exit 0",
              r.returncode == 0, r.stderr[-300:])
        check("analyze-file zip no deflate", "no deflate entries" in r.stdout)
    finally:
        os.unlink(zipf)
    # a ZIP whose central-directory usize is corrupted is rejected
    one_deflate = _make_zip([("one.txt", b"the quick brown fox jumps " * 40,
                              z.ZIP_METHOD_DEFLATE)])
    bad = bytearray(one_deflate)
    struct.pack_into("<I", bad, bad.rfind(z.ZIP_CDH_MAGIC) + 24, 999999)
    with open(zipf, "wb") as fh:
        fh.write(bytes(bad))
    try:
        r = subprocess.run([sys.executable, tool, "analyze-file", zipf],
                           capture_output=True, text=True, check=False)
        check("analyze-file zip bad usize",
              r.returncode != 0 and "usize" in r.stderr, r.stderr[-200:])
    finally:
        os.unlink(zipf)
    # diff: the same library on both sides must produce identical output
    r = subprocess.run([sys.executable, tool, "diff", "--lib", LIB, DATA],
                       capture_output=True, text=True, check=False)
    check("diff exit 0", r.returncode == 0, r.stderr[-300:])
    check("diff identical", "identical" in r.stdout)
    check("diff economics table",
          "=== match economics (cost vs benefit, A vs B) ===" in r.stdout,
          r.stdout[-600:])
    check("diff cost map",
          "=== match cost map (A vs B, encoding buckets, bits / matched byte) ==="
          in r.stdout and "shared max cell = " in r.stdout, r.stdout[-600:])
    check("diff analyze hint", "use analyze mode" in r.stdout, r.stdout[-300:])
    # diff shows the side-by-side A vs B map (forced color on)
    r = subprocess.run([sys.executable, tool, "diff", "--lib", LIB, DATA,
                        "--map-colors-on"], capture_output=True, text=True,
                       check=False)
    check("diff map header",
          "=== match distance x length map (A vs B, encoding buckets) ===" in r.stdout,
          r.stderr[-300:])
    check("diff map shared max", "shared max cell = " in r.stdout)
    check("diff map colors on", "\x1b[38;5;" in r.stdout)
    # --json: machine-parseable output for all four modes
    import json

    def jrun(argv, label):
        r = subprocess.run([sys.executable, tool] + argv, capture_output=True,
                           text=True, check=False)
        check(f"{label} --json exit 0", r.returncode == 0, r.stderr[-300:])
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            check(f"{label} --json parses", False, r.stdout[:200])
            return None

    adoc = jrun(["analyze", "--lib", LIB, DATA, "--json"], "analyze")
    check("analyze json shape", adoc is not None and adoc["mode"] == "analyze"
          and "stats" in adoc and "economics" in adoc, str(adoc)[:200])
    check("analyze json hist capped at 50",
          adoc is not None
          and len(adoc["stats"]["dist_hist"]) <= 50
          and len(adoc["stats"]["pair_hist"]) <= 50
          and len(adoc["economics"]["cost_hist"]) <= 50,
          f"{adoc and len(adoc['stats']['dist_hist'])}")
    check("analyze json truncation note",
          adoc is not None and "_truncated" in adoc["stats"],
          str(adoc and adoc["stats"].get("_truncated")))
    adoc_full = jrun(["analyze", "--lib", LIB, DATA, "--json", "--json-full"],
                     "analyze --json-full")
    check("analyze json-full hist uncapped",
          adoc_full is not None
          and len(adoc_full["stats"]["dist_hist"]) > 50
          and "_truncated" not in adoc_full["stats"],
          f"{adoc_full and len(adoc_full['stats']['dist_hist'])}")
    with open(DATA, "rb") as src_file:
        raw = src_file.read()
    jgz = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_cli_smoke_json.gz")
    with open(jgz, "wb") as gz_file:
        gz_file.write(gzip.compress(raw))
    try:
        fdoc = jrun(["analyze-file", jgz, "--json"], "analyze-file")
        check("analyze-file json shape", fdoc is not None
              and fdoc["mode"] == "analyze-file" and "stats" in fdoc
              and "economics" in fdoc, str(fdoc)[:200])
    finally:
        os.unlink(jgz)
    ddoc = jrun(["diff", "--lib", LIB, DATA, "--json"], "diff")
    check("diff json shape", ddoc is not None and ddoc["mode"] == "diff"
          and "a" in ddoc and "b" in ddoc and "regions" in ddoc, str(ddoc)[:200])
    sdoc = jrun(["diff", "--lib", LIB, DATA, "--sweep", "--json"], "diff sweep")
    check("sweep json shape", sdoc is not None and sdoc["mode"] == "diff-sweep"
          and len(sdoc["rows"]) == 9, str(sdoc)[:200])


def test_cli_version():
    """The CLI reports its version via --version and shows it in --help."""
    print("cli version")
    tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zanalyze.py")
    r = subprocess.run([sys.executable, tool, "--version"],
                       capture_output=True, text=True, check=False)
    check("version flag exit 0", r.returncode == 0, r.stderr[-200:])
    check("version flag format", "zanalyze.py 1.00" in r.stdout.strip(), r.stdout)
    h = subprocess.run([sys.executable, tool, "--help"],
                       capture_output=True, text=True, check=False)
    check("version in --help", "zanalyze.py 1.00" in h.stdout, h.stdout[-300:])


def main():
    """Run all tests and report pass/fail; return 1 on any failure."""
    test_bitreader()
    test_progress()
    test_build_huffman_fixed()
    test_stored_block()
    test_crafted_match_stream()
    test_cross_check_python_zlib()
    test_wrapper_split()
    test_inflate_check()
    test_ctypes_binding()
    test_detect_wrapper()
    test_parse_png()
    test_png_filter_stats()
    test_parse_zip()
    test_aggregate_analyses()
    test_zip_real_files()
    test_zip_progress()
    test_parse_libs()
    test_divergences()
    test_first_byte_diff()
    test_histograms()
    test_match_map()
    test_window_size()
    test_huffman()
    test_match_costs()
    test_event_bounds()
    test_cost_map_grid()
    test_cost_level_fixed()
    test_cost_cell_scaling()
    test_compact_json()
    test_metrics_diff()
    test_economics_diff_rows()
    test_cost_map_diff()
    test_match_economics_render()
    test_region_effect()
    test_cli_smoke()
    test_cli_version()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURES: {FAILURES}")
        return 1
    print("all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
