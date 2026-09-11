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
"""zanalyze - analyze and diff the deflate streams produced by zlib(-ng) libraries.

Compresses a file with a given zlib(-ng) shared library and reports the
compressor's decisions: every match (length + distance) and the run of
literals before each match (opt-in via --events), plus a summary, histograms
of match length and distance frequencies, and a Huffman-coding report
(actual vs entropy bits, bit budget, and optionally per-symbol detail).

Can also compress the same file with two different libraries (or the same
library with different options) and show only the divergent regions of the
decision streams, side-by-side, along with a side-by-side Huffman report.

A third mode (analyze-file) analyzes an existing .gz/.zlib/.def stream (or a
.png's IDAT deflate stream, also reporting the image header, or the deflate
entries of a .zip/.jar/.apk, aggregated across entries and showing per-entry
stats), recovering the original input with system zlib and cross-checking the
internal parser against it (no library is needed to compress).

Examples:
  zanalyze.py analyze --lib build-develop/libz-ng.so file.bin
  zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --level 3 --events
  zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --no-huff-symbols
  zanalyze.py analyze-file file.gz --window-bits 15
  zanalyze.py analyze-file image.png
  zanalyze.py analyze-file archive.zip
  zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so file.bin
  zanalyze.py diff --lib build-develop/libz-ng.so file.bin --window-bits 15,12
  zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so file.bin --sweep
"""

import argparse
import bisect
import ctypes
import json
import math
import os
import sys
import time
from collections import Counter

__version__ = "1.00"

Z_OK = 0
Z_STREAM_END = 1
Z_DEFLATED = 8
Z_FINISH = 4

STRATEGY_NAMES = {
    "default": 0,
    "filtered": 1,
    "huffman_only": 2,
    "rle": 3,
    "fixed": 4,
}
STRATEGY_LABELS = {v: k for k, v in STRATEGY_NAMES.items()}

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_COLOR_TYPES = {0: "grayscale", 2: "rgb", 3: "palette",
                   4: "grayscale+alpha", 6: "rgb+alpha"}
PNG_FILTER_NAMES = {0: "none", 1: "sub", 2: "up",
                    3: "average", 4: "paeth"}
# Samples per pixel by color type (PNG section 2.3).
_PNG_SAMPLES_PER_PIXEL = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
# Adam7 passes as (start_x, start_y, step_x, step_y) (PNG section 2.6).
_PNG_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8),
             (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2),
             (0, 1, 1, 2))

# ZIP (PK) archive magic numbers (local file header, central directory file
# header, end of central directory) and the compression methods we recognize.
ZIP_LOCAL_MAGIC = b"\x50\x4b\x03\x04"
ZIP_CDH_MAGIC = b"\x50\x4b\x01\x02"
ZIP_EOCD_MAGIC = b"\x50\x4b\x05\x06"
ZIP_METHOD_STORED = 0
ZIP_METHOD_DEFLATE = 8

RTLD_NOW = 0x2
RTLD_LOCAL = 0x1
RTLD_DEEPBIND = 0x8


# ---------------------------------------------------------------------------
# ctypes binding to the zlib(-ng) C API
# ---------------------------------------------------------------------------

class z_stream(ctypes.Structure):
    """ctypes mirror of the zlib ``z_stream`` struct (zlib.h)."""

    _fields_ = [
        ("next_in", ctypes.c_void_p),
        ("avail_in", ctypes.c_uint),
        ("total_in", ctypes.c_ulong),
        ("next_out", ctypes.c_void_p),
        ("avail_out", ctypes.c_uint),
        ("total_out", ctypes.c_ulong),
        ("msg", ctypes.c_char_p),
        ("state", ctypes.c_void_p),
        ("zalloc", ctypes.c_void_p),
        ("zfree", ctypes.c_void_p),
        ("opaque", ctypes.c_void_p),
        ("data_type", ctypes.c_int),
        ("adler", ctypes.c_ulong),
        ("reserved", ctypes.c_ulong),
    ]


class zng_stream(ctypes.Structure):
    """ctypes mirror of zlib-ng's native ``zng_stream`` struct (zlib-ng.h).

    Differs from ``z_stream`` in that ``adler`` is ``uint32_t`` (not ``uLong``),
    so ``sizeof`` is 104 instead of 112 on 64-bit platforms."""

    _fields_ = [
        ("next_in", ctypes.c_void_p),
        ("avail_in", ctypes.c_uint),
        ("total_in", ctypes.c_size_t),
        ("next_out", ctypes.c_void_p),
        ("avail_out", ctypes.c_uint),
        ("total_out", ctypes.c_size_t),
        ("msg", ctypes.c_char_p),
        ("state", ctypes.c_void_p),
        ("zalloc", ctypes.c_void_p),
        ("zfree", ctypes.c_void_p),
        ("opaque", ctypes.c_void_p),
        ("data_type", ctypes.c_int),
        ("adler", ctypes.c_uint),
        ("reserved", ctypes.c_ulong),
    ]


def _fn(lib, name):
    """Return ``lib.<name>`` or None if the symbol is not exported."""
    try:
        return getattr(lib, name)
    except AttributeError:
        return None


def _version_bytes(lib, *names):
    """Return the C string a version function points to, or None if the first
    of ``names`` that is exported returns one."""
    for name in names:
        fn = _fn(lib, name)
        if fn is not None:
            fn.restype = ctypes.c_char_p
            return fn()
    return None


class ZlibLib:
    """A zlib(-ng) shared library loaded with RTLD_LOCAL|DEEPBIND so that
    several versions can coexist in one process."""

    def __init__(self, path):
        """Load the library and bind the deflate entry points.

        Exits if the file is missing, fails to load, or lacks the deflate
        symbols. ``self.prefix`` is ``zng_`` for zlib-ng builds that export
        both plain and zng_ names, so several builds can coexist per process."""
        if not os.path.isfile(path):
            raise SystemExit(f"error: library not found: {path}")
        flags = RTLD_NOW | RTLD_LOCAL
        if sys.platform.startswith("linux"):
            flags |= RTLD_DEEPBIND
        self.path = os.path.abspath(path)
        try:
            self.lib = ctypes.CDLL(self.path, mode=flags)
        except OSError as e:
            raise SystemExit(f"error: cannot load {path}: {e}") from e
        self.prefix = "zng_" if _fn(self.lib, "zng_deflate") is not None else ""
        # zlib-ng native uses a distinct stream struct (zng_stream) whose adler
        # field is uint32, so pick the ctypes mirror matching the symbol prefix.
        self.stream_type = zng_stream if self.prefix else z_stream
        # deflateInit2 is a C macro; the real ABI-stable symbol is
        # deflateInit2_ (exported by zlib, zlib-ng compat, and zlib-ng native),
        # so bind that rather than the 6-arg macro name.
        for name in ("deflateInit2_", "deflate", "deflateBound", "deflateEnd"):
            if _fn(self.lib, self.prefix + name) is None:
                raise SystemExit(
                    f"error: {path} does not export '{self.prefix}{name}'")
        self.fns = {name: _fn(self.lib, self.prefix + name)
                    for name in ("deflateInit2_", "deflate", "deflateBound",
                                 "deflateEnd")}
        fns = self.fns
        stream = self.stream_type
        fns["deflateInit2_"].argtypes = [ctypes.POINTER(stream), ctypes.c_int,
                                         ctypes.c_int, ctypes.c_int,
                                         ctypes.c_int, ctypes.c_int,
                                         ctypes.c_char_p, ctypes.c_int]
        fns["deflate"].argtypes = [ctypes.POINTER(stream), ctypes.c_int]
        fns["deflateEnd"].argtypes = [ctypes.POINTER(stream)]
        fns["deflateBound"].argtypes = [ctypes.POINTER(stream), ctypes.c_ulong]
        fns["deflateBound"].restype = ctypes.c_ulong
        for name in ("deflateInit2_", "deflate", "deflateEnd"):
            fns[name].restype = ctypes.c_int

        # Version strings: zlib-ng reports via zlibng_version (native "2.x")
        # and/or the emulated zlibVersion ("1.x"); plain zlib has only the
        # latter. Store whichever exist and build a display string that shows
        # both for a zlib-ng build that exposes both.
        zng = _version_bytes(self.lib, "zlibng_version", "zng_zlibng_version")
        zver = _version_bytes(self.lib, "zlibVersion")
        self.zng_version = zng.decode() if zng is not None else None
        self.zlib_version = zver.decode() if zver is not None else None
        if self.zng_version is not None:
            if self.zlib_version is not None:
                self.version = (f"zlib-ng {self.zng_version} "
                                f"(emulating zlib {self.zlib_version})")
            else:
                self.version = f"zlib-ng {self.zng_version}"
        elif self.zlib_version is not None:
            self.version = f"zlib {self.zlib_version}"
        else:
            self.version = "unknown"
        # deflateInit2_ checks version[0] against the library's own version
        # (ZLIB_VERSION "1.2.x" for zlib/compat, ZLIBNG_VERSION "2.x" for
        # native) and stream_size against sizeof(stream); use the version the
        # library reports so the leading char always matches.
        if self.prefix:
            self._init_version = (_version_bytes(self.lib, "zlibng_version",
                                                 "zng_zlibng_version")
                                  or b"2.0.0")
        else:
            self._init_version = _version_bytes(self.lib, "zlibVersion") or b"1.2.0"

    @property
    def label(self):
        """Basename of the library path (compact id for reports)."""
        return os.path.basename(self.path)

    def compress(self, data, level, window_bits=15, mem_level=8, strategy=0):
        """Compress ``data`` in one ``deflate(Z_FINISH)`` call; return the
        wrapper-including compressed bytes."""
        fns = self.fns
        strm = self.stream_type()
        rc = fns["deflateInit2_"](ctypes.byref(strm), level, Z_DEFLATED,
                                  window_bits, mem_level, strategy,
                                  self._init_version,
                                  ctypes.sizeof(self.stream_type))
        if rc != Z_OK:
            raise RuntimeError(
                f"{self.label}: deflateInit2_ failed (rc={rc})")
        try:
            bound = fns["deflateBound"](None, len(data))
            out = ctypes.create_string_buffer(bound)
            strm.next_in = ctypes.cast(data, ctypes.c_void_p)
            strm.avail_in = len(data)
            strm.next_out = ctypes.cast(out, ctypes.c_void_p)
            strm.avail_out = bound
            rc = fns["deflate"](ctypes.byref(strm), Z_FINISH)
            if rc != Z_STREAM_END:
                raise RuntimeError(f"{self.label}: deflate failed (rc={rc})")
            return out.raw[:strm.total_out]
        finally:
            fns["deflateEnd"](ctypes.byref(strm))


# ---------------------------------------------------------------------------
# Deflate stream format
# ---------------------------------------------------------------------------

LENGTH_BASE = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
               35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258)
LENGTH_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0)
DIST_BASE = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
             257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
             8193, 12289, 16385, 24577)
DIST_EXTRA = (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
              7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13)
CODE_LEN_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)

# fixed lit/len tree: 0-143:8, 144-255:9, 256-279:7, 280-287:8
FIXED_LITLEN = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
FIXED_DIST = [5] * 30

# histogram bar glyphs: full block tiles seamlessly; eighths give sub-cell fill
BLOCK = "\u2588"          # full block
EIGHTH = "\u258f\u258e\u258d\u258c\u258b\u258a\u2589"  # 1/8 .. 7/8 (bottom fill)

# match distance x length map: 7 fill levels (index 0 = blank), a triple-
# vertical ruler marker, and the linear-axis grid size + pow2 tick values.
MAP_GLYPH = " \u00b7\u25aa\u2591\u2592\u2593\u2588"  # blank, 1/6 .. 1 (low to high)
MAP_MARKER = "\u2503"  # box-drawings triple vertical: marks an exact tick column
MAP_LIN_ROWS = 40
MAP_LIN_COLS = 56
MAP_TICKS_ENC = (1, 8, 64, 512, 4096, 32768)  # every-3rd pow2, fits 30 dist codes
MAP_TICKS_LIN = (1, 2048, 4096, 8192, 16384, 32768)  # pow2 that fit 56 columns
# xterm-256 color ramp for the map: 30 steps from cool (low) to hot (high),
# five per density glyph (the 234 blank / zero floor is separate, see
# MAP_BG_BLANK).
MAP_THERMAL = (17, 18, 19, 21, 27, 33, 39, 45, 51, 50, 49, 48, 47, 46, 82, 83,
                118, 119, 154, 155, 191, 227, 226, 220, 214, 208, 202, 166,
                160, 196)
# TERM values that imply a 256-color terminal (used to auto-enable map color).
_MAP_COLOR_TERMS = {"xterm-256color", "putty-256color"}
# box-drawing frame around the map's cell area (top + sides only; the ruler
# line beneath the last row is left open), plus the xterm colors for a blank
# (zero-count) cell and the dim frame.
MAP_TOP_LEFT = "\u250c"   # ┌
MAP_TOP_RIGHT = "\u2510"  # ┐
MAP_SIDE = "\u2502"       # │
MAP_H = "\u2500"          # ─
MAP_BG_BLANK = 234        # dark neutral background for a zero-count cell
MAP_FRAME_COLOR = 240     # dim gray for the frame in color mode
COST_MAX_BITS = 8.0       # the cost map's fixed linear scale, in bits/byte
MAP_OVERPAID = 231        # bright white, for cost cells over COST_MAX_BITS
# ANSI SGR sequences: a background-only cell (blank cells / the blank legend
# swatch), a foreground+background cell set to the same color (heat cells, so
# the glyph is invisible in color but remains once the codes are stripped), and
# the reset to default.
_MAP_ANSI_BG = "\x1b[48;5;{}m"
_MAP_ANSI_FG_BG = "\x1b[38;5;{};48;5;{}m"
_MAP_ANSI_RESET = "\x1b[0m"


def _code_map(base, extra, cap=None):
    """Map each representable value -> its base code index.

    Inverse of ``base[i] + offset`` for ``offset < 2**extra[i]`` (optionally
    capped by ``cap``); used to recover the extra-bit count a given match
    length/distance contributes to the stream."""
    mapping = {}
    for i in range(len(base)):
        for offset in range(1 << extra[i]):
            value = base[i] + offset
            if cap is None or value <= cap:
                mapping[value] = i
    return mapping


# match length / distance -> code index (for the bit-budget extra-bit counts)
LEN_CODE_OF = _code_map(LENGTH_BASE, LENGTH_EXTRA, 258)
DIST_CODE_OF = _code_map(DIST_BASE, DIST_EXTRA)


class DeflateError(Exception):
    """Raised when a deflate stream is malformed or fails to reconstruct."""


class BitReader:
    """LSB-first bit cursor over a bytes buffer.

    ``pos`` is the next bit to read, counted from the start of the buffer;
    within each byte the low bit is bit 0 (deflate's on-the-wire order).

    Reads are served from a small cached window: the little-endian integer of
    the 8 bytes covering the byte the cursor is in is built once per byte and
    reused by every bit read landing in it, so decoding is one shift-and-mask
    per read instead of an ``int.from_bytes`` each time."""
    __slots__ = ("_cache", "_cache_byte", "data", "nbits", "pos")

    def __init__(self, data):
        """Wrap ``data``; the cursor starts before the first bit."""
        self.data = data
        self.pos = 0
        self.nbits = len(data) * 8
        self._cache_byte = -1
        self._cache = 0

    def _refill(self):
        """Rebuild the cached 8-byte window at the byte the cursor is in.

        Eight bytes (64 bits) always cover any read: the in-byte offset is at
        most 7 and a read takes at most 16 bits, so ``offset + n`` never
        exceeds 23 and stays inside the window."""
        byte_index = self.pos >> 3
        self._cache_byte = byte_index
        self._cache = int.from_bytes(self.data[byte_index:byte_index + 8],
                                     "little")

    def read(self, n):
        """Read ``n`` bits (LSB-first) and advance the cursor by ``n``."""
        if (self.pos >> 3) != self._cache_byte:
            self._refill()
        bit_off = self.pos & 7
        self.pos += n
        return (self._cache >> bit_off) & ((1 << n) - 1)

    def align_byte(self):
        """Advance to the next byte boundary (no-op if already aligned)."""
        if self.pos & 7:
            self.pos += 8 - (self.pos & 7)

    def pushback(self, n):
        """Move the cursor back by ``n`` bits so the next reads return them.

        The window is always rebuilt from ``data`` and keyed on the byte the
        cursor is in, so rewinding within the region already read needs no
        cache fix-up: the following ``read`` re-reads the pushed bits either
        from the still-valid window or by refilling the new byte. Used by the
        table decoder, where a fixed-width grab may run past the code's end."""
        self.pos -= n


def build_huffman(lengths):
    """Canonical Huffman code -> {length: {code: symbol}} tables."""
    bl_count = [0] * 16
    for length in lengths:
        if 0 < length < 16:
            bl_count[length] += 1
    bl_count[0] = 0
    code = 0
    first = [0] * 16
    for bits in range(1, 16):
        # Canonical codes: the base code for length L is
        # (base code for L-1 + count of length L-1) << 1; within a length the
        # codes are sequential (next free code tracked by first[length]).
        code = (code + bl_count[bits - 1]) << 1
        first[bits] = code
    tables = [None] * 16
    for sym, length in enumerate(lengths):
        if length:
            table = tables[length]
            if table is None:
                table = tables[length] = {}
            table[first[length]] = sym
            first[length] += 1
    return tables


def _bitrev(x, k):
    """Reverse the low ``k`` bits of ``x`` (bit 0 <-> bit k-1)."""
    r = 0
    for _ in range(k):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _build_decode_table(tables):
    """Build a single-level, bit-reversed decode table for a Huffman tree.

    Returns ``(L, table)`` where ``L`` is the tree's actual maximum code length
    and ``table`` is a list indexed by the L-bit LSB-first grab. Each entry
    packs ``(symbol << 16) | code_length``. ``L`` is the true max length, so a
    grab reads exactly the longest code's bits and any shorter code leaves the
    high bits as the start of the next symbol (which the caller pushes back).
    Shorter codes are tiled across every value that extends them so they
    resolve no matter what the over-read grabbed."""
    L = 0
    for k in range(15, 0, -1):
        if tables[k]:
            L = k
            break
    if L == 0:
        raise DeflateError("empty Huffman tree")
    table = [0] * (1 << L)
    for k in range(1, L + 1):
        t = tables[k]
        if not t:
            continue
        for code, sym in t.items():
            # Index by the bit-reversed code so an LSB-first grab lands on it
            # directly; then fill every longer value sharing this prefix.
            rev = _bitrev(code, k)
            entry = (sym << 16) | k
            for extra in range(1 << (L - k)):
                table[rev | (extra << k)] = entry
    return L, table


class _Decoder:
    """Decodes one fixed/dynamic block using a prebuilt Huffman table pair.

    ``lit_freq``/``dist_freq`` (optional) accumulate per-symbol counts while
    decoding so the Huffman efficiency report is computed in one pass."""
    __slots__ = (
        "_decode_cache",
        "br",
        "dist_freq",
        "dist_tables",
        "lit_freq",
        "lit_tables",
        "on_progress",
    )

    def __init__(self, br, lit_tables, dist_tables,
                 lit_freq=None, dist_freq=None, on_progress=None):
        """Bind the bit reader, Huffman table pairs, optional freq counters,
        and an optional ``on_progress(done)`` callback reported from block()."""
        self.br = br
        self.lit_tables = lit_tables
        self.dist_tables = dist_tables
        self.lit_freq = lit_freq
        self.dist_freq = dist_freq
        self.on_progress = on_progress
        self._decode_cache = {}

    def symbol(self, tables):
        """Decode one Huffman symbol via a per-tree single-level lookup table.

        The table is built (bit-reversed, one entry per possible L-bit grab) on
        first use and cached per decoder, where L is the tree's own maximum code
        length. A grab reads the full L-bit window; a shorter code pushes the
        over-read bits back for the next symbol."""
        key = id(tables)
        cached = self._decode_cache.get(key)
        if cached is None:
            L, table = _build_decode_table(tables)
            # Keep a reference to the tables object so its id (the cache key)
            # cannot be reused by a different tree for this decoder's lifetime.
            cached = self._decode_cache[key] = (L, table, tables)
        br = self.br
        L, table, _tables = cached
        val = br.read(L)
        packed = table[val]
        if packed == 0:
            raise DeflateError("invalid Huffman code")
        k = packed & 0xFFFF
        if L != k:
            br.pushback(L - k)
        return packed >> 16

    def block(self, src, events, out):
        """Decode one fixed/dynamic block. out is a bytearray extended in place."""
        br = self.br
        lit_tables = self.lit_tables
        dist_tables = self.dist_tables
        lit_freq, dist_freq = self.lit_freq, self.dist_freq
        on_progress = self.on_progress
        # Report progress at most once per 64 KiB of decoded output; a crossing
        # gate (not an exact multiple) so long matches cannot skip over it. The
        # per-block threshold resets each block, at worst re-firing a few
        # throttled updates at block boundaries.
        next_report = 0x10000
        # each symbol emits >= 1 output byte, so a valid stream can never
        # contain more symbols than output bytes
        limit = len(src) + 1
        for _ in range(limit):
            sym = self.symbol(lit_tables)
            if lit_freq is not None:
                lit_freq[sym] += 1
            if sym < 256:
                out.append(sym)
                _append_lit(events)
            elif sym == 256:
                return
            else:
                len_idx = sym - 257
                length = LENGTH_BASE[len_idx] + br.read(LENGTH_EXTRA[len_idx])
                dsym = self.symbol(dist_tables)
                if dist_freq is not None:
                    dist_freq[dsym] += 1
                dist = DIST_BASE[dsym] + br.read(DIST_EXTRA[dsym])
                _append_match(out, events, length, dist)
            if on_progress is not None and len(out) >= next_report:
                on_progress(len(out))
                next_report += 0x10000
        raise DeflateError("block has more symbols than input bytes")


def _append_lit(events):
    """Extend the trailing literal-run event, or start a new one."""
    if events and events[-1][0] == "L":
        events[-1][1] += 1
    else:
        events.append(["L", 1])


def _append_match(out, events, length, dist):
    """Append a match's bytes to ``out`` and record an ["M", length, dist] event.

    The first ``min(dist, length)`` bytes are a plain copy (the match cannot
    yet overlap itself); the remainder is copied byte-by-byte so overlapping
    matches (dist < length) expand correctly."""
    pos = len(out)
    if dist > pos:
        raise DeflateError(f"match at offset {pos} has dist {dist} > pos")
    start = pos - dist
    plain_copy = min(length, dist)
    out += out[start:start + plain_copy]
    for i in range(plain_copy, length):
        out.append(out[pos + i - dist])
    events.append(["M", length, dist])


def parse_deflate(data, src, verify=True, on_progress=None):
    """Parse a raw deflate stream.
    Returns (blocks, events, block_trees).
    blocks: list of "stored"|"fixed"|"dynamic"
    events: list of ["L", count] or ["M", length, dist], partitioning src.
    block_trees: one record per block; stored -> {"type","bytes"},
        fixed/dynamic -> {"type","lit_len","dist_len","lit_freq","dist_freq"}.
        Every record also carries "ev_start"/"ev_end", the half-open span of
        event indices the block covers, so a match's code lengths come from its
        own block's tree.
    If verify, the stream is replayed and must reproduce src exactly.
    If on_progress, it is called with the running decoded byte count (roughly
    every 64 KiB) so a caller can drive a progress bar.
    """
    br = BitReader(data)
    blocks = []
    events = []
    trees = []
    out = bytearray()
    bfinal = 0
    while not bfinal:
        bfinal = br.read(1)
        btype = br.read(2)
        if btype == 0:
            br.align_byte()
            length = br.read(16)
            n_length = br.read(16)
            if length != (~n_length & 0xFFFF):
                raise DeflateError(f"stored block length mismatch "
                                   f"({length} vs {n_length})")
            bytepos = br.pos >> 3
            chunk = data[bytepos:bytepos + length]
            if len(chunk) != length:
                raise DeflateError("stored block extends past end of stream")
            br.pos += length * 8
            if verify:
                out += chunk
                if on_progress is not None:
                    on_progress(len(out))
            events.append(["L", length])
            blocks.append("stored")
            trees.append({"type": "stored", "bytes": length,
                          "ev_start": len(events) - 1, "ev_end": len(events)})
        elif btype == 1:
            blocks.append("fixed")
            lit_len, dist_len = FIXED_LITLEN, FIXED_DIST
            start = len(events)
            dec = _Decoder(br, build_huffman(lit_len),
                           build_huffman(dist_len),
                           lit_freq=[0] * len(lit_len),
                           dist_freq=[0] * len(dist_len),
                           on_progress=on_progress)
            dec.block(src, events, out)
            trees.append({"type": "fixed", "lit_len": lit_len,
                          "dist_len": dist_len, "lit_freq": dec.lit_freq,
                          "dist_freq": dec.dist_freq,
                          "ev_start": start, "ev_end": len(events)})
        elif btype == 2:
            hlit = br.read(5) + 257
            hdist = br.read(5) + 1
            hclen = br.read(4) + 4
            cl_lengths = [0] * 19
            for i in range(hclen):
                cl_lengths[CODE_LEN_ORDER[i]] = br.read(3)
            cl_tables = build_huffman(cl_lengths)
            lengths: list[int] = []
            dec = _Decoder(br, cl_tables, None)
            # Decode HLIT+HDIST code lengths, expanding the repeat codes:
            # 16 = repeat previous 3-6 times, 17 = 3-10 zeros, 18 = 11-138 zeros.
            while len(lengths) < hlit + hdist:
                sym = dec.symbol(cl_tables)
                if sym < 16:
                    lengths.append(sym)
                elif sym == 16:
                    if not lengths:
                        raise DeflateError("repeat code with no previous length")
                    rep = br.read(2) + 3
                    lengths.extend([lengths[-1]] * rep)
                elif sym == 17:
                    rep = br.read(3) + 3
                    lengths.extend([0] * rep)
                else:
                    rep = br.read(7) + 11
                    lengths.extend([0] * rep)
            if len(lengths) != hlit + hdist:
                raise DeflateError("too many code lengths decoded")
            blocks.append("dynamic")
            lit_len, dist_len = lengths[:hlit], lengths[hlit:]
            start = len(events)
            dec = _Decoder(br, build_huffman(lit_len),
                           build_huffman(dist_len),
                           lit_freq=[0] * len(lit_len),
                           dist_freq=[0] * len(dist_len),
                           on_progress=on_progress)
            dec.block(src, events, out)
            trees.append({"type": "dynamic", "lit_len": lit_len,
                          "dist_len": dist_len, "lit_freq": dec.lit_freq,
                          "dist_freq": dec.dist_freq,
                          "ev_start": start, "ev_end": len(events)})
        else:
            raise DeflateError(f"bad block type {btype}")
    if br.pos > br.nbits or br.nbits - br.pos > 7:
        raise DeflateError("trailing data after final block")
    if verify:
        if len(out) != len(src):
            raise DeflateError(f"stream reconstructs {len(out)} bytes, "
                               f"input is {len(src)}")
        if out != src:
            raise DeflateError("stream does not reconstruct the input data")
    return blocks, events, trees


# ---------------------------------------------------------------------------
# Wrapper handling (zlib / gzip / raw)
# ---------------------------------------------------------------------------

def _gzip_deflate_offset(comp):
    """Byte offset where the deflate data starts in a gzip stream.

    Skips the 10-byte base header, then the optional fields (FEXTRA, FNAME,
    FCOMMENT, FHCRC) in the order they appear on disk."""
    if len(comp) < 18 or comp[0] != 0x1F or comp[1] != 0x8B or comp[2] != 8:
        raise DeflateError("bad gzip header")
    flags = comp[3]
    pos = 10
    if flags & 4:   # FEXTRA
        xlen = int.from_bytes(comp[10:12], "little")
        pos += 2 + xlen
    if flags & 8:   # FNAME
        pos = comp.index(0, pos) + 1
    if flags & 16:  # FCOMMENT
        pos = comp.index(0, pos) + 1
    if flags & 2:   # FHCRC
        pos += 2
    return pos


def split_wrapper(comp, window_bits):
    """Split a compressed stream into (deflate_bytes, wrapper, trailer).

    trailer is a list of (name, value) pairs parsed from the wrapper's
    trailer data (values are taken as stored, never recomputed):
      zlib: [("adler32", v)]
      gzip: [("crc32", v), ("isize", v)]
      raw:  []
    """
    if window_bits < 0:  # raw deflate, no wrapper
        return comp, "raw", []
    if window_bits > 15:  # gzip wrapper
        pos = _gzip_deflate_offset(comp)
        deflate = comp[pos:-8]
        crc = int.from_bytes(comp[-8:-4], "little")
        isize = int.from_bytes(comp[-4:], "little")
        return deflate, "gzip", [("crc32", crc), ("isize", isize)]
    if 8 <= window_bits <= 15:  # zlib wrapper
        if len(comp) < 6:
            raise DeflateError("compressed data too short for zlib wrapper")
        cmf, flags = comp[0], comp[1]
        if (cmf & 0x0F) != 8:
            raise DeflateError("zlib header: not deflate")
        if (cmf * 256 + flags) % 31 != 0:
            raise DeflateError("zlib header: bad check")
        adler = int.from_bytes(comp[-4:], "big")
        return comp[2:-4], "zlib", [("adler32", adler)]
    raise DeflateError(f"unsupported windowBits {window_bits}")


def detect_wrapper(comp):
    """Detect the wrapper from magic bytes. Returns (deflate, wrapper, trailer).

    gzip (1f 8b), then zlib (deflate CMF with valid header check), else raw.
    """
    if len(comp) >= 18 and comp[0] == 0x1F and comp[1] == 0x8B:
        pos = _gzip_deflate_offset(comp)
        crc = int.from_bytes(comp[-8:-4], "little")
        isize = int.from_bytes(comp[-4:], "little")
        return comp[pos:-8], "gzip", [("crc32", crc), ("isize", isize)]
    if len(comp) >= 6:
        cmf, flags = comp[0], comp[1]
        if (cmf & 0x0F) == 8 and (cmf * 256 + flags) % 31 == 0:
            adler = int.from_bytes(comp[-4:], "big")
            return comp[2:-4], "zlib", [("adler32", adler)]
    return comp, "raw", []


def fmt_trailer_value(name, value):
    """Format a trailer value: plain decimal for isize, hex for checksums."""
    return str(value) if name == "isize" else f"{value:#x}"


def window_size(wbits):
    """Nominal sliding-window size (and thus max match distance) for windowBits.

    8-15:   zlib wrapper,  window = 2**wbits
    16-31:  gzip wrapper,  window = 2**(wbits-16)
    -15--8: raw deflate,  window = 2**(-wbits)
    Returns None if windowBits is outside the supported ranges.

    Note: zlib-ng enforces a 512-byte minimum window and silently upgrades
    smaller ones (e.g. windowBits 8 -> a 512-byte window), so a stream made
    with windowBits 8 may legitimately contain distances up to 512 and will
    trip the window check against the nominal 256 here."""
    if wbits is None:
        return None
    if 8 <= wbits <= 15:
        return 1 << wbits
    if 16 <= wbits <= 31:
        return 1 << (wbits - 16)
    if -15 <= wbits <= -8:
        return 1 << (-wbits)
    return None


# ---------------------------------------------------------------------------
# PNG handling (IDAT deflate stream + image header)
# ---------------------------------------------------------------------------

def parse_png(data):
    """Parse a PNG file's chunks into (header, idat, n_idat).

    ``header`` is a dict of the IHDR fields (width, height, bit_depth,
    color_type, compression, filter, interlace); ``idat`` is the concatenation
    of all IDAT chunk payloads (a standard zlib stream); ``n_idat`` counts the
    IDAT chunks. Raises DeflateError on a bad signature, a missing IHDR, or no
    IDAT chunk."""
    if not data.startswith(PNG_SIGNATURE):
        raise DeflateError("not a PNG file (bad signature)")
    pos = len(PNG_SIGNATURE)
    header = None
    idat_parts = []
    while pos < len(data):
        if len(data) - pos < 8:
            raise DeflateError("truncated PNG chunk")
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        if len(payload) < length:
            raise DeflateError("truncated PNG chunk")
        pos += 8 + length + 4  # skip length + type + payload + crc
        if ctype == b"IHDR":
            if len(payload) != 13:
                raise DeflateError("bad IHDR chunk length")
            header = {
                "width": int.from_bytes(payload[0:4], "big"),
                "height": int.from_bytes(payload[4:8], "big"),
                "bit_depth": payload[8],
                "color_type": payload[9],
                "compression": payload[10],
                "filter": payload[11],
                "interlace": payload[12],
            }
        elif ctype == b"IDAT":
            idat_parts.append(payload)
        elif ctype == b"IEND":
            break
    if header is None:
        raise DeflateError("PNG has no IHDR chunk")
    if not idat_parts:
        raise DeflateError("PNG has no IDAT chunk")
    return header, b"".join(idat_parts), len(idat_parts)


def png_filter_stats(header, filtered):
    """Count the per-scanline filter types (0-4) of a decoded PNG's IDAT data.

    ``filtered`` is the decompressed IDAT: each scanline is preceded by a
    1-byte filter type (PNG sections 2.6/6.1). Returns (counts, n_rows) where
    counts is a Counter of filter-type -> scanline count, or None if the byte
    count does not match the declared dimensions (so no stats are shown)."""
    width, height = header["width"], header["height"]
    bit_depth, color_type, interlace = (header["bit_depth"],
                                        header["color_type"], header["interlace"])
    samples = _PNG_SAMPLES_PER_PIXEL.get(color_type)
    if samples is None:
        return None
    bits_per_pixel = samples * bit_depth
    plan: list[tuple[int, int]] = []
    if interlace == 0:
        row_width = (width * bits_per_pixel + 7) // 8
        plan.append((height, 1 + row_width))
    elif interlace == 1:
        for start_x, start_y, step_x, step_y in _PNG_ADAM7:
            if width <= start_x or height <= start_y:
                continue
            w_pass = (width - start_x + step_x - 1) // step_x
            h_pass = (height - start_y + step_y - 1) // step_y
            row_width = (w_pass * bits_per_pixel + 7) // 8
            plan.append((h_pass, 1 + row_width))
    else:
        return None
    if sum(scanlines * stride for scanlines, stride in plan) != len(filtered):
        return None
    counts: Counter[int] = Counter()
    offset = 0
    for scanlines, stride in plan:
        for _ in range(scanlines):
            counts[filtered[offset]] += 1
            offset += stride
    return counts, sum(scanlines for scanlines, _ in plan)


def print_png_header(header, n_idat, idat_size, name, filters=None):
    """Print the PNG image header (IHDR), IDAT layout, and the per-scanline
    filter-type distribution (when it could be determined from the data)."""
    ct = header["color_type"]
    print(f"=== png: {name} ===")
    print(f"  image:     {header['width']} x {header['height']}")
    print(f"  bit depth: {header['bit_depth']}")
    print(f"  color:     type {ct} ({PNG_COLOR_TYPES.get(ct, 'unknown')})")
    print(f"  interlace: {header['interlace']}")
    print(f"  idat:      {n_idat} chunk(s), {idat_size} bytes")
    if filters is None:
        print("  filters:   (not determined; data size != declared dimensions)")
        return
    counts, n_rows = filters
    parts = [f"{PNG_FILTER_NAMES.get(f, f'unknown {f}')}: {counts[f]}"
             for f in sorted(counts)]
    print(f"  filters:   {', '.join(parts)}  ({n_rows} scanlines)")


# ---------------------------------------------------------------------------
# ZIP handling (deflate entry analysis + per-entry basic stats)
# ---------------------------------------------------------------------------

def parse_zip(data):
    """Parse a ZIP/JAR/APK archive, returning a list of entry dicts.

    Reads the end-of-central-directory record (searched from the end of the
    file), then walks the central directory, which is the authoritative source
    for each entry's method, crc, and sizes. Each entry's compressed-data start
    is located from its local file header (30 + name_len + extra_len after the
    local header's start offset, whose own name/extra lengths are used, since
    they may differ from the central directory's). Returns a list of dicts with
    keys ``name``, ``method``, ``crc``, ``csize``, ``usize``, ``data_offset``.
    Raises DeflateError on a missing EOCD, a corrupt central directory, or a
    ZIP64 sentinel value (0xffffffff) in an entry size or local-header offset."""
    eocd = data.rfind(ZIP_EOCD_MAGIC)
    if eocd < 0 or eocd + 22 > len(data):
        raise DeflateError("not a zip file (no end-of-central-directory record)")
    n_entries = int.from_bytes(data[eocd + 10:eocd + 12], "little")
    cd_offset = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    entries = []
    pos = cd_offset
    for _ in range(n_entries):
        if pos + 46 > len(data) or data[pos:pos + 4] != ZIP_CDH_MAGIC:
            raise DeflateError(f"corrupt zip: bad central directory at offset {pos}")
        method = int.from_bytes(data[pos + 10:pos + 12], "little")
        crc = int.from_bytes(data[pos + 16:pos + 20], "little")
        csize = int.from_bytes(data[pos + 20:pos + 24], "little")
        usize = int.from_bytes(data[pos + 24:pos + 28], "little")
        name_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        extra_len = int.from_bytes(data[pos + 30:pos + 32], "little")
        comment_len = int.from_bytes(data[pos + 32:pos + 34], "little")
        lfh_offset = int.from_bytes(data[pos + 42:pos + 46], "little")
        name = data[pos + 46:pos + 46 + name_len].decode("utf-8", "replace")
        if (csize == 0xFFFFFFFF or usize == 0xFFFFFFFF
                or lfh_offset == 0xFFFFFFFF):
            raise DeflateError(f"zip64 not supported (entry {name!r})")
        if (lfh_offset + 30 > len(data)
                or data[lfh_offset:lfh_offset + 4] != ZIP_LOCAL_MAGIC):
            raise DeflateError(f"corrupt zip: bad local header for {name!r}")
        lfh_name_len = int.from_bytes(
            data[lfh_offset + 26:lfh_offset + 28], "little")
        lfh_extra_len = int.from_bytes(
            data[lfh_offset + 28:lfh_offset + 30], "little")
        data_offset = lfh_offset + 30 + lfh_name_len + lfh_extra_len
        entries.append({"name": name, "method": method, "crc": crc,
                        "csize": csize, "usize": usize,
                        "data_offset": data_offset})
        pos += 46 + name_len + extra_len + comment_len
    return entries


def _zip_method_label(method):
    """Short human label for a ZIP compression method number."""
    if method == ZIP_METHOD_DEFLATE:
        return "deflate"
    if method == ZIP_METHOD_STORED:
        return "stored"
    return f"other-{method}"


def _pct(part, whole):
    """``part`` as a percentage of ``whole`` (0.0 when whole is 0)."""
    return 100.0 * part / whole if whole else 0.0


def print_zip_header(name, file_size, entries):
    """Print the ZIP archive header: entry counts by method, the total deflate
    data, and how many uncompressed entry bytes are not deflate (stored/other,
    which are not analyzed)."""
    n_deflate = sum(1 for entry in entries
                    if entry["method"] == ZIP_METHOD_DEFLATE)
    n_stored = sum(1 for entry in entries
                   if entry["method"] == ZIP_METHOD_STORED)
    n_other = len(entries) - n_deflate - n_stored
    deflate_csize = sum(entry["csize"] for entry in entries
                        if entry["method"] == ZIP_METHOD_DEFLATE)
    deflate_usize = sum(entry["usize"] for entry in entries
                        if entry["method"] == ZIP_METHOD_DEFLATE)
    non_deflate_bytes = sum(entry["usize"] for entry in entries
                            if entry["method"] != ZIP_METHOD_DEFLATE)
    print(f"=== zip: {name} ===")
    print(f"  entries:     {len(entries)} "
          f"({n_deflate} deflate, {n_stored} stored, {n_other} other)")
    print(f"  deflate:     {n_deflate} entries, {deflate_csize} compressed -> "
          f"{deflate_usize} uncompressed bytes")
    print(f"  non-deflate: {len(entries) - n_deflate} entries, "
          f"{non_deflate_bytes} uncompressed bytes (stored/other)")
    print(f"  file size:   {file_size} bytes")


def print_zip_summary(agg, n_entries, wbits):
    """Print the aggregate deflate summary for all deflate entries (read as one
    stream): sizes, block/match/literal counts, and match length/distance
    ranges, aligned like the single-stream summary."""
    print(f"=== aggregate deflate ({n_entries} entries) ===")
    ratio = agg["comp_size"] / agg["src_size"] if agg["src_size"] else 0.0
    rows = []
    rows.append(("input",
                 (f"{agg['src_size']} bytes "
                  f"(across {n_entries} deflate entries)")))
    rows.append(("compressed", f"{agg['comp_size']} bytes (ratio={ratio:.4f})"))
    block_summary = ", ".join(f"{btype}={count}"
                              for btype, count in sorted(agg["block_counts"].items()))
    rows.append(("blocks", f"{sum(agg['block_counts'].values())} [{block_summary}]"))
    rows.append(("literals",
                 (f"{agg['n_lit']} ({_pct(agg['n_lit'], agg['src_size']):.2f}% "
                  f"of input)")))
    rows.append(("literal runs",
                 f"{agg['n_runs']} (avg {agg['run_avg']:.2f}, max {agg['run_max']})"))
    rows.append(("matches",
                 (f"{agg['n_match']} (match bytes {agg['match_bytes']}, "
                  f"{_pct(agg['match_bytes'], agg['src_size']):.2f}% of input)")))
    rows.append(("match len",
                 (f"avg {agg['len_avg']:.2f}, min {agg['len_min']}, "
                  f"max {agg['len_max']}")))
    window = agg["window"]
    if wbits is None:
        dist_note = "window unknown; pass --window-bits to check"
    elif window is None:
        dist_note = f"window unknown for window_bits={wbits}"
    else:
        dist_note = f"window size {window}"
    rows.append(("match dist",
                 (f"avg {agg['dist_avg']:.2f}, min {agg['dist_min']}, "
                  f"max {agg['dist_max']}   ({dist_note})")))
    label_width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"  {label + ':':<{label_width + 1}} {value}")
    if window is not None and agg["dist_max"] > window:
        print(f"  WARNING: max match distance {agg['dist_max']} exceeds the "
              f"window size {window} allowed by window_bits={wbits}")


def print_zip_entries(entries, deflate_analyses):
    """Print a compact one-line-per-entry table for every entry: method, name,
    compressed/uncompressed size, ratio, and crc32 (displayed, never checked).
    Deflate entries (present in ``deflate_analyses`` keyed by index) also show
    their match/literal counts; stored/other entries show basic stats only
    (dashes for those columns)."""
    print(f"=== per-entry ({len(entries)} entries) ===")
    name_width = min(40, max((len(entry["name"]) for entry in entries), default=8))
    print(f"  {'idx':>3}  {'method':<8} {'entry':<{name_width}} "
          f"{'csize':>9} {'usize':>9} {'ratio':>7} {'matches':>8} {'literals':>8} "
          f"{'crc32 (not checked)':>21}")
    for index, entry in enumerate(entries):
        ratio = entry["csize"] / entry["usize"] if entry["usize"] else 0.0
        analysis = deflate_analyses.get(index)
        matches = str(analysis.stats["n_match"]) if analysis is not None else "-"
        literals = str(analysis.stats["n_lit"]) if analysis is not None else "-"
        name = entry["name"]
        if len(name) > name_width:
            name = name[:name_width]
        crc_text = fmt_trailer_value("crc32", entry["crc"])
        print(f"  {index:>3}  {_zip_method_label(entry['method']):<8} "
              f"{name:<{name_width}} {entry['csize']:>9} {entry['usize']:>9} "
              f"{ratio:>7.4f} {matches:>8} {literals:>8} {crc_text:>21}")


class _AggregateAnalysis:
    """Expose an aggregate stats dict as an Analysis-like object for reporters.

    Lets the single-stream reporters (print_huffman, print_huff_symbols (shown
    by default; disable with --no-huff-symbols), and print_match_economics)
    read the aggregated ZIP
    metrics via the same ``.stats``, ``.block_trees``, and ``.events``
    attributes without a real Analysis."""

    def __init__(self, stats, block_trees, events):
        """Wrap a precomputed aggregate stats dict, the merged block trees
        (with globally renumbered ev_start/ev_end), and the concatenated
        per-entry events."""
        self.stats = stats
        self.block_trees = block_trees
        self.events = events


def analyze_zip_file(args, comp, name, zlib):
    """'analyze-file' on a ZIP/JAR/APK: show the archive header, analyze the
    deflate entries (aggregated as one stream, cross-checked against system
    zlib), and list basic stats for every entry (stored/other not analyzed)."""
    try:
        entries = parse_zip(comp)
    except DeflateError as e:
        raise SystemExit(f"error: {args.file}: {e}") from e
    if args.json:
        _dump(_zip_json(name, comp, entries, args.window_bits, zlib,
                        args.json_full))
        return
    print_zip_header(name, len(comp), entries)
    print()
    wbits = args.window_bits
    options = (None, wbits, None, None)
    deflate_entries = [(idx, entry) for idx, entry in enumerate(entries)
                       if entry["method"] == ZIP_METHOD_DEFLATE]
    if not deflate_entries:
        print_zip_entries(entries, {})
        print()
        print("  no deflate entries to analyze "
              f"({len(entries)} entries are stored/other)")
        return
    deflate_analyses: dict[int, Analysis] = {}
    analyses: list[Analysis] = []
    # One bar across all deflate entries: the per-entry decoded byte count is
    # offset by the cumulative size of the earlier entries so it advances
    # monotonically from 0 to the total.
    total = sum(entry["usize"] for _idx, entry in deflate_entries)
    progress = Progress(total, enabled=args.progress)
    base = [0]

    def _report(d):
        """Report per-entry decoded bytes offset into the running total."""
        progress.update(base[0] + d)

    for index, entry in deflate_entries:
        raw = comp[entry["data_offset"]:entry["data_offset"] + entry["csize"]]
        try:
            src = zlib.decompress(raw, -15)  # raw deflate (no wrapper/trailer)
        except zlib.error as e:
            raise SystemExit(f"error: system zlib failed to inflate entry "
                             f"{entry['name']!r}: {e}") from e
        if len(src) != entry["usize"]:
            raise SystemExit(f"error: entry {entry['name']!r}: decompressed "
                             f"{len(src)} bytes but zip usize is {entry['usize']}")
        try:
            analysis = Analysis(None, options, src, raw,
                                detected=(raw, "raw", []), on_progress=_report)
        except DeflateError as e:
            raise SystemExit(f"error: internal decode disagrees with system "
                             f"zlib for entry {entry['name']!r}: {e}") from e
        deflate_analyses[index] = analysis
        analyses.append(analysis)
        base[0] += len(src)
    progress.finish()
    agg = aggregate_analyses(analyses, wbits)
    print_zip_summary(agg, len(analyses), wbits)
    print(f"system zlib inflate: ok ({len(analyses)} deflate entries "
          f"cross-checked)")
    print()
    print_zip_entries(entries, deflate_analyses)
    print()
    print_length_hist(agg["len_hist"], agg["n_match"], args.length_full)
    print()
    print_dist_hist(agg["dist_hist"], agg["n_match"], args.dist_log2)
    print()
    print_match_map(agg["pair_hist"], args.map_axis_linear,
                    args.map_scale_log2, resolve_map_color(args))
    print()
    # Concatenate the per-entry events and renumber each block's ev_start/ev_end
    # to global indices so _match_costs maps every match to its own entry's tree.
    merged_events: list = []
    merged_trees: list = []
    for part in analyses:
        offset = len(merged_events)
        merged_events.extend(part.events)
        merged_trees.extend(
            {**tree, "ev_start": tree["ev_start"] + offset,
             "ev_end": tree["ev_end"] + offset} for tree in part.block_trees)
    aggregate = _AggregateAnalysis(agg, merged_trees, merged_events)
    print_match_economics(aggregate, args.map_axis_linear,
                          resolve_map_color(args))
    print()
    print_huffman(aggregate, args.huff_symbols)


def first_byte_diff(a, b):
    """Index of first differing byte, or min-len if lengths differ, else None."""
    common_len = min(len(a), len(b))
    off = 0
    chunk = 1 << 20
    while off + chunk <= common_len:
        if a[off:off + chunk] != b[off:off + chunk]:
            for i in range(chunk):
                if a[off + i] != b[off + i]:
                    return off + i
            return off
        off += chunk
    if a[off:common_len] != b[off:common_len]:
        for i in range(common_len - off):
            if a[off + i] != b[off + i]:
                return off + i
        return off
    return common_len if len(a) != len(b) else None


def inflate_check(src, comp, wrapper):
    """Verify a compressed stream is correct by inflating it with system zlib.

    A stream produced by the library under test is re-inflated with system
    zlib -- a trusted reference, not the library itself -- and compared to
    ``src``. A round-trip through the same library could hide a bug that
    affects deflate and inflate alike. Returns (ok, produced_len)."""
    import zlib  # system zlib: the trusted reference, not the library under test
    wbits = {"zlib": 15, "gzip": 31, "raw": -15}[wrapper]
    try:
        out = zlib.decompress(comp, wbits)
    except zlib.error:
        return False, 0
    return out == src, len(out)


# ---------------------------------------------------------------------------
# Analysis results
# ---------------------------------------------------------------------------

def event_offset(events, idx):
    """Input offset where event ``idx`` starts (sum of earlier event lengths)."""
    off = 0
    for ev in events[:idx]:
        off += ev[1]
    return off


def _tree_bits(lens, freqs):
    """(actual_bits, entropy_bits, n_symbols) for one Huffman tree.

    actual  = sum over symbols of freq * code_length
    entropy = the ideal bit count, count * (-sum(p * log2 p))"""
    count = sum(freqs)
    if count == 0:
        return 0, 0.0, 0
    actual = sum(freq * code_len
                 for freq, code_len in zip(freqs, lens, strict=True))
    ent = 0.0  # accumulates the mean entropy (bits per symbol)
    for freq in freqs:
        if freq:
            prob = freq / count
            ent -= prob * math.log2(prob)
    return actual, ent * count, count


def _efficiency(block_trees):
    """Per-tree actual/entropy bits, by block type and total.
    Returns (litlen, dist); each is {scope: [actual, ideal, count]}."""
    totals = {name: {scope: [0, 0.0, 0]
                     for scope in ("total", "fixed", "dynamic")}
              for name in ("litlen", "dist")}
    for block in block_trees:
        if block["type"] == "stored":
            continue
        for name, lens, freqs in (("litlen", block["lit_len"], block["lit_freq"]),
                                  ("dist", block["dist_len"], block["dist_freq"])):
            actual, ideal, count = _tree_bits(lens, freqs)
            for scope in (block["type"], "total"):
                totals[name][scope][0] += actual
                totals[name][scope][1] += ideal
                totals[name][scope][2] += count
    return totals["litlen"], totals["dist"]


def _bit_budget(events, deflate_len, block_trees):
    """Split the deflate stream's bits into categories. Returns a dict."""
    litlen, dist = _efficiency(block_trees)
    litlen_bits, dist_bits = litlen["total"][0], dist["total"][0]
    len_extra = dist_extra = 0
    for ev in events:
        if ev[0] == "M":
            len_code = LEN_CODE_OF.get(ev[1])
            dist_code = DIST_CODE_OF.get(ev[2])
            if len_code is not None:
                len_extra += LENGTH_EXTRA[len_code]
            if dist_code is not None:
                dist_extra += DIST_EXTRA[dist_code]
    stored_bits = sum(block["bytes"] * 8 for block in block_trees
                      if block["type"] == "stored")
    total = deflate_len * 8
    # Whatever the symbol/extra bits and stored payloads don't account for is
    # block headers (bfinal/btype, HLIT/HDIST/HCLEN, code lengths) + bit padding.
    header = (total - litlen_bits - len_extra - dist_bits - dist_extra
              - stored_bits)
    return {"litlen": litlen_bits, "len_extra": len_extra,
            "dist": dist_bits, "dist_extra": dist_extra,
            "stored": stored_bits, "header": header, "total": total}


def _symbol_stats(block_trees):
    """Aggregate per-symbol (freq, actual_bits) for the lit/len and dist trees.

    For each symbol, the entry is [freq, actual_bits] where actual_bits is
    freq * code_length summed across every block that used the symbol."""
    out: dict[str, dict[int, list[int]]] = {"litlen": {}, "dist": {}}
    for block in block_trees:
        if block["type"] == "stored":
            continue
        for name, lens, freqs in (("litlen", block["lit_len"], block["lit_freq"]),
                                  ("dist", block["dist_len"], block["dist_freq"])):
            target = out[name]
            for sym, freq in enumerate(freqs):
                if freq:
                    entry = target.get(sym)
                    if entry is None:
                        target[sym] = [freq, freq * lens[sym]]
                    else:
                        entry[0] += freq
                        entry[1] += freq * lens[sym]
    return out["litlen"], out["dist"]


def _match_costs(events, block_trees) -> dict:
    """Per-match bit cost vs the all-literal alternative, plus aggregates.

    For each match (L, D) in block k (located via each block record's
    ev_start/ev_end span), the match's bit cost is the length symbol's code
    length + length extra + the distance symbol's code length + distance
    extra, all read from block k's real Huffman trees. The literal alternative
    is L bytes at the stream's literal bits/byte. ``net = match_bits -
    L*literal_bpb`` (positive means the match costs more than encoding those
    bytes as literals, i.e. it is wasteful). Returns the summary numbers, one
    row per distance code (with the break-even length), the per-(distance,
    length) cost histogram for the cost map, and the most-overpaid cell."""
    block_of = [0] * len(events)
    for k, tree in enumerate(block_trees):
        for i in range(tree["ev_start"], tree["ev_end"]):
            block_of[i] = k
    lit_bits = lit_n = 0
    for tree in block_trees:
        if tree["type"] == "stored":
            continue
        lens, freqs = tree["lit_len"], tree["lit_freq"]
        for sym in range(256):
            if freqs[sym]:
                lit_bits += freqs[sym] * lens[sym]
                lit_n += freqs[sym]
    literal_bpb = lit_bits / lit_n if lit_n else 8.0
    n_match = total_bytes = total_bits = 0
    n_wasteful = bytes_wasteful = overpayment = 0
    dist_rows: dict[int, list[int]] = {}
    cost_hist: dict[tuple[int, int], list[int]] = {}
    cell_over: dict[tuple[int, int], int] = {}
    for i, ev in enumerate(events):
        if ev[0] != "M":
            continue
        length, dist = ev[1], ev[2]
        tree = block_trees[block_of[i]]
        lc = LEN_CODE_OF[length]
        dc = DIST_CODE_OF[dist]
        bits = (tree["lit_len"][257 + lc] + LENGTH_EXTRA[lc]
                + tree["dist_len"][dc] + DIST_EXTRA[dc])
        net = bits - length * literal_bpb
        n_match += 1
        total_bytes += length
        total_bits += bits
        row = dist_rows.setdefault(dc, [0, 0, 0, 0, 0])
        row[0] += 1
        cell = cost_hist.setdefault((dist, length), [0, 0])
        cell[0] += bits
        cell[1] += length
        if net > 0:
            n_wasteful += 1
            bytes_wasteful += length
            overpayment += net
            row[2] += 1
            row[3] += length
            row[4] += net
            row[1] = max(row[1], length)
            key = (dc, lc)
            cell_over[key] = cell_over.get(key, 0) + net
    rows = [(dc, *dist_rows[dc]) for dc in sorted(dist_rows)]
    dominant = (max(cell_over.items(), key=lambda item: item[1])
                if cell_over else None)
    return {
        "literal_bpb": literal_bpb,
        "n_match": n_match,
        "total_matched_bytes": total_bytes,
        "total_match_bits": total_bits,
        "bits_per_matched_byte": (total_bits / total_bytes) if total_bytes else 0.0,
        "n_wasteful": n_wasteful,
        "bytes_wasteful": bytes_wasteful,
        "overpayment_bits": overpayment,
        "dist_rows": rows,
        "cost_hist": cost_hist,
        "dominant_cell": dominant,
    }


class Analysis:
    """A fully-parsed compression result.

    Holds the wrapper split, the decoded decision events, the per-block Huffman
    trees, and the precomputed metrics (``self.stats``) that the reporters use."""

    def __init__(self, lib, options, src, comp, detected=None, on_progress=None):
        """Build an Analysis from raw compressed ``comp`` bytes.

        ``options`` is (level, window_bits, mem_level, strategy). If ``detected``
        (a wrapper split, for an external file) is given it is used, otherwise the
        wrapper is split using ``options[1]``. The stream is always parsed with
        verification against ``src``. ``lib`` may be None in analyze-file mode.
        ``on_progress``, if given, is forwarded to the parser as the decoded
        byte-count callback (see parse_deflate)."""
        self.lib = lib
        self.options = options  # (level, wbits, mem, strategy)
        self.src = src
        if detected is None:
            self.deflate, wrapper, trailer = split_wrapper(comp, options[1])
        else:
            self.deflate, wrapper, trailer = detected
        self.blocks, self.events, self.block_trees = parse_deflate(
            self.deflate, src, verify=True, on_progress=on_progress)
        self.comp_size = len(comp)
        self.src_size = len(src)
        self.wrapper = wrapper
        self.trailer = trailer
        self.kind = "file" if detected is not None else "compress"
        self.stats = self._stats()

    def _stats(self):
        """Compute every derived metric from the decoded events and block trees."""
        events = self.events
        n_lit = sum(ev[1] for ev in events if ev[0] == "L")
        n_match = sum(1 for ev in events if ev[0] == "M")
        match_bytes = sum(ev[1] for ev in events if ev[0] == "M")
        lens = [ev[1] for ev in events if ev[0] == "M"]
        dists = [ev[2] for ev in events if ev[0] == "M"]
        runs = [ev[1] for ev in events if ev[0] == "L"]
        huff_litlen, huff_dist = _efficiency(self.block_trees)
        budget = _bit_budget(self.events, len(self.deflate), self.block_trees)
        return {
            "n_events": len(events),
            "n_lit": n_lit,
            "n_match": n_match,
            "match_bytes": match_bytes,
            "len_hist": Counter(lens),
            "dist_hist": Counter(dists),
            "pair_hist": Counter(zip(dists, lens, strict=True)),
            "len_min": min(lens) if lens else 0,
            "len_max": max(lens) if lens else 0,
            "len_avg": (sum(lens) / len(lens)) if lens else 0.0,
            "dist_min": min(dists) if dists else 0,
            "dist_max": max(dists) if dists else 0,
            "dist_avg": (sum(dists) / len(dists)) if dists else 0.0,
            "run_max": max(runs) if runs else 0,
            "run_avg": (len(runs) and n_lit / len(runs)) or 0.0,
            "n_runs": len(runs),
            "block_counts": Counter(self.blocks),
            "window": window_size(self.options[1]),
            "huff": {"litlen": huff_litlen, "dist": huff_dist},
            "budget": budget,
        }


def aggregate_analyses(analyses, wbits):
    """Merge per-entry deflate Analysis objects into one aggregate stats dict.

    Concatenates the decision events and block trees across all entries and
    recomputes the counters, histograms, and the Huffman/bit-budget metrics from
    the combined data, so the result reads like a single deflate stream covering
    every entry (each entry is an independent stream, and these metrics are
    additive across them). ``wbits`` supplies the window for distance checks.
    Returns a dict with the same keys as ``Analysis.stats`` plus ``comp_size``,
    ``src_size``, and ``wrapper``."""
    events: list = []
    trees: list = []
    comp_size = 0
    src_size = 0
    deflate_len = 0
    for analysis in analyses:
        events.extend(analysis.events)
        trees.extend(analysis.block_trees)
        comp_size += analysis.comp_size
        src_size += analysis.src_size
        deflate_len += len(analysis.deflate)
    lens = [ev[1] for ev in events if ev[0] == "M"]
    dists = [ev[2] for ev in events if ev[0] == "M"]
    runs = [ev[1] for ev in events if ev[0] == "L"]
    n_lit = sum(runs)
    huff_litlen, huff_dist = _efficiency(trees)
    budget = _bit_budget(events, deflate_len, trees)
    return {
        "n_events": len(events),
        "n_lit": n_lit,
        "n_match": len(lens),
        "match_bytes": sum(lens),
        "len_hist": Counter(lens),
        "dist_hist": Counter(dists),
        "pair_hist": Counter(zip(dists, lens, strict=True)),
        "len_min": min(lens) if lens else 0,
        "len_max": max(lens) if lens else 0,
        "len_avg": (sum(lens) / len(lens)) if lens else 0.0,
        "dist_min": min(dists) if dists else 0,
        "dist_max": max(dists) if dists else 0,
        "dist_avg": (sum(dists) / len(dists)) if dists else 0.0,
        "run_max": max(runs) if runs else 0,
        "run_avg": (n_lit / len(runs)) if runs else 0.0,
        "n_runs": len(runs),
        "block_counts": Counter(block["type"] for block in trees),
        "window": window_size(wbits),
        "huff": {"litlen": huff_litlen, "dist": huff_dist},
        "budget": budget,
        "comp_size": comp_size,
        "src_size": src_size,
        "wrapper": "raw",
    }


def find_divergences(ev_a, ev_b):
    """Walk two event partitions of the same input, one event at a time.

    Returns (regions, n_regions, covered_bytes). Each region is a tuple
    (start, end, i_first, i_end, j_first, j_end): ``[start, end)`` is the span
    of input bytes where the two sides disagree, and ``[i_first, i_end)`` /
    ``[j_first, j_end)`` are the matching half-open event-index ranges on
    sides A and B that make up that span."""
    n_a, n_b = len(ev_a), len(ev_b)
    off_a = [0] * (n_a + 1)
    for i in range(n_a):
        off_a[i + 1] = off_a[i] + ev_a[i][1]
    off_b = [0] * (n_b + 1)
    for j in range(n_b):
        off_b[j + 1] = off_b[j] + ev_b[j][1]
    total = off_a[n_a]

    regions = []
    i = j = 0
    while i < n_a and j < n_b:
        if ev_a[i] == ev_b[j]:
            i += 1
            j += 1
            continue
        start = off_a[i]
        i_end, j_end = i, j
        converged = False
        # Walk through the region advancing the side whose current event ends
        # first, until both sides reach an identical event at the same offset
        # (convergence) or one side runs out (the region extends to the end).
        while True:
            if i_end >= n_a or j_end >= n_b:
                break
            if off_a[i_end] == off_b[j_end] and ev_a[i_end] == ev_b[j_end]:
                converged = True
                break
            end_a = off_a[i_end + 1] if i_end + 1 < n_a else total
            end_b = off_b[j_end + 1] if j_end + 1 < n_b else total
            if end_a <= end_b:
                i_end += 1
            else:
                j_end += 1
        end = off_a[i_end] if converged else total
        regions.append((start, end, i, i_end, j, j_end))
        if not converged:
            break
        i, j = i_end, j_end
    covered = sum(region[1] - region[0] for region in regions)
    return regions, len(regions), covered


def first_divergence_offset(ev_a, ev_b):
    """Input offset of the first differing decision, or None."""
    n_a, n_b = len(ev_a), len(ev_b)
    off_a = off_b = 0
    i = j = 0
    while i < n_a and j < n_b:
        if ev_a[i] == ev_b[j]:
            off_a += ev_a[i][1]
            off_b += ev_b[j][1]
            i += 1
            j += 1
            continue
        return off_a
    return None


def _region_effect(events_a, events_b, start, end) \
        -> tuple[int, tuple[int, int, int, float], tuple[int, int, int, float]]:
    """Summarize one divergent region's per-side match/literal split.

    Both sides cover the same input span [start, end); returns (span, side_a,
    side_b) where each side is (n_match, matched_bytes, literal_bytes,
    avg_match_len)."""
    def side(events) -> tuple[int, int, int, float]:
        matched = sum(ev[1] for ev in events if ev[0] == "M")
        literal = sum(ev[1] for ev in events if ev[0] == "L")
        n_match = sum(1 for ev in events if ev[0] == "M")
        return (n_match, matched, literal,
                matched / n_match if n_match else 0.0)
    return (end - start), side(events_a), side(events_b)


def fmt_event(ev, off, src=None, show_bytes=False):
    """Render one event for display; optionally include the literal byte hex."""
    if ev[0] == "L":
        text = f"L x{ev[1]}"
        if show_bytes and src is not None:
            chunk = src[off:off + ev[1]]
            hexs = " ".join(f"{byte:02x}" for byte in chunk[:16])
            if len(chunk) > 16:
                hexs += " ..."
            text += f" [{hexs}]"
    else:
        text = f"M len={ev[1]} dist={ev[2]}"
    return text


def _bar(count, max_count, width):
    """A proportional bar: full blocks + one fractional (eighth) tail cell."""
    scaled = width * count / max_count
    full = int(scaled)
    eighths = round((scaled - full) * 8)
    if eighths == 8:
        return BLOCK * (full + 1)
    if eighths:
        return BLOCK * full + EIGHTH[eighths - 1]
    return BLOCK * full


def print_histogram(title, rows, total, label_name, width=40):
    """Print a column header plus label/count/percent rows with a proportional
    bar per row. ``label_name`` names the first (label) column."""
    if not rows:
        print(f"{title}\n  (none)")
        return
    max_count = max(count for _, count in rows)
    label_width = max(len(label) for label, _ in rows)
    print(title)
    print(f"  {label_name:>{label_width}}  {'count':>10}  {'pct':>7}  distribution")
    for label, count in rows:
        bar = _bar(count, max_count, width) if count else ""
        pct = 100.0 * count / total if total else 0.0
        print(f"  {label:>{label_width}}  {count:>10}  {pct:6.2f}%  {bar}")


def length_hist_rows(counter, full=False):
    """(label, count) rows for the match-length histogram.

    ``full`` gives one row per length (3-258). The default groups matches by
    their deflate length code (RFC 1951 Table 14), shown sans extra bits: each
    of the 29 codes spans a contiguous run of lengths (``LENGTH_BASE``), so the
    rows read like the codec's own length symbols."""
    if full:
        return [(str(length), count) for length, count in sorted(counter.items())]
    sums = [0] * len(LENGTH_BASE)
    for length, count in counter.items():
        code = bisect.bisect_right(LENGTH_BASE, length) - 1
        sums[code] += count
    rows = []
    for code, base in enumerate(LENGTH_BASE):
        if sums[code]:
            top = LENGTH_BASE[code + 1] - 1 if code + 1 < len(LENGTH_BASE) else 258
            label = str(base) if base == top else f"[{base},{top}]"
            rows.append((label, sums[code]))
    return rows


def print_length_hist(counter, n_match, full):
    """Print the match-length histogram: bucketed by length code (sans extra
    bits) by default, or one row per length when ``full`` is set."""
    if full:
        title = "=== match length histogram ==="
        rows = length_hist_rows(counter, full=True)
    else:
        title = "=== match length encoding histogram (sans extra bits) ==="
        rows = length_hist_rows(counter)
    print_histogram(title, rows, n_match, "length")


def dist_hist_rows(counter, log2=False):
    """(label, count) rows for the match-distance histogram.

    ``log2`` gives the magnitude buckets (1, 2, [3,4], [5,8], ...). The default
    groups distances by their deflate distance code (RFC 1951 Table 8), shown
    sans extra bits: each of the 30 codes spans a contiguous run of distances
    (``DIST_BASE``), so the rows read like the codec's own distance symbols."""
    if log2:
        buckets: dict[int, int] = {}
        for dist, count in counter.items():
            if dist <= 1:
                bucket = 0
            elif dist == 2:
                bucket = 1
            else:
                bucket = (dist - 1).bit_length()
            buckets[bucket] = buckets.get(bucket, 0) + count
        rows = []
        for bucket in sorted(buckets):
            if bucket == 0:
                lo = hi = 1
            elif bucket == 1:
                lo = hi = 2
            else:
                lo, hi = 2 ** (bucket - 1) + 1, 2 ** bucket
            rows.append((f"[{lo},{hi}]", buckets[bucket]))
        return rows
    sums = [0] * len(DIST_BASE)
    for dist, count in counter.items():
        code = bisect.bisect_right(DIST_BASE, dist) - 1
        sums[code] += count
    rows = []
    for code, base in enumerate(DIST_BASE):
        if sums[code]:
            top = DIST_BASE[code + 1] - 1 if code + 1 < len(DIST_BASE) else 32768
            label = str(base) if base == top else f"[{base},{top}]"
            rows.append((label, sums[code]))
    return rows


def print_dist_hist(counter, n_match, log2):
    """Print the match-distance histogram: bucketed by distance code (sans extra
    bits) by default, or by log2 magnitude buckets when ``log2`` is set."""
    if log2:
        title = "=== match distance histogram (log2 buckets) ==="
        rows = dist_hist_rows(counter, log2=True)
    else:
        title = "=== match distance encoding histogram (sans extra bits) ==="
        rows = dist_hist_rows(counter)
    print_histogram(title, rows, n_match, "distance")


def _map_quantize(frac, steps):
    """Map a normalized fraction in [0, 1] to an even bucket level in [1, steps].

    Divides the range into ``steps`` equal buckets (floor, so a value exactly at
    the top clamps to ``steps``). Callers map a zero count to level 0 (blank)."""
    return min(steps, math.floor(frac * steps) + 1)


def _map_level_linear(count, max_count, steps):
    """Shading level (0..steps) on the honest/linear scale: even buckets over
    [0, max_count], so the busiest cell is ``steps`` and every band is uniform.
    A zero count is blank (0); any non-zero count is at least level 1."""
    if count <= 0:
        return 0
    if max_count <= 1:
        return steps
    return _map_quantize(count / max_count, steps)


def _map_level_log2(count, max_count, steps):
    """Shading level (0..steps) on the log2 scale: even buckets over the log2
    span [log2(2), log2(max_count + 1)] scaled to the max, so low counts get
    fine resolution while the bands stay equal in log space. Zero is blank; any
    non-zero count is at least level 1."""
    if count <= 0:
        return 0
    if max_count <= 1:
        return steps
    frac = (math.log2(count + 1) - 1.0) / (math.log2(max_count + 1) - 1.0)
    return _map_quantize(frac, steps)


def _cost_level_fixed(val, max_bits, steps):
    """Map a match cost (bits / matched byte) onto the fixed 0..max_bits ramp.

    The scale is fixed (never normalized per map), so cost maps are directly
    comparable across files and runs. A zero/empty cell is blank (0); any
    non-zero value, however small, is at least level 1; ``max_bits`` maps to the
    densest level. A value over ``max_bits`` (overpaid) returns ``steps + 1``,
    which ``_map_cell`` renders as a bright-white 'X' cell."""
    if val <= 0:
        return 0
    if val > max_bits:
        return steps + 1
    return _map_quantize(val / max_bits, steps)


def _dim(s, color):
    """Wrap a string in the dim frame color (a fixed dim gray) when ``color`` is
    on, else return it unchanged (plain box-drawing)."""
    if not color:
        return s
    return f"\x1b[38;5;{MAP_FRAME_COLOR}m{s}{_MAP_ANSI_RESET}"


def _map_top_border(n_cols, color):
    """The top border line of one map: '┌' + n_cols '─' + '┐' (no bottom border;
    the ruler beneath the last row closes the frame visually)."""
    return _dim(MAP_TOP_LEFT + MAP_H * n_cols + MAP_TOP_RIGHT, color)


def _map_side_frame(body, color):
    """Wrap one map row's rendered cells in left/right side borders. ``body`` may
    carry ANSI (its cells), which still render at their visual width, so the
    borders stay aligned with the cell area."""
    return _dim(MAP_SIDE, color) + body + _dim(MAP_SIDE, color)


def _map_cell(count, max_count, level_fn, color):
    """Render one map cell.

    Plain (``color`` off): the density glyph (a space for a zero count). Colored:
    a zero count is a blank cell on the dark blank background (xterm 234); a
    non-zero count is its density glyph with both the foreground and the
    background set to the matching thermal step, so the glyph is invisible
    against its own color (a solid heat block) in a color terminal but the glyph
    remains once the ANSI codes are stripped (e.g. copied text). The cost maps'
    overpaid sentinel (a level beyond the densest) renders as a bright-white
    'X' cell: an 'X' glyph with an fg=bg xterm 231 block in color mode."""
    glyph_idx = level_fn(count, max_count, 6)
    if glyph_idx > len(MAP_GLYPH) - 1:
        if color:
            return (f"{_MAP_ANSI_FG_BG.format(MAP_OVERPAID, MAP_OVERPAID)}"
                    f"X{_MAP_ANSI_RESET}")
        return "X"
    if not color:
        return MAP_GLYPH[glyph_idx]
    if glyph_idx == 0:
        return f"{_MAP_ANSI_BG.format(MAP_BG_BLANK)} {_MAP_ANSI_RESET}"
    code = MAP_THERMAL[level_fn(count, max_count, len(MAP_THERMAL)) - 1]
    return (f"{_MAP_ANSI_FG_BG.format(code, code)}"
            f"{MAP_GLYPH[glyph_idx]}{_MAP_ANSI_RESET}")


def _map_cell_row(row, max_count, level_fn, color):
    """Render a full map row (a list of counts) into one string of cells."""
    return "".join(_map_cell(count, max_count, level_fn, color) for count in row)


def _map_legend(color, note="1 match = \u00b7", overpaid=False):
    """The legend line beneath a map. Plain: the density glyph ramp. Colored: a
    blank (xterm 234) swatch + the 30-step thermal ramp, each swatch rendered
    exactly like a map cell (fg=bg), so the legend matches the map in color and
    still shows the density glyphs once the ANSI codes are stripped (copied).
    ``note`` is the plain-mode descriptor for what one scale step means (the
    count map's '1 match = \u00b7'; the cost map's 'bits per matched byte').
    ``overpaid`` (cost maps) appends the bright-white 'X' overpaid swatch /
    glyph and advertises the > COST_MAX_BITS threshold."""
    if not color:
        ramp = "\u00b7 \u25aa \u2591 \u2592 \u2593 \u2588" + (" X" if overpaid
                                                              else "")
        parts = ["0 = blank", note]
        if overpaid:
            parts.append(f"> {COST_MAX_BITS:g} = overpaid")
        return f"  {ramp}   low \u2192 high  ({', '.join(parts)})"
    band = len(MAP_THERMAL) // 6  # thermal steps per density-glyph band
    swatches = [f"{_MAP_ANSI_BG.format(MAP_BG_BLANK)} {_MAP_ANSI_RESET}"]
    for step in range(1, len(MAP_THERMAL) + 1):
        code = MAP_THERMAL[step - 1]
        glyph = MAP_GLYPH[(step + band - 1) // band]  # even band per glyph
        swatches.append(f"{_MAP_ANSI_FG_BG.format(code, code)}"
                        f"{glyph}{_MAP_ANSI_RESET}")
    if overpaid:
        swatches.append(f"{_MAP_ANSI_FG_BG.format(MAP_OVERPAID, MAP_OVERPAID)}"
                        f"X{_MAP_ANSI_RESET}")
        tail = f"low \u2192 high  (0 = blank, > {COST_MAX_BITS:g} = overpaid)"
    else:
        tail = "low \u2192 high  (0 = blank)"
    return f"  {' '.join(swatches)}   {tail}"


def match_map_grid(pair_hist, linear):
    """Bin (distance, length) match pairs into a 2-D grid of counts.

    Returns ``(grid, row_labels, tick_cols, tick_vals)`` where ``grid[r][c]``
    is the number of matches in that length row / distance column. Encoding mode
    uses the deflate length/distance code buckets (the fixed 1-32768 window);
    linear mode uses uniform bins over 3-258 (length) and 0-32768 (distance).
    ``tick_cols``/``tick_vals`` pair each pow2 distance label with its column."""
    if linear:
        n_rows, n_cols = MAP_LIN_ROWS, MAP_LIN_COLS
        grid = [[0] * n_cols for _ in range(n_rows)]
        for (dist, length), count in pair_hist.items():
            row = min(n_rows - 1, (length - 3) * n_rows // 255)
            col = min(n_cols - 1, dist * n_cols // 32768)
            grid[row][col] += count
        row_labels = [str(3 + i * 255 // n_rows) for i in range(n_rows)]
        tick_vals = MAP_TICKS_LIN
        tick_cols = [min(n_cols - 1, value * n_cols // 32768) for value in tick_vals]
        return grid, row_labels, tick_cols, tick_vals
    n_rows = len(LENGTH_BASE)
    n_cols = len(DIST_BASE)
    grid = [[0] * n_cols for _ in range(n_rows)]
    for (dist, length), count in pair_hist.items():
        row = bisect.bisect_right(LENGTH_BASE, length) - 1
        col = bisect.bisect_right(DIST_BASE, dist) - 1
        grid[row][col] += count
    row_labels = []
    for i in range(n_rows):
        top = LENGTH_BASE[i + 1] - 1 if i + 1 < n_rows else 258
        row_labels.append(str(LENGTH_BASE[i]) if top == LENGTH_BASE[i]
                          else f"{LENGTH_BASE[i]}-{top}")
    tick_vals = MAP_TICKS_ENC
    tick_cols = [bisect.bisect_right(DIST_BASE, value) - 1 for value in tick_vals]
    return grid, row_labels, tick_cols, tick_vals


def cost_map_grid(cost_hist, linear):
    """Bin per-(distance,length) match-cost data into a 2-D grid of
    bits/matched-byte. Mirrors match_map_grid's axes, but each cell is the
    average match cost (total match bits / total matched bytes) in that bin;
    empty cells are 0.0. Returns (grid, row_labels, tick_cols, tick_vals)."""
    if linear:
        n_rows, n_cols = MAP_LIN_ROWS, MAP_LIN_COLS
    else:
        n_rows, n_cols = len(LENGTH_BASE), len(DIST_BASE)
    bits = [[0] * n_cols for _ in range(n_rows)]
    byts = [[0] * n_cols for _ in range(n_rows)]
    for (dist, length), (mbits, mbytes) in cost_hist.items():
        if linear:
            row = min(n_rows - 1, (length - 3) * n_rows // 255)
            col = min(n_cols - 1, dist * n_cols // 32768)
        else:
            row = bisect.bisect_right(LENGTH_BASE, length) - 1
            col = bisect.bisect_right(DIST_BASE, dist) - 1
        bits[row][col] += mbits
        byts[row][col] += mbytes
    grid = [[(bits[r][c] / byts[r][c]) if byts[r][c] else 0.0
             for c in range(n_cols)] for r in range(n_rows)]
    if linear:
        row_labels = [str(3 + i * 255 // n_rows) for i in range(n_rows)]
        tick_vals = MAP_TICKS_LIN
        tick_cols = [min(n_cols - 1, value * n_cols // 32768) for value in tick_vals]
    else:
        row_labels = []
        for i in range(n_rows):
            top = LENGTH_BASE[i + 1] - 1 if i + 1 < n_rows else 258
            row_labels.append(str(LENGTH_BASE[i]) if top == LENGTH_BASE[i]
                              else f"{LENGTH_BASE[i]}-{top}")
        tick_vals = MAP_TICKS_ENC
        tick_cols = [bisect.bisect_right(DIST_BASE, value) - 1 for value in tick_vals]
    return grid, row_labels, tick_cols, tick_vals


def print_match_map(pair_hist, linear, log2, color):
    """Print the 2-D match distance x length map: rows are match lengths,
    columns are match distances, each cell a fill glyph scaled to the count in
    that bin. The axis defaults to the deflate encoding buckets (``linear``
    switches to uniform bins); the shading defaults to honest/linear (``log2``
    switches to a log2 scale). The cell area is framed (top + sides; the ruler
    beneath is open); in color mode the cells are solid heat blocks (fg=bg) on a
    dark blank background and the frame is a dim gray. A pow2 distance ruler
    (``┃`` markers + labels) and a legend are printed beneath."""
    if not pair_hist:
        print("=== match distance x length map ===\n  (no matches)")
        return
    grid, row_labels, tick_cols, tick_vals = match_map_grid(pair_hist, linear)
    n_rows = len(grid)
    n_cols = len(grid[0])
    max_count = 0
    for row in grid:
        for count in row:
            max_count = max(max_count, count)
    level_fn = _map_level_log2 if log2 else _map_level_linear
    axis = f"linear {n_rows}x{n_cols}" if linear else "encoding buckets"
    print(f"=== match distance x length map ({axis}) ===")
    print(" " * 8 + _map_top_border(n_cols, color))
    for i in range(n_rows):
        cells = _map_cell_row(grid[i], max_count, level_fn, color)
        print(f"{row_labels[i]:>8}{_map_side_frame(cells, color)}")
    tick_set = set(tick_cols)
    print(" " * 9 + "".join(MAP_MARKER if c in tick_set else " "
                            for c in range(n_cols)))
    line = [" "] * (n_cols + 3)
    for col, value in zip(tick_cols, tick_vals, strict=True):
        label = f"{value // 1024}K" if value >= 1024 else str(value)
        for offset, char in enumerate(label):
            line[col + offset] = char
    print(" " * 9 + "".join(line).rstrip())
    print(f"  scale: {'log2' if log2 else 'linear'}   max cell = {max_count}")
    print(_map_legend(color))


def print_cost_map(cost_hist, axis_linear, color):
    """Print the 2-D match cost map: same axes as the count map, but each cell
    is shaded by the average match cost in that bin (bits per matched byte).
    Cells use a fixed linear 0.0-8.0 bits/byte scale over the color ramp, so
    maps are directly comparable across files and runs; a cell over 8.0 bits/
    byte (overpaid) is a bright-white 'X'. Framing, the pow2 distance ruler,
    and the legend mirror the count map."""
    if not cost_hist:
        print("=== match cost map (bits / matched byte) ===\n  (no matches)")
        return
    grid, row_labels, tick_cols, tick_vals = cost_map_grid(cost_hist, axis_linear)
    n_rows = len(grid)
    n_cols = len(grid[0])
    max_val = 0.0
    for row in grid:
        for val in row:
            max_val = max(max_val, val)
    axis = f"linear {n_rows}x{n_cols}" if axis_linear else "encoding buckets"
    print(f"=== match cost map ({axis}, bits / matched byte) ===")
    print(" " * 8 + _map_top_border(n_cols, color))
    for i in range(n_rows):
        cells = _map_cell_row(grid[i], COST_MAX_BITS, _cost_level_fixed, color)
        print(f"{row_labels[i]:>8}{_map_side_frame(cells, color)}")
    tick_set = set(tick_cols)
    print(" " * 9 + "".join(MAP_MARKER if c in tick_set else " "
                            for c in range(n_cols)))
    line = [" "] * (n_cols + 3)
    for col, value in zip(tick_cols, tick_vals, strict=True):
        label = f"{value // 1024}K" if value >= 1024 else str(value)
        for offset, char in enumerate(label):
            line[col + offset] = char
    print(" " * 9 + "".join(line).rstrip())
    print(f"  scale: 0.0-{COST_MAX_BITS:.1f} bits/byte   "
          f"shared max cell = {max_val:.1f} bits/byte   "
          f"(overpaid > {COST_MAX_BITS:.1f})")
    print(_map_legend(color, note="bits per matched byte", overpaid=True))


def print_match_map_diff(a, b, linear, log2, color):
    """Print the 2-D match distance x length map for two sides (A vs B)
    side-by-side on a shared scale. Each grid is framed (top + sides; the ruler
    beneath is open); row labels sit centered in the middle; each side carries
    its own pow2 distance ruler and tick labels. Cells use the same shading as
    the single map (solid heat blocks on a dark blank background in color mode)."""
    hist_a = a.stats["pair_hist"]
    hist_b = b.stats["pair_hist"]
    if not hist_a and not hist_b:
        print("=== match distance x length map (A vs B) ===\n  (no matches)")
        return
    grid_a, row_labels, tick_cols, tick_vals = match_map_grid(hist_a, linear)
    grid_b, _lbl_b, _tick_cols_b, _tick_vals_b = match_map_grid(hist_b, linear)
    n_rows = len(grid_a)
    n_cols = len(grid_a[0])
    max_count = 0
    for grid in (grid_a, grid_b):
        for row in grid:
            for count in row:
                max_count = max(max_count, count)
    level_fn = _map_level_log2 if log2 else _map_level_linear
    gap = "  "
    label_w = 8
    lead = " "  # left margin so the A grid's edge cells don't touch the window
    top = _map_top_border(n_cols, color)
    # column of the B grid's left border: lead + A frame + gap + labels + gap
    b_left = 1 + (n_cols + 2) + 2 * len(gap) + label_w
    axis = f"linear {n_rows}x{n_cols}" if linear else "encoding buckets"
    print(f"=== match distance x length map (A vs B, {axis}) ===")
    print(lead + "A:" + " " * (b_left - 3) + "B:")  # 'A:'/'B:' over left borders
    print(lead + f"{top}{gap}{' ' * label_w}{gap}{top}")
    for i in range(n_rows):
        left = _map_side_frame(_map_cell_row(grid_a[i], max_count, level_fn,
                                             color), color)
        right = _map_side_frame(_map_cell_row(grid_b[i], max_count, level_fn,
                                              color), color)
        print(lead + f"{left}{gap}{row_labels[i]:^{label_w}}{gap}{right}")
    tick_set = set(tick_cols)
    ruler = "".join(MAP_MARKER if c in tick_set else " " for c in range(n_cols))
    # the frame becomes spaces on the ruler/tick lines (no border below the map)
    print(lead + f" {ruler} {gap}{' ' * label_w}{gap} {ruler} ")
    line = [" "] * n_cols
    for col, value in zip(tick_cols, tick_vals, strict=True):
        label = f"{value // 1024}K" if value >= 1024 else str(value)
        start = col if col + len(label) <= n_cols else n_cols - len(label)
        for offset, char in enumerate(label):
            line[start + offset] = char
    ticks = "".join(line)
    print(lead + f" {ticks} {gap}{' ' * label_w}{gap} {ticks} ")
    print(f"  scale: {'log2' if log2 else 'linear'}   "
          f"shared max cell = {max_count}")
    print(_map_legend(color))


def print_cost_map_diff(hist_a, hist_b, axis_linear, color):
    """Print the 2-D match cost map for two sides (A vs B) side-by-side on the
    fixed 0.0-8.0 bits/byte scale.

    Layout mirrors ``print_match_map_diff`` (per-side frame + pow2 ruler,
    centered row labels), but each cell is shaded by the average match cost in
    that bin and both grids share the fixed scale, so the two halves are
    directly comparable to each other and to any other run. Overpaid cells
    (over 8.0) are a bright-white 'X'; the legend reads 'bits per matched
    byte' like the single cost map."""
    if not hist_a and not hist_b:
        print("=== match cost map (A vs B, bits / matched byte) ===\n"
              "  (no matches)")
        return
    grid_a, row_labels, tick_cols, tick_vals = cost_map_grid(hist_a,
                                                             axis_linear)
    grid_b, _lbl_b, _tick_cols_b, _tick_vals_b = cost_map_grid(hist_b,
                                                               axis_linear)
    n_rows = len(grid_a)
    n_cols = len(grid_a[0])
    max_val = max((val for grid in (grid_a, grid_b) for row in grid
                   for val in row), default=0.0)
    gap = "  "
    label_w = 8
    lead = " "  # left margin so the A grid's edge cells don't touch the window
    top = _map_top_border(n_cols, color)
    # column of the B grid's left border: lead + A frame + gap + labels + gap
    b_left = 1 + (n_cols + 2) + 2 * len(gap) + label_w
    axis = f"linear {n_rows}x{n_cols}" if axis_linear else "encoding buckets"
    print(f"=== match cost map (A vs B, {axis}, bits / matched byte) ===")
    print(lead + "A:" + " " * (b_left - 3) + "B:")  # 'A:'/'B:' over left borders
    print(lead + f"{top}{gap}{' ' * label_w}{gap}{top}")
    for i in range(n_rows):
        left = _map_side_frame(_map_cell_row(grid_a[i], COST_MAX_BITS,
                                             _cost_level_fixed, color), color)
        right = _map_side_frame(_map_cell_row(grid_b[i], COST_MAX_BITS,
                                              _cost_level_fixed, color), color)
        print(lead + f"{left}{gap}{row_labels[i]:^{label_w}}{gap}{right}")
    tick_set = set(tick_cols)
    ruler = "".join(MAP_MARKER if c in tick_set else " " for c in range(n_cols))
    # the frame becomes spaces on the ruler/tick lines (no border below the map)
    print(lead + f" {ruler} {gap}{' ' * label_w}{gap} {ruler} ")
    line = [" "] * n_cols
    for col, value in zip(tick_cols, tick_vals, strict=True):
        label = f"{value // 1024}K" if value >= 1024 else str(value)
        start = col if col + len(label) <= n_cols else n_cols - len(label)
        for offset, char in enumerate(label):
            line[start + offset] = char
    ticks = "".join(line)
    print(lead + f" {ticks} {gap}{' ' * label_w}{gap} {ticks} ")
    print(f"  scale: 0.0-{COST_MAX_BITS:.1f} bits/byte   "
          f"shared max cell = {max_val:.1f} bits/byte   "
          f"(overpaid > {COST_MAX_BITS:.1f})")
    print(_map_legend(color, note="bits per matched byte", overpaid=True))


# ---------------------------------------------------------------------------
# Report: single library
# ---------------------------------------------------------------------------

def print_summary(analysis, title):
    """Print the header/summary block for a single analysis (label: value rows,
    aligned to the widest label), plus any window-size warning."""
    lib, (level, wbits, mem, strat) = analysis.lib, analysis.options
    stats = analysis.stats
    ratio = analysis.comp_size / analysis.src_size if analysis.src_size else 0.0
    print(f"=== {title} ===")
    rows = []
    if analysis.kind == "file":
        rows.append(("decoded by",
                     "internal parser (cross-checked vs system zlib)"))
        rows.append(("wrapper", f"{analysis.wrapper} (detected from magic bytes)"))
        if wbits is not None:
            rows.append(("window check",
                         f"against user-specified window_bits={wbits}"))
        rows.append(("input", f"{analysis.src_size} bytes"))
        rows.append(("compressed", f"{analysis.comp_size} bytes (ratio={ratio:.4f})"))
    else:
        rows.append(("library", f"{lib.path} ({lib.version})"))
        rows.append(("options",
                     (f"level={level} window_bits={wbits} mem_level={mem} "
                      f"strategy={STRATEGY_LABELS.get(strat, strat)}")))
        rows.append(("input", f"{analysis.src_size} bytes"))
        rows.append(("compressed",
                     (f"{analysis.comp_size} bytes "
                      f"(wrapper={analysis.wrapper}, ratio={ratio:.4f})")))
    block_summary = ", ".join(f"{btype}={count}"
                              for btype, count in sorted(stats["block_counts"].items()))
    rows.append(("blocks", f"{len(analysis.blocks)} [{block_summary}]"))
    input_size = analysis.src_size
    rows.append(("literals",
                 (f"{stats['n_lit']} ({100.0 * stats['n_lit'] / input_size:.2f}% "
                  f"of input)")))
    rows.append(("literal runs",
                 f"{stats['n_runs']} (avg {stats['run_avg']:.2f}, max {stats['run_max']})"))
    rows.append(("matches",
                 (f"{stats['n_match']} (match bytes {stats['match_bytes']}, "
                  f"{100.0 * stats['match_bytes'] / input_size:.2f}% of input)")))
    rows.append(("match len",
                 (f"avg {stats['len_avg']:.2f}, min {stats['len_min']}, "
                  f"max {stats['len_max']}")))
    window = stats["window"]
    if analysis.kind == "file" and wbits is None:
        dist_note = "window unknown; pass --window-bits to check"
    elif window is None:
        dist_note = f"window unknown for window_bits={wbits}"
    else:
        dist_note = f"window size {window}"
    rows.append(("match dist",
                 (f"avg {stats['dist_avg']:.2f}, min {stats['dist_min']}, "
                  f"max {stats['dist_max']}   ({dist_note})")))
    if analysis.trailer:
        checksum = " ".join(f"{name}={fmt_trailer_value(name, value)}"
                            for name, value in analysis.trailer)
        rows.append(("checksum", checksum))
    label_width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"  {label + ':':<{label_width + 1}} {value}")
    if window is not None and stats["dist_max"] > window:
        print(f"  WARNING: max match distance {stats['dist_max']} exceeds the "
              f"window size {window} allowed by window_bits={wbits}")


def print_events(analysis, max_events, show_bytes):
    """Print the per-event listing, capped to ``max_events`` when > 0."""
    events = analysis.events
    src = analysis.src
    if not max_events or len(events) <= max_events:
        show = events
        more = 0
    else:
        show = events[:max_events]
        more = len(events) - max_events
    print(f"=== events ({len(events)} total) ===")
    off = 0
    for ev in show:
        print(f"  {off:010d}  {fmt_event(ev, off, src, show_bytes)}")
        off += ev[1]
    if more:
        print(f"  ... {more} more events (use --max-events to raise the cap)")


def _eff_rows(litlen, dist):
    """Flatten the lit/len and distance efficiency totals into table rows.

    Each row is (name, n_symbols, actual_bits, ideal_bits, overhead,
    overhead_per_symbol)."""
    out = []
    for name, tree in (("lit/length", litlen), ("distance", dist)):
        actual, ideal, count = tree["total"]
        out.append((name, count, actual, ideal, actual - ideal,
                    (actual - ideal) / count if count else 0.0))
    return out


_BUDGET_ROWS = (("lit/length symbols", "litlen"),
                ("length extra bits", "len_extra"),
                ("distance symbols", "dist"),
                ("distance extra bits", "dist_extra"),
                ("stored payload", "stored"),
                ("headers + align", "header"))


def _sym_label(sym, tree="litlen"):
    """Human label for a Huffman symbol: literal byte, len/dist range, or eob."""
    if tree == "dist":
        lo = DIST_BASE[sym]
        hi = lo + (1 << DIST_EXTRA[sym]) - 1
        return f"dist {lo}" if lo == hi else f"dist {lo}..{hi}"
    if sym == 256:
        return "eob"
    if sym >= 257:
        len_idx = sym - 257
        lo = LENGTH_BASE[len_idx]
        hi = lo + (1 << LENGTH_EXTRA[len_idx]) - 1
        return f"len {lo}..{hi}" if lo != hi else f"len {lo}"
    if 32 <= sym < 127:
        return f"'{chr(sym)}' {sym:02x}"
    return f"0x{sym:02x}"


def print_huffman(analysis, show_symbols=False):
    """Print the Huffman efficiency + bit-budget report (per-symbol if asked)."""
    huff, budget = analysis.stats["huff"], analysis.stats["budget"]
    print("=== huffman efficiency (actual vs entropy bits) ===")
    print(f"  {'tree':<12} {'symbols':>9} {'actual':>11} {'entropy':>11} "
          f"{'overhead':>11} {'ovh/sym':>8}")
    for name, count, actual, ideal, overhead, ovh_sym in _eff_rows(
            huff["litlen"], huff["dist"]):
        print(f"  {name:<12} {count:>9} {actual:>11} {ideal:>11.0f} "
              f"{overhead:>11.0f} {ovh_sym:>7.2f}b")
    scopes = [scope for scope in ("fixed", "dynamic")
              if huff["litlen"][scope][2] or huff["dist"][scope][2]]
    if scopes:
        print()
        print("  overhead by block type:")
        for scope in scopes:
            litlen, dist = huff["litlen"][scope], huff["dist"][scope]
            litlen_ovs = (litlen[0] - litlen[1]) / litlen[2] if litlen[2] else 0.0
            dist_ovs = (dist[0] - dist[1]) / dist[2] if dist[2] else 0.0
            print(f"  {scope:<8} lit/length {litlen_ovs:.2f}b/sym "
                  f"({litlen[2]} symbols)   distance {dist_ovs:.2f}b/sym "
                  f"({dist[2]} symbols)")
    print()
    print("=== bit budget (deflate stream) ===")
    total = budget["total"] or 1
    for label, key in _BUDGET_ROWS:
        bits = budget[key]
        print(f"  {label:<20} {bits:>10} bits  ({100.0 * bits / total:5.1f}%)")
    print(f"  {'total':<20} {budget['total']:>10} bits  (100.0%)")
    if show_symbols:
        print_huff_symbols(analysis)


def print_huff_symbols(analysis, top=15):
    """Print the top-``top`` symbols per tree: freq, avg code length, ideal."""
    print()
    litlen, dist = _symbol_stats(analysis.block_trees)
    for title, stats, tree in (("lit/length", litlen, "litlen"),
                               ("distance", dist, "dist")):
        if not stats:
            continue
        total = sum(entry[0] for entry in stats.values())
        rows = []
        for sym, (freq, bits) in stats.items():
            avg_len = bits / freq
            ideal = -math.log2(freq / total)
            rows.append((_sym_label(sym, tree), freq, avg_len, ideal,
                         avg_len - ideal))
        rows.sort(key=lambda row: -row[1])
        rows = rows[:top]
        label_width = max(len(row[0]) for row in rows)
        print(f"=== {title}: top {len(rows)} symbols by frequency ===")
        print(f"  {'symbol':<{label_width}} {'freq':>8} {'avg len':>8} "
              f"{'ideal':>7} {'gap':>6}")
        for label, freq, avg_len, ideal, gap in rows:
            print(f"  {label:<{label_width}} {freq:>8} {avg_len:>8.2f} "
                  f"{ideal:>7.2f} {gap:>+6.2f}")
        print()


def print_match_economics(analysis, axis_linear, color):
    """Print the match cost/benefit report: a summary, the per-distance
    break-even boundary table, and the 2-D cost map (bits / matched byte)."""
    eco = _match_costs(analysis.events, analysis.block_trees)
    if eco["n_match"] == 0:
        print("=== match economics (cost vs benefit) ===\n  (no matches)")
        return
    bpb = eco["bits_per_matched_byte"]
    print("=== match economics (cost vs benefit) ===")
    print(f"  matches            {eco['n_match']}")
    print(f"  matched bytes      {eco['total_matched_bytes']}")
    print(f"  match bits         {eco['total_match_bits']}  "
          f"({bpb:.2f} bits/matched byte)")
    print(f"  literal cost       {eco['literal_bpb']:.2f} bits/byte "
          "(the all-literals alternative)")
    pct_b = (100.0 * eco["bytes_wasteful"] / eco["total_matched_bytes"]
             if eco["total_matched_bytes"] else 0.0)
    pct_m = 100.0 * eco["n_wasteful"] / eco["n_match"]
    print(f"  wasteful matches   {eco['n_wasteful']} ({pct_m:.1f}%) covering "
          f"{eco['bytes_wasteful']} bytes ({pct_b:.1f}%)")
    print(f"  overpayment        {eco['overpayment_bits']:.3f} bits (match bits "
          "above the literal alternative)")
    dominant = eco["dominant_cell"]
    if dominant is not None:
        (dc, lc), over = dominant
        print(f"  dominant cell      dist code {dc} x len code {lc} "
              f"(+{over:.3f} bits overpaid)")
    print()
    if eco["overpayment_bits"] > 0:
        print("=== match cost/benefit boundary (by distance) ===")
        print("  break-even = the largest match length still wasteful in the "
              "band")
        print(f"  {'distance':^11} {'match':^9} {'break-even':^11} "
              f"{'wasteful':^9} {'wasteful':^9} {'overpay':^12}")
        print(f"  {'band':^11} {'count':^9} {'length':^11} {'matches':^9} "
              f"{'bytes':^9} {'bits':^12}")
        for dc, n, be, wasteful, wbytes, over in eco["dist_rows"]:
            lo = DIST_BASE[dc]
            hi = lo + (1 << DIST_EXTRA[dc]) - 1
            label = str(lo) if lo == hi else f"{lo}-{hi}"
            if be or wasteful or wbytes or over:
                be_s, wa_s, by_s, ov_s = (str(be), str(wasteful),
                                          str(wbytes), f"{over:.3f}")
            else:
                be_s = wa_s = by_s = ov_s = "-"
            print(f"  {label:>11} {n:>9} {be_s:>11} {wa_s:>9} "
                  f"{by_s:>9} {ov_s:>12}")
        print()
    print_cost_map(eco["cost_hist"], axis_linear, color)


def print_huffman_diff(a, b):
    """Print the side-by-side Huffman efficiency + bit-budget report (A vs B)."""
    litlen_a, dist_a = a.stats["huff"]["litlen"], a.stats["huff"]["dist"]
    litlen_b, dist_b = b.stats["huff"]["litlen"], b.stats["huff"]["dist"]
    print("=== huffman efficiency (A vs B) ===")
    print(f"  {'metric':<12} {'A':>12} {'B':>12}")
    for title, eff_a, eff_b in (("lit/length", litlen_a, litlen_b),
                                ("distance", dist_a, dist_b)):
        count_a, actual_a, ideal_a = eff_a["total"]
        count_b, actual_b, ideal_b = eff_b["total"]
        print(f"  {title}")
        for label, val_a, val_b in (("symbols", count_a, count_b),
                                    ("actual bits", actual_a, actual_b),
                                    ("entropy bits", ideal_a, ideal_b),
                                    ("overhead", actual_a - ideal_a,
                                     actual_b - ideal_b)):
            print(f"  {label:<12} {val_a:>12.0f} {val_b:>12.0f}")
        ovh_a = (actual_a - ideal_a) / count_a if count_a else 0.0
        ovh_b = (actual_b - ideal_b) / count_b if count_b else 0.0
        print(f"  {'ovh/sym':<12} {f'{ovh_a:.2f}b':>12} {f'{ovh_b:.2f}b':>12}")
    print()
    print("=== bit budget (A vs B) ===")
    budget_a, budget_b = a.stats["budget"], b.stats["budget"]
    print(f"  {'metric':<20} {'A':>14}   {'B':>14}")
    for label, key in list(_BUDGET_ROWS) + [("total", "total")]:
        val_a, val_b = budget_a[key], budget_b[key]
        pct_a = 100.0 * val_a / budget_a["total"] if budget_a["total"] else 0.0
        pct_b = 100.0 * val_b / budget_b["total"] if budget_b["total"] else 0.0
        cell_a = f"{val_a:>7} {pct_a:>5.1f}%"
        cell_b = f"{val_b:>7} {pct_b:>5.1f}%"
        print(f"  {label:<20} {cell_a:<14}   {cell_b}")


def metrics_diff_rows(a, b):
    """Build the neutral A/B metric comparison rows for diff mode.

    Returns a list of (metric, val_a, val_b) tuples; values are int or float per
    row and the caller derives the delta (val_b - val_a)."""
    def ratio(analysis):
        return analysis.comp_size / analysis.src_size if analysis.src_size else 0.0
    def bits_byte(analysis):
        return (len(analysis.deflate) * 8 / analysis.src_size
                if analysis.src_size else 0.0)
    def coverage(analysis):
        return (100.0 * analysis.stats["match_bytes"] / analysis.src_size
                if analysis.src_size else 0.0)
    return [
        ("compressed (wrapper)", a.comp_size, b.comp_size),
        ("deflate stream", len(a.deflate), len(b.deflate)),
        ("ratio", ratio(a), ratio(b)),
        ("bits/byte (deflate)", bits_byte(a), bits_byte(b)),
        ("blocks", len(a.blocks), len(b.blocks)),
        ("events", a.stats["n_events"], b.stats["n_events"]),
        ("matches", a.stats["n_match"], b.stats["n_match"]),
        ("matched bytes", a.stats["match_bytes"], b.stats["match_bytes"]),
        ("matched coverage %", coverage(a), coverage(b)),
        ("avg match length", a.stats["len_avg"], b.stats["len_avg"]),
        ("max match length", a.stats["len_max"], b.stats["len_max"]),
        ("avg distance", a.stats["dist_avg"], b.stats["dist_avg"]),
        ("max distance", a.stats["dist_max"], b.stats["dist_max"]),
        ("literals", a.stats["n_lit"], b.stats["n_lit"]),
        ("literal runs", a.stats["n_runs"], b.stats["n_runs"]),
    ]


def _print_ab_table(title, rows):
    """Render a neutral A/B comparison table: the title, then one row per
    ``(metric, val_a, val_b)`` with float/int formatting, the side delta, and
    the delta percent (a dash when the A value is zero)."""
    print(title)
    print(f"  {'metric':<22} {'A':>12} {'B':>12} {'delta':>12} {'delta %':>9}")
    for metric, val_a, val_b in rows:
        delta = val_b - val_a
        if isinstance(val_a, float):
            a_s, b_s, d_s = f"{val_a:.4f}", f"{val_b:.4f}", f"{delta:+.4f}"
        else:
            a_s, b_s, d_s = str(val_a), str(val_b), f"{delta:+d}"
        dpct_s = f"{(100.0 * delta / val_a):+.2f}%" if val_a else "  -"
        print(f"  {metric:<22} {a_s:>12} {b_s:>12} {d_s:>12} {dpct_s:>9}")


def print_metrics_diff(a, b):
    """Render the neutral A/B metric table (A / B / delta / delta %)."""
    _print_ab_table("=== metrics (A vs B) ===", metrics_diff_rows(a, b))


def economics_diff_rows(eco_a, eco_b):
    """Build the neutral A/B match-economics rows from two _match_costs dicts."""
    def pct(eco, key):
        return (100.0 * eco[key] / eco["total_matched_bytes"]
                if eco["total_matched_bytes"] else 0.0)
    return [
        ("matches", eco_a["n_match"], eco_b["n_match"]),
        ("matched bytes", eco_a["total_matched_bytes"],
         eco_b["total_matched_bytes"]),
        ("match bits", eco_a["total_match_bits"], eco_b["total_match_bits"]),
        ("bits/matched byte", eco_a["bits_per_matched_byte"],
         eco_b["bits_per_matched_byte"]),
        ("literal cost (b/byte)", eco_a["literal_bpb"], eco_b["literal_bpb"]),
        ("wasteful matches", eco_a["n_wasteful"], eco_b["n_wasteful"]),
        ("wasteful bytes %", pct(eco_a, "bytes_wasteful"),
         pct(eco_b, "bytes_wasteful")),
        ("overpayment (bits)", eco_a["overpayment_bits"],
         eco_b["overpayment_bits"]),
    ]


def print_match_economics_diff(a, b, axis_linear, color):
    """Print the diff-mode match cost report: an A/B summary table and a
    side-by-side cost map on the shared fixed 0.0-8.0 bits/byte scale, plus a
    pointer to analyze mode for the per-distance detail (break-even boundary,
    dominant cell) it omits."""
    eco_a = _match_costs(a.events, a.block_trees)
    eco_b = _match_costs(b.events, b.block_trees)
    if eco_a["n_match"] == 0 and eco_b["n_match"] == 0:
        print("=== match economics (cost vs benefit, A vs B) ===\n"
              "  (no matches)")
        return
    _print_ab_table("=== match economics (cost vs benefit, A vs B) ===",
                    economics_diff_rows(eco_a, eco_b))
    print()
    print_cost_map_diff(eco_a["cost_hist"], eco_b["cost_hist"],
                        axis_linear, color)
    print()
    print("  note: diff mode shows the summary + cost map only; for more "
          "in-depth details")
    print("        (per-distance break-even boundary, dominant overpaid cell) "
          "use analyze mode")


def _human_bytes(n):
    """Format a byte count with a decimal SI suffix (K/M/G/T)."""
    value = float(n)
    for unit in ("", "K", "M", "G", "T"):
        if value < 1000 or unit == "T":
            return f"{value:.0f}{unit}"
        value /= 1000
    return f"{value:.0f}T"


def _human_rate(rate):
    """Format a bytes/second rate to one decimal with an auto unit (1.6M, 65.3K)."""
    value = float(rate)
    for unit, base in (("B", 1), ("K", 1000), ("M", 1000**2),
                       ("G", 1000**3), ("T", 1000**4)):
        if value < base * 1000:
            return f"{value / base:.1f}{unit}"
    return f"{value / 1000**4:.1f}T"


class Progress:
    """A stderr progress bar tracking decoded source bytes during a parse.

    Renders by overwriting a single line with ``\\r`` so the report/JSON written
    to stdout stays clean, and writes at most once per ``interval`` seconds.
    Each frame shows the decoded fraction plus a live bytes/sec rate; the line
    is space-padded to the longest frame seen so far so a shorter frame fully
    overwrites the previous one. On ``finish`` a final "Decoding finished ..."
    line with the average rate is printed. It is enabled only when the caller
    allows it *and* stderr is a TTY, so piped or redirected runs are silent."""
    __slots__ = (
        "enabled",
        "fh",
        "interval",
        "label",
        "last_len",
        "last_time",
        "t0",
        "total",
    )

    def __init__(self, total, interval=0.5, label="", fh=None, enabled=True):
        """Create a bar over ``total`` bytes; ``enabled`` gates on the TTY."""
        self.total = total
        self.interval = interval
        self.label = label
        self.fh = fh if fh is not None else sys.stderr
        self.enabled = bool(enabled) and self.fh.isatty() and total > 0
        # Seed so the first update always renders (monotonic() may be small).
        self.last_time = -interval
        self.t0 = time.monotonic()
        self.last_len = 0

    def update(self, done):
        """Advance the bar to ``done`` bytes, at most once per interval."""
        if not self.enabled or done < 0 or done > self.total:
            return
        now = time.monotonic()
        if (now - self.last_time) >= self.interval:
            self.last_time = now
            self._render(done)

    def finish(self):
        """Render the final frame, then a "Decoding finished" rate summary."""
        if not self.enabled:
            return
        self._render(self.total)
        self.fh.write("\n")
        elapsed = time.monotonic() - self.t0
        rate = self.total / elapsed if elapsed > 0 else 0.0
        self.fh.write(f"Decoding finished in {elapsed:.1f}s at "
                      f"{_human_rate(rate)}/s\n")
        self.fh.flush()

    def _render(self, done):
        """Write one overwritten progress line for ``done`` decoded bytes."""
        frac = done / self.total if self.total else 0.0
        elapsed = time.monotonic() - self.t0
        rate = done / elapsed if elapsed >= 0.05 else 0.0
        width = 24
        filled = int(width * frac)
        bar = "#" * filled + "-" * (width - filled)
        label = f"{self.label} " if self.label else ""
        line = (f"{label}[{bar}] {frac * 100:3.0f}%  "
                f"{_human_bytes(done)}/{_human_bytes(self.total)}  "
                f"{_human_rate(rate)}/s")
        # Pad to the longest frame so far so a shorter one erases the rest.
        if len(line) < self.last_len:
            line += " " * (self.last_len - len(line))
        self.last_len = len(line)
        self.fh.write("\r" + line)
        self.fh.flush()


def cmd_analyze(args, lib, src, comp):
    """'analyze': compress with one library and print the full report."""
    progress = Progress(len(src), enabled=args.progress)
    analysis = Analysis(lib, args.options, src, comp, on_progress=progress.update)
    progress.finish()
    verified = True
    if args.verify:
        ok, _ = inflate_check(src, comp, analysis.wrapper)
        verified = ok
        if not ok:
            raise SystemExit("error: inflate check failed")
    if args.json:
        _dump(_analysis_json("analyze", os.path.basename(args.file),
                             analysis, verified, args.events,
                             args.json_full))
        return
    print_summary(analysis, f"analysis: {os.path.basename(args.file)}")
    if args.verify:
        print("  inflate check: ok")
    print()
    if args.events:
        print_events(analysis, args.max_events, args.show_bytes)
        print()
    print_length_hist(analysis.stats["len_hist"], analysis.stats["n_match"],
                      args.length_full)
    print()
    print_dist_hist(analysis.stats["dist_hist"], analysis.stats["n_match"],
                    args.dist_log2)
    print()
    print_match_map(analysis.stats["pair_hist"], args.map_axis_linear,
                    args.map_scale_log2, resolve_map_color(args))
    print()
    print_match_economics(analysis, args.map_axis_linear,
                          resolve_map_color(args))
    print()
    print_huffman(analysis, args.huff_symbols)


def cmd_analyze_file(args, comp):
    """'analyze-file': analyze an existing .gz/.zlib/.def stream, a .png's IDAT
    deflate stream, or the deflate entries of a .zip/.jar/.apk, recovering the
    input with system zlib and cross-checking the internal parser against it."""
    import zlib  # system zlib, used only in this mode (verify + recover source)
    name = os.path.basename(args.file)
    png_header = None
    n_idat = 0
    if comp.startswith(PNG_SIGNATURE):
        try:
            png_header, idat, n_idat = parse_png(comp)
        except DeflateError as e:
            raise SystemExit(f"error: {args.file}: {e}") from e
        comp = idat
    if comp.startswith(ZIP_LOCAL_MAGIC):
        analyze_zip_file(args, comp, name, zlib)
        return
    detected = detect_wrapper(comp)
    _deflate, wrapper, _trailer = detected
    wbits = {"zlib": 15, "gzip": 31, "raw": -15}[wrapper]
    try:
        src = zlib.decompress(comp, wbits)
    except zlib.error as e:
        raise SystemExit(f"error: system zlib failed to inflate "
                         f"{args.file} ({wrapper}): {e}") from e
    # Internal decode must reproduce the system zlib's output exactly.
    options = (None, args.window_bits, None, None)
    progress = Progress(len(src), enabled=args.progress)
    try:
        analysis = Analysis(None, options, src, comp, detected=detected,
                            on_progress=progress.update)
    except DeflateError as e:
        raise SystemExit(f"error: internal decode disagrees with system zlib: "
                         f"{e}") from e
    progress.finish()
    if args.json:
        doc = _analysis_json("analyze-file", name, analysis, True,
                             args.events, args.json_full)
        if png_header is not None:
            doc["png"] = _png_json(png_header, n_idat, len(comp),
                                   png_filter_stats(png_header, src))
        _dump(doc)
        return
    if png_header is not None:
        filters = png_filter_stats(png_header, src)
        print_png_header(png_header, n_idat, len(comp), name, filters)
        print()
    print_summary(analysis, f"analysis: {name}")
    print("  system zlib inflate: ok (internal decode matches)")
    print()
    if args.events:
        print_events(analysis, args.max_events, args.show_bytes)
        print()
    print_length_hist(analysis.stats["len_hist"], analysis.stats["n_match"],
                      args.length_full)
    print()
    print_dist_hist(analysis.stats["dist_hist"], analysis.stats["n_match"],
                    args.dist_log2)
    print()
    print_match_map(analysis.stats["pair_hist"], args.map_axis_linear,
                    args.map_scale_log2, resolve_map_color(args))
    print()
    print_match_economics(analysis, args.map_axis_linear,
                          resolve_map_color(args))
    print()
    print_huffman(analysis, args.huff_symbols)


# ---------------------------------------------------------------------------
# Report: diff of two analyses
# ---------------------------------------------------------------------------

def print_diff(args, a, b):
    """'diff' (non-sweep): report both sides, the Huffman diff, and the
    divergent decision regions side-by-side."""
    if args.json:
        _dump(_diff_json(os.path.basename(args.file), a, b,
                         args.max_diff_regions, args.json_full))
        return
    src_size = a.src_size
    print(f"=== diff: {os.path.basename(args.file)} ({src_size} bytes) ===")
    print(f"  A: {a.lib.path} ({a.lib.version})")
    print(f"     level={a.options[0]} window_bits={a.options[1]} "
          f"mem_level={a.options[2]} "
          f"strategy={STRATEGY_LABELS.get(a.options[3], a.options[3])}")
    print()
    print(f"  B: {b.lib.path} ({b.lib.version})")
    print(f"     level={b.options[0]} window_bits={b.options[1]} "
          f"mem_level={b.options[2]} "
          f"strategy={STRATEGY_LABELS.get(b.options[3], b.options[3])}")
    print()
    print_metrics_diff(a, b)
    print()
    first_diff = first_byte_diff(a.deflate, b.deflate)
    if a.deflate == b.deflate:
        print("  compressed output:  identical")
    else:
        size_delta = b.comp_size - a.comp_size
        print(f"  compressed output:  differ (first differing byte at deflate "
              f"offset {first_diff}, size delta {size_delta:+d})")
    print()
    print_match_map_diff(a, b, args.map_axis_linear, args.map_scale_log2,
                         resolve_map_color(args))
    print()
    print_match_economics_diff(a, b, args.map_axis_linear,
                               resolve_map_color(args))
    print()
    print_huffman_diff(a, b)
    print()
    regions, n_regions, covered = find_divergences(a.events, b.events)
    if not regions:
        print("  decisions:     identical for the whole input")
        return
    first = regions[0][0]
    print(f"  decisions:     first divergence at input offset {first}; "
          f"{n_regions} divergent regions covering {covered} input bytes "
          f"({100.0 * covered / src_size:.2f}% of input)")
    print()
    shown = regions[:args.max_diff_regions]
    for region_idx, (start, region_end, i_first, i_end, j_first, j_end) in \
            enumerate(shown, 1):
        events_a = a.events[i_first:i_end]
        events_b = b.events[j_first:j_end]
        context = min(args.context, i_first, j_first)
        print(f"@@ region {region_idx}/{len(shown)}: input offset {start} "
              f"(A: {len(events_a)} events, B: {len(events_b)} events) @@")
        col_width = 36
        a_col_width = 11 + col_width  # offset(10) + space(1) + event(col_width)
        head_a = f"A: {a.lib.label} (wb={a.options[1]})"
        head_b = f"B: {b.lib.label} (wb={b.options[1]})"
        print(f"   {head_a:<{a_col_width}}  {head_b}")
        # context: up to ``context`` events preceding the divergence, per side
        ctx_i = i_first - context
        ctx_shown = 0
        while ctx_shown < context and 0 <= ctx_i < i_first:
            off_a = event_offset(a.events, ctx_i)
            off_b = event_offset(b.events, j_first - (i_first - ctx_i))
            ctx_row_a = fmt_event(a.events[ctx_i], off_a)
            ctx_row_b = fmt_event(b.events[j_first - (i_first - ctx_i)], off_b)
            print(f"   {off_a:010d} {ctx_row_a:<{col_width}}  "
                  f"{off_b:010d} {ctx_row_b}")
            ctx_i += 1
            ctx_shown += 1
        # divergent rows, aligned by position within the region
        off_a, off_b = start, start
        cap = args.max_diff_events
        row_count = max(len(events_a), len(events_b))
        if cap and row_count > cap:
            row_count = cap
        for row_idx in range(row_count):
            row_a = (f"{off_a:010d} {fmt_event(events_a[row_idx], off_a)}"
                     if row_idx < len(events_a) else "")
            row_b = (f"{off_b:010d} {fmt_event(events_b[row_idx], off_b)}"
                     if row_idx < len(events_b) else "")
            print(f" ! {row_a:<{a_col_width}}  {row_b}")
            if row_idx < len(events_a):
                off_a += events_a[row_idx][1]
            if row_idx < len(events_b):
                off_b += events_b[row_idx][1]
        span, (na, ma, la, alen), (nb, mb, lb, blen) = _region_effect(
            events_a, events_b, start, region_end)
        print(f"   region effect (span {span} bytes @ {start}..{start + span}):")
        print(f"     A: {na} match(es), {ma} matched / {la} literal, "
              f"avg len {alen:.1f}")
        print(f"     B: {nb} match(es), {mb} matched / {lb} literal, "
              f"avg len {blen:.1f}")
        if ma != mb:
            winner = "A" if ma > mb else "B"
            print(f"     -> {winner} matched {abs(ma - mb)} more of the "
                  f"{span} bytes ({ma} vs {mb})")
        if cap and max(len(events_a), len(events_b)) > cap:
            print(f"   ... region truncated at {cap} rows "
                  f"(use --max-diff-events to raise the cap)")
        if len(regions) > args.max_diff_regions:
            break
    if n_regions > args.max_diff_regions:
        extra = n_regions - args.max_diff_regions
        print(f"  ... {extra} more divergent regions "
              f"(use --max-diff-regions to raise the cap)")


def cmd_sweep(args, lib_a, lib_b, src):
    """'diff --sweep': compact per-level size / first-divergence report."""
    _level_a, wbits_a, mem_a, strat_a = args.options_a
    _level_b, wbits_b, mem_b, strat_b = args.options_b
    if args.json:
        _dump(_sweep_doc(os.path.basename(args.file), lib_a, lib_b,
                         args.options_a, args.options_b, src, args.levels))
        return
    print(f"=== sweep: {os.path.basename(args.file)} ({len(src)} bytes) ===")
    print(f"  A: {lib_a.path} ({lib_a.version})")
    print(f"     window_bits={wbits_a} mem_level={mem_a} "
          f"strategy={STRATEGY_LABELS.get(strat_a, strat_a)}")
    print()
    print(f"  B: {lib_b.path} ({lib_b.version})")
    print(f"     window_bits={wbits_b} mem_level={mem_b} "
          f"strategy={STRATEGY_LABELS.get(strat_b, strat_b)}")
    print()
    print(f"  {'level':>5}  {'A size':>10}  {'B size':>10}  {'delta':>8}  status")
    for level in args.levels:
        comp_a = lib_a.compress(src, level, wbits_a, mem_a, strat_a)
        comp_b = lib_b.compress(src, level, wbits_b, mem_b, strat_b)
        if comp_a == comp_b:
            print(f"  {level:>5}  {len(comp_a):>10}  {len(comp_b):>10}  "
                  f"{0:>8}  identical")
            continue
        defl_a, _, trailer_a = split_wrapper(comp_a, wbits_a)
        defl_b, _, trailer_b = split_wrapper(comp_b, wbits_b)
        _, events_a, _trees_a = parse_deflate(defl_a, src, verify=False)
        _, events_b, _trees_b = parse_deflate(defl_b, src, verify=False)
        div_offset = first_divergence_offset(events_a, events_b)
        first_diff = first_byte_diff(comp_a, comp_b)
        size_delta = len(comp_b) - len(comp_a)
        line = (f"  {level:>5}  {len(comp_a):>10}  {len(comp_b):>10}  "
                f"{size_delta:>+8}  differs: first decision diff at input offset "
                f"{div_offset if div_offset is not None else 'n/a'} "
                f"(first stream byte diff at {first_diff})")
        print(line)
        for (name_a, val_a), (name_b, val_b) in zip(trailer_a, trailer_b,
                                                    strict=False):
            mark = "same" if val_a == val_b else "DIFF"
            print(f"{' ' * 43}{name_a}: A={fmt_trailer_value(name_a, val_a)} "
                  f"B={fmt_trailer_value(name_b, val_b)} [{mark}]")


# ---------------------------------------------------------------------------
# JSON output (machine-parseable, --json)
# ---------------------------------------------------------------------------

_JSON_HIST_TOP = 50


def _jsonable(obj):
    """Recursively convert Counters, tuples, and tuple dict-keys into values
    that json.dumps can serialize directly (tuple keys become 'a-b' strings)."""
    if isinstance(obj, Counter):
        obj = dict(obj)
    if isinstance(obj, dict):
        return {_json_key(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


def _json_key(key):
    """Make a dict key JSON-safe: a tuple key becomes a dashed string, and any
    other non-string key (e.g. an integer histogram bucket) is stringified."""
    if isinstance(key, tuple):
        return "-".join(str(x) for x in key)
    if not isinstance(key, str):
        return str(key)
    return key


def _trim_counter(counter, top=_JSON_HIST_TOP):
    """Cap a Counter to its top-``top`` items by count.

    Returns (kept_dict, n_total, n_kept) so callers can note the truncation."""
    kept = dict(counter.most_common(top))
    return kept, len(counter), len(kept)


def _trim_stats(stats, full):
    """Copy of ``stats`` with the match histograms (len/dist/pair) capped to the
    top _JSON_HIST_TOP items by count unless ``full``; records truncation in a
    ``_truncated`` note."""
    out = dict(stats)
    notes = []
    for name in ("len_hist", "dist_hist", "pair_hist"):
        hist = out.get(name)
        if full or not isinstance(hist, Counter):
            continue
        kept, total, n = _trim_counter(hist)
        out[name] = kept
        if total > n:
            notes.append(f"{name}: top {n} of {total}")
    if notes:
        out["_truncated"] = "; ".join(notes)
    return out


def _trim_economics(eco, full):
    """Copy of ``eco`` with cost_hist capped to the top _JSON_HIST_TOP cells by
    matched bytes unless ``full``; records truncation in a ``_truncated``
    note."""
    out = dict(eco)
    hist = out.get("cost_hist")
    if full or not isinstance(hist, dict) or len(hist) <= _JSON_HIST_TOP:
        return out
    ranked = sorted(hist.items(), key=lambda kv: kv[1][1], reverse=True)
    out["cost_hist"] = dict(ranked[:_JSON_HIST_TOP])
    out["_truncated"] = (f"cost_hist: top {_JSON_HIST_TOP} of {len(hist)} "
                         f"by matched bytes")
    return out


def _options_dict(options):
    """Render a (level, window_bits, mem_level, strategy) options tuple."""
    level, wbits, mem, strat = options
    return {"level": level, "window_bits": wbits, "mem_level": mem,
            "strategy": strat}


def _analysis_json(mode, name, analysis, verified, include_events, full):
    """Build the JSON document for one analyze / analyze-file deflate stream.

    Unless ``full``, the large match histograms and the cost map are capped to
    the top _JSON_HIST_TOP entries (see ``_trim_stats``/``_trim_economics``)."""
    eco = _match_costs(analysis.events, analysis.block_trees)
    doc = {
        "mode": mode,
        "file": name,
        "wrapper": analysis.wrapper,
        "comp_size": analysis.comp_size,
        "src_size": analysis.src_size,
        "deflate_size": len(analysis.deflate),
        "options": _options_dict(analysis.options),
        "verified": verified,
        "stats": _jsonable(_trim_stats(analysis.stats, full)),
        "economics": _jsonable(_trim_economics(eco, full)),
        "blocks": list(analysis.blocks),
    }
    if include_events:
        doc["events"] = analysis.events
    return doc


def _png_json(header, n_idat, idat_size, filters):
    """Build the JSON 'png' section (IHDR fields + IDAT layout + filter counts)."""
    doc = {
        "width": header["width"],
        "height": header["height"],
        "bit_depth": header["bit_depth"],
        "color_type": header["color_type"],
        "color": PNG_COLOR_TYPES.get(header["color_type"], "unknown"),
        "interlace": header["interlace"],
        "n_idat": n_idat,
        "idat_size": idat_size,
        "filters": None,
    }
    if filters is not None:
        counts, n_rows = filters
        doc["filters"] = {f: counts[f] for f in sorted(counts)}
        doc["n_scanlines"] = n_rows
    return doc


def _zip_entries_json(entries):
    """Per-entry basic stats (name, method, sizes, ratio) for the ZIP table."""
    return [{
        "name": entry["name"],
        "method": entry["method"],
        "csize": entry["csize"],
        "usize": entry["usize"],
        "ratio": (entry["csize"] / entry["usize"]
                  if entry["usize"] else 0.0),
    } for entry in entries]


def _zip_json(name, comp, entries, wbits, zlib, full):
    """Build the JSON document for an analyzed .zip/.jar/.apk (aggregated)."""
    options = (None, wbits, None, None)
    deflate_entries = [(idx, entry) for idx, entry in enumerate(entries)
                       if entry["method"] == ZIP_METHOD_DEFLATE]
    analyses = []
    for _idx, entry in deflate_entries:
        raw = comp[entry["data_offset"]:entry["data_offset"] + entry["csize"]]
        try:
            src = zlib.decompress(raw, -15)
        except zlib.error as e:
            raise SystemExit(f"error: system zlib failed to inflate entry "
                             f"{entry['name']!r}: {e}") from e
        if len(src) != entry["usize"]:
            raise SystemExit(f"error: entry {entry['name']!r}: decompressed "
                             f"{len(src)} bytes but zip usize is {entry['usize']}")
        analyses.append(Analysis(None, options, src, raw,
                                 detected=(raw, "raw", [])))
    agg = aggregate_analyses(analyses, wbits)
    # Renumber each block's span to global event indices so _match_costs maps
    # every match to its own entry's tree (as the human reporter does).
    merged_events: list = []
    merged_trees: list = []
    for part in analyses:
        offset = len(merged_events)
        merged_events.extend(part.events)
        merged_trees.extend(
            {**tree, "ev_start": tree["ev_start"] + offset,
             "ev_end": tree["ev_end"] + offset} for tree in part.block_trees)
    return {
        "mode": "analyze-file",
        "file": name,
        "wrapper": "zip",
        "comp_size": len(comp),
        "src_size": agg["src_size"],
        "n_entries": len(entries),
        "n_deflate": len(analyses),
        "window_bits": wbits,
        "entries": _zip_entries_json(entries),
        "aggregate": _jsonable(_trim_stats(agg, full)),
        "economics": _jsonable(_trim_economics(_match_costs(merged_events,
                                                            merged_trees),
                                               full)),
    }


def _side_json(analysis, full):
    """One side (A or B) of a diff: identity, options, stats, economics."""
    return {
        "path": analysis.lib.path,
        "version": analysis.lib.version,
        "options": _options_dict(analysis.options),
        "stats": _jsonable(_trim_stats(analysis.stats, full)),
        "economics": _jsonable(_trim_economics(
            _match_costs(analysis.events, analysis.block_trees), full)),
    }


def _regions_json(a, b, cap):
    """The divergent regions, each with a per-side match/literal split."""
    regions, n_regions, covered = find_divergences(a.events, b.events)
    out = []
    for start, end, i_first, i_end, j_first, j_end in regions[:cap]:
        _span, (na, ma, la, alen), (nb, mb, lb, blen) = _region_effect(
            a.events[i_first:i_end], b.events[j_first:j_end], start, end)
        out.append({
            "start": start,
            "end": end,
            "span": end - start,
            "a": {"n_match": na, "matched": ma, "literal": la,
                  "avg_len": alen},
            "b": {"n_match": nb, "matched": mb, "literal": lb,
                  "avg_len": blen},
        })
    return {"n_regions": n_regions, "covered": covered, "regions": out}


def _diff_json(name, a, b, cap, full):
    """Build the JSON document for diff mode (both sides + divergent regions)."""
    identical = a.deflate == b.deflate
    return {
        "mode": "diff",
        "file": name,
        "src_size": a.src_size,
        "a": _side_json(a, full),
        "b": _side_json(b, full),
        "compressed_identical": identical,
        "first_byte_diff": (None if identical
                            else first_byte_diff(a.deflate, b.deflate)),
        "size_delta": b.comp_size - a.comp_size,
        "metrics": [{"metric": metric, "a": va, "b": vb, "delta": vb - va}
                    for metric, va, vb in metrics_diff_rows(a, b)],
        "regions": _regions_json(a, b, cap),
    }


def _sweep_doc(name, lib_a, lib_b, opts_a, opts_b, src, levels):
    """Build the JSON document for diff --sweep (one row per level)."""
    _level_a, wbits_a, mem_a, strat_a = opts_a
    _level_b, wbits_b, mem_b, strat_b = opts_b
    rows = []
    for level in levels:
        comp_a = lib_a.compress(src, level, wbits_a, mem_a, strat_a)
        comp_b = lib_b.compress(src, level, wbits_b, mem_b, strat_b)
        row = {"level": level, "size_a": len(comp_a), "size_b": len(comp_b),
               "delta": len(comp_b) - len(comp_a), "identical": comp_a == comp_b}
        if not row["identical"]:
            defl_a, _, _ = split_wrapper(comp_a, wbits_a)
            defl_b, _, _ = split_wrapper(comp_b, wbits_b)
            _, events_a, _ = parse_deflate(defl_a, src, verify=False)
            _, events_b, _ = parse_deflate(defl_b, src, verify=False)
            row["first_divergence_offset"] = first_divergence_offset(
                events_a, events_b)
            row["first_byte_diff"] = first_byte_diff(comp_a, comp_b)
        rows.append(row)
    return {
        "mode": "diff-sweep",
        "file": name,
        "src_size": len(src),
        "a": {"path": lib_a.path, "version": lib_a.version,
              "options": _options_dict(opts_a)},
        "b": {"path": lib_b.path, "version": lib_b.version,
              "options": _options_dict(opts_b)},
        "rows": rows,
    }


def _is_scalar(value):
    """True for a JSON scalar (string, number, boolean, or null)."""
    return value is None or isinstance(value, (str, int, float, bool))


def _is_inline(value):
    """True for a value that renders compactly on one line: a scalar, or a list
    of scalars (e.g. a [bits, bytes] cost cell)."""
    return (_is_scalar(value)
            or (isinstance(value, list)
                and all(_is_scalar(x) for x in value)))


def _compact_json(obj, indent=0):
    """Serialize a JSON-safe doc compactly: scalar lists and flat (scalar- or
    scalar-list-valued) dicts are inlined on one line; deeper nesting indents one
    level per line. Always valid JSON (parseable by jq)."""
    pad = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        if all(_is_inline(v) for v in obj.values()):
            return ("{" + ", ".join(
                f"{json.dumps(k)}: {_compact_json(v, indent + 1)}"
                for k, v in obj.items()) + "}")
        return ("{\n" + ",\n".join(
            f"{pad}  {json.dumps(k)}: {_compact_json(v, indent + 1)}"
            for k, v in obj.items()) + "\n" + pad + "}")
    if isinstance(obj, list):
        if not obj:
            return "[]"
        if all(_is_scalar(v) for v in obj):
            return "[" + ", ".join(
                _compact_json(v, indent + 1) for v in obj) + "]"
        return ("[\n" + ",\n".join(
            f"{pad}  {_compact_json(v, indent + 1)}" for v in obj)
            + "\n" + pad + "]")
    return json.dumps(obj)


def _dump(doc):
    """Write a JSON document to stdout as compact, valid, jq-parseable JSON."""
    print(_compact_json(_jsonable(doc)))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_pair(value, cast, name):
    """Parse 'V' -> (V, V) or 'A,B' -> (A, B), casting each value with ``cast``."""
    if "," in value:
        parts = value.split(",")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(
                f"{name}: expected 'V' or 'A,B', got {value!r}")
        try:
            return cast(parts[0].strip()), cast(parts[1].strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{name}: bad value in {value!r}") from exc
    try:
        parsed = cast(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{name}: bad value {value!r}") from exc
    return parsed, parsed


def parse_strategy(value):
    """Parse a strategy name or 0-4 integer into its strategy code."""
    tok = value.strip().lower()
    if tok in STRATEGY_NAMES:
        return STRATEGY_NAMES[tok]
    try:
        as_int = int(tok)
        if 0 <= as_int <= 4:
            return as_int
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(
        f"strategy: expected one of {list(STRATEGY_NAMES)} or 0-4, got {value!r}")


def parse_levels(spec):
    """Parse a '1-9,3,5' style list into a sorted list of levels (each 0-9)."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (0 <= lo <= 9 and 0 <= hi <= 9 and lo <= hi):
                raise argparse.ArgumentTypeError(f"levels: bad range {part!r}")
            out.extend(range(lo, hi + 1))
        else:
            level = int(part)
            if not 0 <= level <= 9:
                raise argparse.ArgumentTypeError(f"levels: bad value {part!r}")
            out.append(level)
    return sorted(set(out))


def parse_libs(spec):
    """Parse 'PATH' or 'PATH_A,PATH_B' into the (a, b) library paths."""
    parts = [path.strip() for path in spec.split(",")]
    parts = [path for path in parts if path]
    if len(parts) not in (1, 2):
        raise SystemExit(f"error: --lib takes 'PATH' or 'PATH_A,PATH_B', "
                         f"got {spec!r}")
    if len(parts) == 1:
        return parts[0], parts[0]
    return parts[0], parts[1]


def add_compression_opts(subparser):
    """Add the shared --level/--window-bits/--mem-level/--strategy options."""
    subparser.add_argument("--level", default="6",
                           help="compression level 0-9, or 'A,B' per side in "
                                "diff mode (default: 6)")
    subparser.add_argument("--window-bits", default="15",
                           help="windowBits (8-15 zlib, 16-31 gzip, "
                                "negative = raw), or 'A,B' per side in diff "
                                "mode (default: 15)")
    subparser.add_argument("--mem-level", default="8",
                           help="memLevel 1-9, or 'A,B' per side in diff "
                                "mode (default: 8)")
    subparser.add_argument("--strategy", default="default",
                           help="default|filtered|huffman_only|rle|fixed "
                                "(or 0-4), or 'A,B' per side in diff mode "
                                "(default: default)")


def resolve_options(args, per_side):
    """Resolve the shared options into per-side tuples.

    In diff mode ('per_side') returns four (A, B) pairs; otherwise the 'A,B'
    form is rejected unless both sides are equal and a single tuple is returned."""
    level = parse_pair(args.level, int, "level")
    wbits = parse_pair(args.window_bits, int, "window-bits")
    mem = parse_pair(args.mem_level, int, "mem-level")
    strat = parse_pair(args.strategy, parse_strategy, "strategy")
    if per_side:
        return level, wbits, mem, strat
    for name, pair in (("level", level), ("window-bits", wbits),
                       ("mem-level", mem), ("strategy", strat)):
        if pair[0] != pair[1]:
            raise SystemExit(f"error: {name} 'A,B' form is only valid in diff mode")
    return (level[0], wbits[0], mem[0], strat[0])


def add_map_opts(subparser):
    """Add the distance x length map options: the axis/scale form flags and the
    mutually-exclusive color on/off overrides (auto-detected from the terminal
    when neither is given)."""
    subparser.add_argument("--map-axis-linear", action="store_true",
                           help="bin the distance x length map's axes with "
                                "uniform linear bins (default: deflate "
                                "encoding buckets)")
    subparser.add_argument("--map-scale-log2", action="store_true",
                           help="scale the distance x length map's cell "
                                "shading with log2 (default: honest/linear)")
    color_group = subparser.add_mutually_exclusive_group()
    color_group.add_argument("--map-colors-on", dest="map_colors",
                             action="store_const", const=True,
                             help="force colorized map cells on (overrides the "
                                  "terminal auto-detect)")
    color_group.add_argument("--map-colors-off", dest="map_colors",
                             action="store_const", const=False,
                             help="force plain-glyph map cells (overrides the "
                                  "terminal auto-detect)")


def resolve_map_color(args):
    """Decide whether map cells are colorized: an explicit --map-colors-on/off
    wins; otherwise auto-enable on a 256-color TTY (TERM in the known set)."""
    if args.map_colors is not None:
        return args.map_colors
    term = os.environ.get("TERM", "")
    return sys.stdout.isatty() and term in _MAP_COLOR_TERMS


def add_progress_opt(subparser):
    """Add the --no-progress flag that disables the stderr decode progress bar."""
    subparser.add_argument("--no-progress", action="store_false",
                           dest="progress",
                           help="disable the stderr decode progress bar "
                                "(shown automatically on a TTY)")


def main():
    """Parse CLI arguments and dispatch to the analyze/analyze-file/diff modes."""
    parser = argparse.ArgumentParser(
        prog="zanalyze.py",
        description="Analyze/diff deflate streams produced by zlib(-ng) libraries.",
        epilog=f"zanalyze.py {__version__} — see the module docstring and README for "
               "report details and examples.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_analyze = sub.add_parser("analyze", help="analyze one library's stream")
    p_analyze.add_argument("file")
    p_analyze.add_argument("--lib", required=True,
                           help="path to the zlib(-ng) shared library")
    add_compression_opts(p_analyze)
    p_analyze.add_argument("--events", action="store_true",
                           help="show the per-event listing (off by default)")
    p_analyze.add_argument("--max-events", type=int, default=0,
                           help="cap the per-event listing (0 = all)")
    p_analyze.add_argument("--show-bytes", action="store_true",
                           help="show literal byte values in the event listing")
    p_analyze.add_argument("--no-huff-symbols", action="store_false",
                           dest="huff_symbols",
                           help="do not list the top Huffman symbols per tree "
                                "(they are shown by default)")
    p_analyze.add_argument("--length-full", action="store_true",
                           help="show the match-length histogram as every "
                                "individual length (default: grouped into "
                                "deflate length-code buckets, sans extra bits)")
    p_analyze.add_argument("--dist-log2", action="store_true",
                           help="show the match-distance histogram as log2 "
                                "magnitude buckets (default: grouped into "
                                "deflate distance-code buckets, sans extra "
                                "bits)")
    add_map_opts(p_analyze)
    add_progress_opt(p_analyze)
    p_analyze.add_argument("--no-verify", action="store_true",
                           help="skip the inflate check (the stream is still "
                                "parsed and verified internally)")
    p_analyze.add_argument("--json", action="store_true",
                           help="print machine-parseable JSON instead of the "
                                "human-readable report")
    p_analyze.add_argument("--json-full", action="store_true",
                           help="with --json, do not cap the match histograms "
                                "or cost map to the top "
                                f"{_JSON_HIST_TOP} entries")

    p_analyze_file = sub.add_parser("analyze-file",
                                      help="analyze an existing "
                                           ".gz/.zlib/.def/.png/.zip/.jar/.apk "
                                           "stream")
    p_analyze_file.add_argument("file", help="compressed file to analyze")
    p_analyze_file.add_argument("--window-bits", type=int, default=None,
                                help="window size to check distances against "
                                     "(the original windowBits is unknown "
                                     "for external files)")
    p_analyze_file.add_argument("--events", action="store_true",
                                help="show the per-event listing (off by default; "
                                     "not shown for aggregated .zip/.jar/.apk)")
    p_analyze_file.add_argument("--max-events", type=int, default=0,
                                help="cap the per-event listing (0 = all)")
    p_analyze_file.add_argument("--show-bytes", action="store_true",
                                help="show literal byte values in the event listing")
    p_analyze_file.add_argument("--no-huff-symbols", action="store_false",
                                dest="huff_symbols",
                                help="do not list the top Huffman symbols per "
                                     "tree (they are shown by default)")
    p_analyze_file.add_argument("--length-full", action="store_true",
                                help="show the match-length histogram as every "
                                     "individual length (default: grouped into "
                                     "deflate length-code buckets, sans extra "
                                     "bits)")
    p_analyze_file.add_argument("--dist-log2", action="store_true",
                                 help="show the match-distance histogram as log2 "
                                      "magnitude buckets (default: grouped into "
                                      "deflate distance-code buckets, sans extra "
                                      "bits)")
    add_map_opts(p_analyze_file)
    add_progress_opt(p_analyze_file)
    p_analyze_file.add_argument("--json", action="store_true",
                                help="print machine-parseable JSON instead of "
                                     "the human-readable report")
    p_analyze_file.add_argument("--json-full", action="store_true",
                                help="with --json, do not cap the match "
                                     f"histograms or cost map to the top "
                                     f"{_JSON_HIST_TOP} entries")

    p_diff = sub.add_parser("diff", help="diff two libraries' streams")
    p_diff.add_argument("--lib", required=True,
                        help="path to the library for both sides, or "
                             "'PATH_A,PATH_B' for one per side")
    p_diff.add_argument("file")
    add_compression_opts(p_diff)
    add_map_opts(p_diff)
    add_progress_opt(p_diff)
    p_diff.add_argument("--sweep", action="store_true",
                        help="compact per-level report instead of full diff")
    p_diff.add_argument("--levels", default="1-9",
                        help="levels for --sweep (default: 1-9)")
    p_diff.add_argument("--context", type=int, default=3,
                        help="context events preceding each divergence "
                             "(default: 3)")
    p_diff.add_argument("--max-diff-events", type=int, default=0,
                        help="cap rows per divergent region (0 = all)")
    p_diff.add_argument("--max-diff-regions", type=int, default=50,
                        help="cap divergent regions shown (default: 50)")
    p_diff.add_argument("--no-verify", action="store_true",
                        help="skip the inflate check (the streams are still "
                             "parsed and verified internally)")
    p_diff.add_argument("--json", action="store_true",
                        help="print machine-parseable JSON instead of the "
                             "human-readable report")
    p_diff.add_argument("--json-full", action="store_true",
                        help="with --json, do not cap the match histograms "
                             f"or cost map to the top {_JSON_HIST_TOP} entries")

    args = parser.parse_args()
    if args.cmd == "diff":
        args.levels = parse_levels(args.levels)
    args.verify = not getattr(args, "no_verify", False)

    if args.cmd == "analyze-file":
        with open(args.file, "rb") as fh:
            comp = fh.read()
        if not comp:
            raise SystemExit(f"error: {args.file} is empty")
        cmd_analyze_file(args, comp)
        return

    with open(args.file, "rb") as fh:
        src = fh.read()
    if not src:
        raise SystemExit(f"error: {args.file} is empty")

    if args.cmd == "analyze":
        lib = ZlibLib(args.lib)
        args.options = resolve_options(args, per_side=False)
        comp = lib.compress(src, *args.options)
        cmd_analyze(args, lib, src, comp)
    else:
        lib_a_path, lib_b_path = parse_libs(args.lib)
        lib_a = ZlibLib(lib_a_path)
        lib_b = ZlibLib(lib_b_path)
        level, wbits, mem, strat = resolve_options(args, per_side=True)
        args.options_a = (level[0], wbits[0], mem[0], strat[0])
        args.options_b = (level[1], wbits[1], mem[1], strat[1])
        if args.sweep:
            cmd_sweep(args, lib_a, lib_b, src)
            return
        comp_a = lib_a.compress(src, *args.options_a)
        comp_b = lib_b.compress(src, *args.options_b)
        progress_a = Progress(len(src), label="A", enabled=args.progress)
        a = Analysis(lib_a, args.options_a, src, comp_a,
                     on_progress=progress_a.update)
        progress_a.finish()
        progress_b = Progress(len(src), label="B", enabled=args.progress)
        b = Analysis(lib_b, args.options_b, src, comp_b,
                     on_progress=progress_b.update)
        progress_b.finish()
        if args.verify:
            for name, comp, wrapper in (("A", comp_a, a.wrapper),
                                        ("B", comp_b, b.wrapper)):
                ok, _ = inflate_check(src, comp, wrapper)
                if not ok:
                    raise SystemExit(f"error: inflate check failed for side {name}")
        print_diff(args, a, b)


if __name__ == "__main__":
    main()
