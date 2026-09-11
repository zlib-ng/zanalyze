# deflate-analyze Agent Guide

`zanalyze.py` is a single-file, **stdlib-only** Python CLI tool (needs 3.10+;
`zip(strict=)` is the only version-sensitive feature; CI runs the suite on
3.12 and PyPy 3.11) that
compresses a file with a supplied zlib(-ng) shared library and analyzes the
resulting deflate stream: every match (length + distance), the literal runs
before each match, a summary, match-length/distance histograms, and a
Huffman-coding report (actual vs entropy bits, bit budget, optional per-symbol
detail). It can also diff two libraries (or one library with different options)
and show only the divergent regions of the decision streams side-by-side. It can
further analyze an existing compressed file (`.gz`/`.zlib`/`.def`, a `.png`'s
IDAT deflate stream, reporting the image header, or a `.zip`/`.jar`/`.apk`'s
deflate entries, aggregated across entries with a per-entry stats table) by
recovering the source with system zlib, and can instead `dump-file` it:
the untruncated per-event listing (every literal byte in full hex) of an
existing stream, parser-only — no library and no system zlib involved.

## Files

- `zanalyze.py` — the tool (ctypes binding + deflate parser + reporters + CLI).
- `test_zanalyze.py` — the test suite (parser, wrapper, divergence, metrics, CLI).
- `CHANGELOG.md` — version history (currently 1.20, 1.10 PyPy, 1.00 "Initial release").
- `pyproject.toml` — all linter/checker config: ruff (`[tool.ruff.lint]`),
  mypy (`[tool.mypy]`), and pylint (`[tool.pylint.*]`).
- `.github/workflows/ci.yml` — CI: linters/type check, plus tests (builds zlib-ng).
- `README.md` — user-facing docs with `freeze`-generated screenshots.
- `screenshots/` — `analyze-map.png`, `diff-maps.png`, `sweep.png` (colored
  terminal captures made with `freeze`, `--map-colors-on`; regenerate with the
  exact commands under `## Screenshots (regeneration)`).

## Commands

### Run the tool
```bash
# one library's full report
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin
# per-event listing (off by default) + literal byte hex
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --events --show-bytes
# the top Huffman symbols are listed by default; disable with --no-huff-symbols
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --no-huff-symbols
# a stderr progress bar (decoded bytes + rate) shows while the stream is parsed on
# a TTY; disable it with --no-progress (analyze / analyze-file / diff)
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --no-progress
# machine-parseable JSON instead of the human-readable report (any mode);
# by default the match histograms / cost map are capped to the top 50 entries,
# and --json-full emits the full (uncapped) data
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --json
python3 zanalyze.py analyze --lib build-develop/libz-ng.so file.bin --json --json-full

# analyze an existing compressed file (uses system zlib to recover the source)
python3 zanalyze.py analyze-file file.gz --window-bits 15
# analyze a PNG's IDAT deflate stream (also prints the image header)
python3 zanalyze.py analyze-file image.png
# analyze a ZIP/JAR/APK's deflate entries (aggregated; per-entry table shown)
python3 zanalyze.py analyze-file archive.zip --window-bits 15
# focus the whole report on one deflate entry (optional --zip-entry)
python3 zanalyze.py analyze-file archive.zip --zip-entry 2 --window-bits 15

# dump an existing stream's full per-event listing (parser-only, no library,
# no system zlib — the source is reconstructed by the internal parser); the
# literal runs are shown in full hex; cap with --max-events
python3 zanalyze.py dump-file file.gz --max-events 200
# zip containers need --zip-entry N (plain run lists entries, exits non-zero)
python3 zanalyze.py dump-file archive.zip --zip-entry 2

# diff two libraries (comma form; or per-side options, e.g. different windowBits)
python3 zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so file.bin
python3 zanalyze.py diff --lib build-develop/libz-ng.so file.bin --window-bits 15,12
# compact per-level (1-9) report
python3 zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so file.bin --sweep
# machine-parseable JSON for diff (and diff --sweep)
python3 zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so file.bin --json
```

### Run tests
```bash
python3 test_zanalyze.py            # uses the develop build of zlib-ng by default
python3 test_zanalyze.py PATH       # pass a specific libz-ng.so
```
Set `ZANALYZE_TEST_DATA` to override the cross-check input file (used by CI, which
builds zlib-ng and points at its `test/data/lcet10.txt`).

### Run linters (run from this directory so the config files are picked up)
```bash
ruff check zanalyze.py test_zanalyze.py   # must be clean (see pyproject.toml)
mypy zanalyze.py test_zanalyze.py         # must be clean (see pyproject.toml)
pylint zanalyze.py test_zanalyze.py       # must be 10/10 (see pyproject.toml)
```

## Lint / type standard

- **ruff** (`pyproject.toml` `[tool.ruff.lint]`) — Ruff's default rules plus
  `PERF` (Perflint), `B` (Bugbear), `C4` (Comprehensions), `UP` (Pyupgrade) and
  `FURB` (Refurb): performance, idiom, and legacy-syntax checks. Keep
  `ruff check zanalyze.py test_zanalyze.py` clean.
- **mypy** (`pyproject.toml` `[tool.mypy]`) — pragmatic profile:
  `check_untyped_defs` is on so the bodies of unannotated functions are
  type-checked for real mistakes, but full annotations are **not** required on
  every function (`disallow_untyped_defs` is off). Keep
  `mypy zanalyze.py test_zanalyze.py` clean.
- **pylint** (`pyproject.toml` `[tool.pylint.*]`) — the bar is **no E/F/W** plus
  **docstrings required** (`C0115`/`C0116`). Convention (`C`) and Refactor (`R`)
  checks are disabled (style/structural noise for a single-file CLI), and `W0201`
  is disabled because the ctypes `z_stream` fields are set outside `__init__`.
  Keep both files 10/10.
- **Docstrings** are expected on every function and class, including
  underscore-prefixed helpers and `__init__` methods; add short comments in the
  places where the logic is non-obvious (bit packing, metric math, the
  divergence walk).
- **Names** are expected to not be opaque, and avoid shorter than 3 char names.

## Architecture

- **ctypes binding** — `z_stream` and `zng_stream` (ctypes mirrors of the zlib /
  zlib-ng native structs; the latter's `adler` is `uint32`, so `sizeof` is 104
  vs 112). `ZlibLib` loads a `.so` with `RTLD_LOCAL|RTLD_DEEPBIND` so several
  builds coexist in one process; `self.prefix` is `zng_` when the build exports
  `zng_` names, and `self.stream_type` / `self._init_version` are chosen from it
  so the `deflateInit2_` call (the real ABI-stable symbol, not the 6-arg
  `deflateInit2` macro) passes its version/`sizeof` check. `self.version` shows
  the version, e.g. `zlib-ng 2.3.90 (emulating zlib 1.2.13)` when a build
  exposes both version functions. `compress` runs one `deflate(Z_FINISH)` call.
  `inflate_check` (standalone, not on `ZlibLib`) re-inflates a stream with
  system zlib for a deflate-correctness check.
 - **Deflate parser** — `BitReader` (LSB-first bit cursor; reads are served from a
   cached 8-byte little-endian window keyed on the byte the cursor is in, and
   `pushback(n)` rewinds for the table decoder), `build_huffman` (canonical codes
   from code lengths), `_bitrev`/`_build_decode_table` (a single-level, bit-reversed
   lookup table per tree: index = bit-reversed code, shorter codes tiled across
   every over-read, entries packed `(sym<<16)|len`), `_Decoder` (decodes one
   fixed/dynamic block via one table lookup + over-read push-back per symbol,
   optionally counting per-symbol frequencies, and reporting decoded bytes for the
   progress bar), `parse_deflate` (returns `(blocks, events, block_trees)`; `events`
   partition the input into `["L", count]` and `["M", length, dist]` items; takes an
   `on_progress(done)` callback fired ~every 64 KiB).
- **Wrapper handling** — `split_wrapper` (split by windowBits), `detect_wrapper`
  (by magic bytes), `_gzip_deflate_offset`, `parse_png` (extract the IHDR header
  and concatenate the IDAT chunk payloads into one zlib stream) and
  `png_filter_stats` (count the per-scanline filter types, interlace 0 and
  Adam7), and `parse_zip` (read the EOCD → central directory → local headers to
  get each entry's method/crc/sizes/data offset) — all for `analyze-file`. Trailer
  values (adler32/crc32/isize) are read as stored, **never recomputed**.
- **ZIP aggregation** — `analyze_zip_file` analyzes the deflate (method 8) entries
  of a `.zip`/`.jar`/`.apk` (detected by the `PK\x03\x04` magic, so any extension
  works), recovering each with system zlib and building one `Analysis` per entry;
  `aggregate_analyses` concatenates the per-entry events/block-trees and re-runs
  `_efficiency`/`_bit_budget` so the summary, histograms, and Huffman/bit-budget
  report read as one stream. Stored/other entries get basic stats only (no
  analysis); `print_zip_header`/`print_zip_summary`/`print_zip_entries` render the
  file header, the aggregate summary, and a one-line-per-entry table. An optional
  `--zip-entry N` focuses on one entry: `_zip_focus_entries` (shared by the
  human and `_zip_json` paths) validates N against the entries and restricts the
  deflate list to it, the summary reads `(1 entry)`, `--events` is honored for
  that entry, and on any other file the flag errors.
- **Metrics** — `_tree_bits`, `_efficiency` (actual vs entropy bits per tree),
  `_bit_budget` (splits the stream's bits: lit/len, len-extra, dist, dist-extra,
  stored, header), `_match_costs` (per-match bit cost vs the all-literal
  alternative: summary, per-distance break-even boundary, per-(distance,length)
  cost histogram for the cost map, and the most-overpaid cell),
  `_symbol_stats`, `window_size`.
- **`Analysis`** — a fully-parsed result: wrapper split, decoded events, block
  trees, and the precomputed `stats` dict the reporters read.
- **Divergence** — `find_divergences` (event-index regions where two sides differ),
  `first_divergence_offset`, `first_byte_diff`.
- **Reporters** — `print_summary`, `print_histogram`/`_bar`,
  `print_length_hist`/`length_hist_rows` (match-length, bucketed by length code
  or per length), `print_dist_hist`/`dist_hist_rows` (match-distance, bucketed
   by distance code or log2), `print_match_map`/`match_map_grid` (the 2-D match
     distance x length map: density glyphs, on length rows x distance columns,
     encoding or linear axis, even-bucket linear or log2 shading; framed with a
     top+sides box (open at the ruler), cells solid fg=bg heat blocks on a dark
     blank background in color mode, dim-gray frame, pow2 ruler + legend) and
      `print_match_map_diff` (the side-by-side A vs B map in diff mode: shared
      scale, centered middle row labels, per-side frame + pow2 ruler),
    `print_match_economics` (the match cost/benefit summary + per-distance
      break-even boundary + the 2-D bits/matched-byte cost map via
      `cost_map_grid`/`print_cost_map`, fixed 0.0-8.0 linear shading), `print_events`,
    `print_huffman`/`print_huff_symbols`, `print_diff`/`print_huffman_diff`
    (`_print_ab_table`/`metrics_diff_rows`/`print_metrics_diff` render the neutral
    A/B metric table, `economics_diff_rows`/`print_match_economics_diff`/
    `print_cost_map_diff` render the diff-mode match economics A/B table + the
    side-by-side cost map on a shared scale with a footer hint to `analyze`,
    and `_region_effect` summarizes each divergent region's per-side
    match/literal split), and `cmd_sweep`.
  - **JSON output** (`--json`) — `_jsonable` (recursively makes the stats/economics
    dicts JSON-safe, turning Counters and non-string keys into dashed/string
    strings), then per-mode document builders `_analysis_json` (analyze/
    analyze-file, with `_png_json` for the PNG header and `_zip_json` for the
    aggregated archive (recording a focused `--zip-entry` N in `zip_entry`),
    `_diff_json` (both sides + metrics + regions), and
    `_sweep_doc` (per-level rows). Before building, `_trim_stats`/`_trim_economics`
    cap the large match histograms (`len_hist`/`dist_hist`/`pair_hist`) and the
    cost map to the top `_JSON_HIST_TOP` (50) entries and record a `_truncated`
    note; `--json-full` disables the cap. `_dump` prints the doc via
    `_compact_json` (valid, jq-parseable JSON: scalar lists and flat dicts are
    inlined on one line, deeper nesting indents per level).
  - **CLI** — `argparse` subcommands; `parse_pair`/`parse_strategy`/`parse_levels`/
    `parse_libs`/`resolve_options` handle the `V` vs `A,B` per-side option forms,
    `add_map_opts`/`resolve_map_color` handle the map axis/scale flags and the
    `--map-colors-on/off` overrides (else TTY+TERM auto-detect), and
    `add_progress_opt` adds the `--no-progress` flag (dest `progress`); `main`
    dispatches (after `_prefer_pypy3`: direct launches re-exec under a
    `pypy3` found on PATH, unless already on PyPy, `ZANALYZE_NO_PYPY` is set,
    a `--no-pypy` flag appears in argv, or the `ZANALYZE_ALREADY_PYPY` re-entry
    guard is present; `add_pypy_opt` registers the flag on the top parser and
    all four subparsers). `cmd_analyze`/
    `cmd_analyze_file`/`analyze_zip_file` and the
    `diff` path build a `Progress` (stderr, TTY-gated) and thread its `update`
    into `Analysis` → `parse_deflate` → `_Decoder` (per-side `A`/`B` bars in diff).
    `cmd_dump_file`/`dump_zip` (the `dump-file` mode) print the untruncated
    per-event listing (`print_event_list`, literal runs always in full hex via
    `fmt_event(..., show_bytes=True, hex_cap=None)`) of an existing stream's
    deflate data (PNG IDAT, or one `--zip-entry` of a zip), parsing with the
    internal parser alone — `parse_deflate(data, None, return_out=True)`, whose
    optional `src=None` disables verification and bounds the per-block symbol
    count by the stream's remaining bits instead. It has no progress bar (the
    decoded total is unknowable without zlib) and its `--help` warns the output
    is many times larger than the file.

## Conventions

- **Bit order** (verified against real streams): Huffman **codes** are
  MSB-first on the wire; integer **fields** (bfinal, btype, LEN/NLEN, HLIT/
  HDIST/HCLEN, code-length repeats, extra bits) are LSB-first.
- **Checksums**: adler32/crc32 are only read from the wrapper trailer and
  compared — never recomputed.
- **Window/distance**: the only constraint is `dist <= window_size`.
  `window_size(wbits)`: zlib 8–15 → `2**wbits`; gzip 16–31 → `2**(wbits-16)`;
  raw −15…−8 → `2**(-wbits)`. Note zlib-ng enforces a 512-byte minimum window and
  silently upgrades smaller ones (windowBits 8 → 512-byte window), so a stream
  made with windowBits 8 may legitimately hold distances up to 512.
- **System `zlib`** is used **only** in `analyze-file` mode (lazy import) to
  recover the source and cross-check the internal parser. In `diff`, `--lib` is
  required (no system-zlib fallback); in `dump-file`, `--lib` is not accepted
  and no library or system zlib is touched at all.
- **PNG** (`analyze-file` only): a file starting with the 8-byte PNG signature
  has its IDAT chunk(s) concatenated into one zlib stream and analyzed like any
  other zlib stream; the IHDR (width, height, bit depth, color type, interlace)
  and the per-scanline filter-type distribution (None/Sub/Up/Average/Paeth,
  handling both interlace 0 and Adam7) are printed as a header block. No pixel
  decoding or filter reversal is done — only the IDAT deflate stream and the
   header are reported.
- **ZIP** (`analyze-file` only): a file starting with the 4-byte local-file
  header magic `PK\x03\x04` is a `.zip`/`.jar`/`.apk` (all are just renamed zips,
  so detection is by content, not extension). `parse_zip` reads the EOCD → central
  directory (the authoritative source for method/crc/sizes/offset) → each local
  header (for the data start). Only **deflate** entries (compression method 8) are
  analyzed; their raw (unwrapped) deflate payloads are recovered with system zlib
  and **aggregated into one stream** (`aggregate_analyses`). Stored (method 0) and
  other methods are **not** analyzed — they appear only in the per-entry table with
  basic stats (name, sizes, ratio), and the total uncompressed bytes in non-deflate
  entries are reported as "not deflate". The per-entry Huffman report is **not**
  shown (trees differ per entry); the Huffman/bit-budget report is the aggregate.
  Header values verified against `zip-info.txt`.
 - **Options** (`--level/--window-bits/--mem-level/--strategy`) accept `V` or
   `A,B` (per side); the `A,B` form is only valid in `diff` mode.
 - **Decode progress bar** — `analyze`, `analyze-file` (single-stream and
   `.zip`/`.jar`/`.apk`), and `diff` show a stderr progress bar of decoded source
   bytes while the internal parser runs (the `Progress` class): it overwrites one
   line with `\r`, shows the fraction plus a live bytes/sec rate (one decimal,
   auto unit, e.g. `1.6M`/`65.3K`), and prints a `Decoding finished in Xs at Y/s`
   line on completion. Frames are space-padded to the longest so a shorter frame
   never leaves residue. It writes to **stderr** (stdout stays clean for the
   report/JSON), is enabled only when stderr is a TTY, and is disabled with
   `--no-progress` (sweep has no bar). For a zip the single bar spans all deflate
   entries (each entry's count offset by the earlier entries' total); in `diff`
   side `A` fills, then side `B`.
 - **Report defaults**: the per-event listing is off (`--events`); the
  per-symbol Huffman table is **on by default** (disable with `--no-huff-symbols`);
   the Huffman efficiency + bit-budget report is always shown. Every section's
   content and its status messages (under a `=== ... ===` heading) are
   **2-space indented** (the maps and the diff region side-by-side listing keep
   their own deliberate layouts). The **match
  economics** report (cost vs benefit: a summary, the per-distance break-even
  boundary, and the 2-D bits/matched-byte cost map) is always shown after the
   match map; the boundary table is omitted entirely when the total overpayment is
   0 (it would be all zeroes), and a band with matches but none wasteful shows `-`
   in its break-even/wasteful/bytes/overpay columns (the table header is
   two-line: distance/band, match/count, break-even/length, wasteful/matches,
   wasteful/bytes, overpay/bits, with overpay shown to 3 decimals). The cost map
   uses a **fixed linear 0.0-8.0 bits/byte scale**, so its shading is directly
   comparable across files, runs, and diff sides; cells over 8.0 bits/matched
   byte are overpaid and render as a bright-white 'X' (a plain 'X' in
   non-color mode), and the legend/footer advertise the threshold.
   In `diff` mode the report
  shows a neutral A/B **metrics table** (no winner marker) plus a per-region
  match/literal effect for each divergent region, the A vs B match and cost
  maps, and a **match economics A/B table** (matches, matched bytes, match
  bits, bits/matched byte, literal cost, wasteful matches/bytes %, overpayment)
  with a side-by-side **cost map on a shared scale** and a footer hint pointing
  to `analyze` for the per-distance break-even boundary / dominant cell detail
  it omits;
  `diff --sweep` it stays a compact per-level table. Any mode accepts `--json` to
  print a machine-parseable JSON document instead of the human-readable report. The match-length histogram defaults to
  the **deflate length-code buckets** (each of the 29 length codes shown sans
  its extra bits, "match length encoding histogram (sans extra bits)");
   `--length-full` switches it to one row per individual length ("match length
   histogram"). The match-distance histogram defaults to the **deflate
   distance-code buckets** (each of the 30 distance codes shown sans its extra
    bits, "match distance encoding histogram (sans extra bits)"); `--dist-log2`
    switches it to the log2 magnitude buckets ("match distance histogram (log2
    buckets)"). The **match distance x length map** is always shown after the
    histograms (a 2-D grid, length rows x distance columns, shaded by cell
    count, with a `┃`-marked pow2 distance ruler + glyph legend); it defaults to
    the **deflate encoding buckets** (29 length-codes x 30 distance-codes, fixed
    frame to the 32768 window) and **honest/linear** shading. `--map-axis-linear`
    switches the axes to uniform linear bins (40 x 56); `--map-scale-log2`
    switches the cell shading to a log2 scale. Shading uses **even buckets** (each
     of the 6 density glyphs spans exactly 5 of the 30 thermal steps) on both
     scales. The cell area is **framed** with a box-drawing top + sides (open at
      the ruler; per-grid in diff mode), dim gray in color mode, with the length
      row labels right-aligned against the left frame. Cells are
     **colorized** automatically on a 256-color TTY (`TERM` in
     `xterm-256color`/`putty-256color`) and can be forced with `--map-colors-on` /
     `--map-colors-off`; in color mode each non-blank cell is a **solid fg=bg heat
     block** (the glyph is invisible in color but remains when the ANSI codes are
     stripped on copy) on a dark **xterm 234** blank background, and the legend
     mirrors the cells (a 234 blank swatch + the 30-step ramp). The map is also
     shown in **`diff` mode** as a side-by-side A vs B grid on a shared scale
     (centered middle row labels, per-side frame + ruler), but is **not** shown in
     `--sweep` (which stays a compact table).

## Screenshots (regeneration)

The three `screenshots/*.png` are colored terminal captures made with
[`freeze`](https://github.com/charmbracelet/freeze) (charmbracelet; on this
machine at `/usr/bin/freeze`). Regenerate them whenever the reporters change.
Run each command below with this repo's bash `workdir` set to
`/home/opencode/opencode/zlib-ng` (so the visible command text stays short —
`../deflate-analyze/zanalyze.py`, `build-develop/libz-ng.so`,
`test/data/lcet10.txt`), with the `-o` output path absolute into the
`deflate-analyze/screenshots/` dir.

```bash
# analyze-map.png — match map + match economics + cost map (lcet10, level 6)
freeze --execute "python3 ../deflate-analyze/zanalyze.py analyze --lib build-develop/libz-ng.so test/data/lcet10.txt --map-colors-on --no-progress 2>/dev/null | sed -n '/=== match distance x length map/,/=== huffman/p'" -o /home/opencode/opencode/deflate-analyze/screenshots/analyze-map.png -W 980

# diff-maps.png — side-by-side match + cost maps, per-side level 1 vs 9
freeze --execute "python3 ../deflate-analyze/zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so test/data/lcet10.txt --level 1,9 --map-colors-on --no-progress 2>/dev/null | sed -n '/=== match distance x length map/,/=== huffman/p'" -o /home/opencode/opencode/deflate-analyze/screenshots/diff-maps.png -W 1100

# sweep.png — compact per-level (1-9) table (no colors by design)
freeze --execute "python3 ../deflate-analyze/zanalyze.py diff --lib build-develop/libz-ng.so,build-pr/libz-ng.so test/data/lcet10.txt --sweep 2>/dev/null" -o /home/opencode/opencode/deflate-analyze/screenshots/sweep.png -W 700
```

Gotchas, learned the hard way:

- **`-W` is the image width in pixels, not columns.** freeze renders at the
  terminal's intrinsic cell size and never upscales: a `-W` wider than the
  content only adds right-hand blank margin, too small a `-W` rescales the text
  into an unreadable mush *without changing the line count* (heights are
  width-independent). The tuned values above (analyze 980, diff 1100, sweep
  700) make the content fill ~93-96% of the width; re-tune only if the layout
  changes.
- **Two libraries use the comma form** `--lib A,B` for freeze frames too — the
  space form makes the second path parse as the input file and die with
  `unrecognized arguments`.
- **`sed` crop**: analyze/diff frames crop the report to the
  `=== match distance x length map` … `=== huffman` range (the two maps plus
  the match-economics block); sweep needs no crop.
- **Exit status**: freeze reports `could not execute: exit status 1` and
  writes nothing if the pipeline exits nonzero — end the pipeline on `sed`
  (exit 0). Broken/missing `/dev/ptmx` grant renders the same error/empty
  output (see the nono-sandbox fix).
- **No `cd`/`&&`/`;` directly in the freeze string**: freeze's own exec
  handling fails on compound commands; `python3 ... | sed ...` works as-is
  (wrap in `sh -c '...'` only if a compound is unavoidable). Pipes are fine.
- **Run each capture as a standalone command, not inside a bash `for` loop** —
  freeze has been observed to intermittently exit 1 or write nothing in loops.
- **Logos on errors**: the analyzer writes its decode progress bar to stderr,
  so `2>/dev/null` keeps the frame clean (plus `--no-progress` where
  supported); `2>&1` must NOT be used or EOF-broken ANSI leaks in.
- **Verified** after each capture with PIL: dark-theme background, saturated
  (colored) pixels present in the two map shots but ~none in sweep, and
  `rightmost lit x / width` ≥ 0.93 (a model cannot eyeball the images).

Current frames: `analyze-map.png` 980x3544, `diff-maps.png` 1100x2838,
`sweep.png` 700x352.

## Test data / libraries

- Libraries: `/home/opencode/opencode/zlib-ng/build-develop/libz-ng.so` and
  `.../build-pr/libz-ng.so` (loaded with `RTLD_NOW|RTLD_LOCAL|RTLD_DEEPBIND`).
- Test file: `/home/opencode/opencode/zlib-ng/test/data/lcet10.txt` (419233 bytes).
- Test PNG: `/home/opencode/opencode/chromium-browser.png` (for `analyze-file`).
- Test ZIPs: `/home/opencode/opencode/cpu-z_2.15-en.zip` (4 deflate entries),
  `jsse.jar` (162 stored entries, no deflate), and
  `com.freepie.android.imu.apk` (7 deflate + 8 stored) (for `analyze-file`).
  `zip-info.txt` (same dir) documents the ZIP header layout (verified against these).
- RFC references: `/home/opencode/opencode/rfc1950.txt` (zlib), `rfc1951.txt`
  (deflate), `rfc1952.txt` (gzip), `rfc2083.txt` (PNG).

## Changelog / versioning

- `CHANGELOG.md` is the single source of truth for what changed per version;
  the version number itself lives in `zanalyze.py` as `__version__` and is
  shown by `--version` / `--help` (the `test_cli_version` test derives it from
  `zanalyze.__version__`, so it never hardcodes a number).
- On release, bump `__version__` to the next version, add a matching
  `## [x.yz] - <date>` section at the top of `CHANGELOG.md`, and refresh the
  "currently …" summary in the `## Files` bullet above.
- Every user-visible **feature** and **bug fix** that is new *compared to the
  previous released version* is appended to the current version's changelog
  section **as it is done** — when the feature/fix lands, not retrofitted at
  release time. This excludes fixes to problems introduced during this same
  version's development (those are judged by the version they compare against,
  i.e. what a 1.xx user upgrading to the next release would notice).
- Version scheme: `A.B` with a two-digit minor (e.g. 1.10 → 1.20); a `- <date>`
  ISO-dated entry per version.

## License

- `LICENSE.md` holds the zlib license (Copyright (C) 2026 Hans Kristian
  Rosbach), and `zanalyze.py`/`test_zanalyze.py` carry the same notice as a
  header comment after the shebang. Keep any new `.py` files aligned with this
  header format.
