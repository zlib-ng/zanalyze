# Changelog

All notable changes to `zanalyze.py` are documented in this file.

## [1.20] - 2026-09-12

### Added

- New `dump-file` mode: prints the complete per-event listing of an existing
  compressed file (every literal run and match, with its start position and
  each literal byte shown in full hex). It is the only mode that never touches
  system zlib — the internal parser reconstructs the source itself. Because
  the output is many times larger than the input (see `--help`), literal runs
  are dumped in full; `--max-events` caps the listing. For a
  `.zip`/`.jar`/`.apk` the command exits non-zero and lists the entries until
  `--zip-entry N` selects a deflate entry to dump.
- `analyze-file` gains an optional `--zip-entry N`: analyze only that single
  deflate entry of a `.zip`/`.jar`/`.apk` instead of the whole-archive
  aggregate. The report keeps the zip header and the full per-entry table for
  context but reads as a one-entry stream (summary labelled `(1 entry)`,
  histograms/map/economics/Huffman from that entry only, and `--events`
  honored for it). A non-deflate or out-of-range entry exits non-zero; on a
  non-zip file the flag is an error.
- CI now runs the test suite under PyPy 3.11 as well as CPython 3.12.

### Fixed

- The test suite's `FAILURES` collector is now annotated (`list[str]`), keeping
  current mypy clean on CI.

## [1.10] - 2026-09-12

### Added

- PyPy support: direct launches (`./zanalyze.py` or `python3 zanalyze.py`)
  that find a `pypy3` on `PATH` automatically re-execute under it. PyPy's JIT
  roughly halves the decode time on large files.
- `--no-pypy` flag (accepted on the top-level parser and every subcommand) and
  the `ZANALYZE_NO_PYPY` environment variable to force plain CPython in case
  a local `pypy3` is too old or misbehaves.
- A progress-bar hint: when the parse runs on CPython with no `pypy3`
  installed and the decode has taken more than 2 seconds, the bar appends a
  tip that installing pypy3 could roughly double the speed.

## [1.00] - 2026-09-12

Initial release.