# Changelog

All notable changes to `zanalyze.py` are documented in this file.

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