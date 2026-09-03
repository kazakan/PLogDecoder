# Changelog

All notable changes to **plog-core** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions correspond to Git tags (`vX.Y.Z`) created by the CD pipeline when a
`release`-labelled PR is merged into `main`.

---

## [0.0.2] - 2026-09-03

### Added

- CLI runtime for analyzing text and binary files using a Kaitai Struct (`.ksy`) definition.
- GUI runtime for picking input files, choosing text vs. binary mode, and running analyses from the desktop app.
- Text-analysis modes for `line`, `whole`, and `auto` detection, including file watching for live tailing of appended log lines.
- Large-file acceleration for one-shot analysis via a memory-mapped, chunked, parallel decode path that preserves packet ordering and index stability.
- Unit and integration tests covering CLI execution, GUI startup flows, and large-file correctness.

### Fixed

- Streamed output for large runs so analysis no longer builds a giant in-memory output buffer before writing results.
- Corrected ordering and indexing when parallel chunk decoding is used.
- Improved warnings and error handling for invalid hex data, decode failures, and missing inputs.

### Validation

- Added CI-relevant validation coverage for formatting, linting, and workspace test execution.

---

## [0.0.1] — 2026-08-31

### Added

- `hex::decode` — single nibble-loop hex decoder; whitespace-tolerant; no intermediate allocations.
- `Extractor` — compiled-once `regex::Regex` wrapper; `extract_from_line()` reuses the compiled pattern.
- `DecoderCache` — FNV-1a content-hash keyed cache for KSY protocol decoders; each unique KSY is prepared exactly once.
- `Value` / `DecodedPacket` — typed result representation; `.display()` allocates only on demand.
- `start_analysis()` — one-shot streaming analysis on a background thread via `mpsc::channel`.
- `start_analysis_watch()` — tail-follow (hot-reload) mode; resumes from the current byte offset when lines are appended; handles file rotation.
- Criterion benchmarks: `hex_decode` (compact & spaced, 16 B / 128 B / 2 KB), `extractor` (matching vs. non-matching), `pipeline` end-to-end (1 K and 10 K lines).
- GitHub Actions CI/CD/CT workflows (`.github/workflows/ci.yml`, `.github/workflows/cd.yml`).
