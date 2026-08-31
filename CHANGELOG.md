# Changelog

All notable changes to **plog-core** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions correspond to Git tags (`vX.Y.Z`) created by the CD pipeline when a
`release`-labelled PR is merged into `main`.

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
