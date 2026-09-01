# PLogDecoder
Parse and visualize binary contents in file

Cargo workspace with three crates:

- `plog-core` — the parsing/decoding library (regex extraction, hex decoding, Kaitai-style decoding).
- `plog-cli` — command-line runtime (`plog`).
- `plog-gui` — desktop GUI runtime (egui/eframe).

## CLI usage

```sh
cargo run -p plog-cli -- <FILE> --ksy <KSY_FILE> [--pattern <REGEX>] [--mode auto|line|whole|binary] [--watch]
```

- `--mode auto` (default) detects whether `<FILE>` is text or binary.
- Text files can be analyzed **line by line** (`--mode line`, one packet per matching line, supports `--watch` to tail the file) or as a **whole file** (`--mode whole`, all hex matches concatenated into a single packet).
- Binary files (`--mode binary`) are decoded directly, without regex extraction.

## GUI usage

```sh
cargo run -p plog-gui
```

Pick a log/binary file and a `.ksy` file, choose a mode, and click Run.
