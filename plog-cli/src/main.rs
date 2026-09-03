use std::io::{BufWriter, Write};
use std::process::ExitCode;

use clap::Parser;
use plog_cli::{resolve_mode, run_binary, run_line, run_whole, Cli, Mode};
use plog_core::filekind;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let ksy_source = match std::fs::read_to_string(&cli.ksy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read ksy file {:?}: {e}", cli.ksy);
            return ExitCode::FAILURE;
        }
    };

    let mode = match cli.mode {
        Mode::Auto => match filekind::detect(&cli.file) {
            Ok(kind) => resolve_mode(Mode::Auto, kind),
            Err(e) => {
                eprintln!("error: could not read file {:?}: {e}", cli.file);
                return ExitCode::FAILURE;
            }
        },
        m => m,
    };

    // Rust's stdout is line-buffered even when redirected to a file/pipe, so
    // writing millions of lines directly to it means millions of flush
    // syscalls. Wrap it in a large `BufWriter` so output is batched instead.
    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(1024 * 1024, stdout.lock());

    let result = match mode {
        Mode::Binary => run_binary(&cli.file, &ksy_source, &mut out),
        Mode::Whole => run_whole(&cli.file, &cli.pattern, &ksy_source, &mut out),
        Mode::Line => run_line(&cli.file, &cli.pattern, &ksy_source, cli.watch, &mut out),
        Mode::Auto => unreachable!("resolved above"),
    };

    if let Err(e) = out.flush() {
        eprintln!("error: could not flush output: {e}");
        return ExitCode::FAILURE;
    }

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
