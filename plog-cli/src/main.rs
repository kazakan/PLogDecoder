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

    let result = match mode {
        Mode::Binary => run_binary(&cli.file, &ksy_source),
        Mode::Whole => run_whole(&cli.file, &cli.pattern, &ksy_source),
        Mode::Line => run_line(&cli.file, &cli.pattern, &ksy_source, cli.watch),
        Mode::Auto => unreachable!("resolved above"),
    };

    match result {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
