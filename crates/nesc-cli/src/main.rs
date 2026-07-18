use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    nesc_cli::run(
        std::env::args_os(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}
