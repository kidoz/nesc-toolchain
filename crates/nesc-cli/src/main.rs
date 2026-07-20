use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    nesc_cli::run_with_input(
        std::env::args_os(),
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}
