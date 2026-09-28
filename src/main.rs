//! Binary entry point for proxlet.

use anyhow::Result;
use clap::Parser;
use proxlet::Cli;

/// Parse CLI options and run proxlet in daemon or foreground mode.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
/// Returns `Ok(())` when the detached child is listening or the foreground
/// server exits cleanly.
///
/// # Errors
///
/// Returns an error when CLI-driven daemon spawning, Tokio runtime creation, or
/// server execution fails.
fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.daemon {
        return proxlet::daemon::spawn(&cli);
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(proxlet::run(cli));
    if let Err(error) = &result {
        proxlet::daemon::report_failure(error);
    }
    result
}
