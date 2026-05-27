use anyhow::Result;
use clap::Parser;
use proxlet::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.daemon {
        let pid = proxlet::daemon::spawn()?;
        println!("proxlet started in background with PID {pid}");
        return Ok(());
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()?
        .block_on(proxlet::run(cli))
}
