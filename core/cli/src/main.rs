use clap::Parser;

#[derive(Parser)]
#[command(name = "lazymail", about = "Command line for the Lazy Mail core")]
struct Cli {
    /// Print the core version
    #[arg(long, short = 'V')]
    version: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.version {
        println!("{}", lazymail_core::core_version());
    }
}
