//! lancer-prowler
//! Rust clone of prowler. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-prowler", version, about = "Rust clone of prowler")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-prowler - scaffold ready. Implement per plan.md.");
    Ok(())
}
