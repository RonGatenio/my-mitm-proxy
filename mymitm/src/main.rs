mod bpf;
mod config;
mod dump;
mod proxy;

fn main() -> anyhow::Result<()> {
    println!("mymitm v{}", mymitm_common::VERSION);
    Ok(())
}
