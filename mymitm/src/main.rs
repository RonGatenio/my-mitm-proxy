mod bpf;
mod config;
mod dump;

fn main() -> anyhow::Result<()> {
    println!("mymitm v{}", mymitm_common::VERSION);
    Ok(())
}
