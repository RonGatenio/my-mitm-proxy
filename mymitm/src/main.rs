mod config;

fn main() -> anyhow::Result<()> {
    println!("mymitm v{}", mymitm_common::VERSION);
    Ok(())
}
