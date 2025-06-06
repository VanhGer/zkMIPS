use std::path::PathBuf;

use clap::Parser;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::build::build_plonk_bn254_artifacts_with_dummy;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_plonk_bn254_artifacts_with_dummy(args.build_dir);
}
