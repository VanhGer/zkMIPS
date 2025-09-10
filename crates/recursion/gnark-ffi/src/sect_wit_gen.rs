use std::{io::Write, path::PathBuf};

use zkm_recursion_compiler::ir::{Config, Witness};

use crate::{ffi::prove_witness_sect, GnarkWitness, SectWitness};

#[derive(Debug, Clone, Default)]
pub struct SectWitnessGenerator;

impl SectWitnessGenerator {
    // referenced from Groth16Bn254Prover::prove
    pub fn prove<C: Config>(&self, witness: Witness<C>, build_dir: PathBuf) -> SectWitness {
        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        prove_witness_sect(build_dir.to_str().unwrap(), witness_file.path().to_str().unwrap());
        SectWitness {}
    }
}