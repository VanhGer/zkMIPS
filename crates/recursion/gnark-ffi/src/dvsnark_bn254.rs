use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{witness::GnarkWitness, DvSnarkBn254Proof};

use sha2::{Digest, Sha256};
use zkm_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};
use crate::ffi::{build_dvsnark_bn254, prove_dvsnark_bn254};

/// A prover that can generate proofs with Dvsnark protocol
#[derive(Debug, Clone)]
pub struct DvSnarkBn254Prover;

/// A prover that can generate proofs with the Groth16 protocol using bindings to Gnark.
impl DvSnarkBn254Prover {
    /// Creates a new [DvSnarkBn254Prover].
    pub fn new() -> Self {
        Self
    }

    pub fn get_vkey_hash(build_dir: &Path) -> [u8; 32] {
        let vkey_path = build_dir.join("groth16_vk.bin");
        let vk_bin_bytes = std::fs::read(vkey_path).unwrap();
        Sha256::digest(vk_bin_bytes).into()
    }

    /// Builds the DvSnark circuit locally.
    pub fn build<C: Config>(
        constraints: Vec<Constraint>,
        witness: Witness<C>,
        build_dir: PathBuf,
        store_dir: PathBuf,
    ) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        // Write constraints.
        let constraints_path = build_dir.join("constraints.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = build_dir.join("dvsnark_witness.json");
        let gnark_witness = GnarkWitness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Build the circuit.
        build_dvsnark_bn254(build_dir.to_str().unwrap(), store_dir.to_str().unwrap());
    }

    /// Generates a dv-snark proof given a witness.
    pub fn prove<C: Config>(
        &self,
        witness: Witness<C>,
        build_dir: PathBuf,
        store_dir: PathBuf,
    ) -> DvSnarkBn254Proof {
        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        let mut proof = prove_dvsnark_bn254(
            build_dir.to_str().unwrap(),
            witness_file.path().to_str().unwrap(),
            store_dir.to_str().unwrap(),
        );
        proof.dvsnark_vkey_hash = Self::get_vkey_hash(&build_dir);
        proof
    }
}

impl Default for DvSnarkBn254Prover {
    fn default() -> Self {
        Self::new()
    }
}
