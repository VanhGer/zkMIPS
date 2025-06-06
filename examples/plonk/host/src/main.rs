//! A script that generates a Groth16 proof for the Fibonacci program, and verifies the
//! Groth16 proof in ZKM.

use zkm_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMStdin};

/// The ELF for the Groth16 verifier program.
const PLONK_ELF: &[u8] = include_elf!("plonk-verifier");

/// The ELF for the Fibonacci program.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci");

/// Generates the proof, public values, and vkey hash for the Fibonacci program in a format that
/// can be read by `zkm-verifier`.
///
/// Returns the proof bytes, public values, and vkey hash.
fn generate_fibonacci_proof() -> (Vec<u8>, Vec<u8>, String) {
    // Create an input stream and write '20' to it.
    let n = 20u32;

    // The input stream that the program will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Generate the plonk proof for the Fibonacci program.
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    println!("vk: {:?}", vk.bytes32());
    let proof = client.prove(&pk, stdin).plonk().run().unwrap();
    (proof.bytes(), proof.public_values.to_vec(), vk.bytes32())
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Generate the Fibonacci proof, public values, and vkey hash.
    let (fibonacci_proof, fibonacci_public_values, vk) = generate_fibonacci_proof();

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = ZKMStdin::new();
    stdin.write_vec(fibonacci_proof);
    stdin.write_vec(fibonacci_public_values);
    stdin.write(&vk);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(PLONK_ELF, stdin).run().unwrap();
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}
