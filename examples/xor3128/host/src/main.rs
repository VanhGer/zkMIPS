use std::env;
use rand::RngCore;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("xor3128");
fn prove_xor3128_rust() {
    let mut stdin = ZKMStdin::new();

    let rng = &mut rand::rng();
    let mut a_input: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut a_input);
    let mut b_input: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut b_input);
    let mut c_input: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut c_input);

    stdin.write(&a_input);
    stdin.write(&b_input);
    stdin.write(&c_input);

    let mut expected_result = [0u8; 16];
    for i in 0..16 {
        expected_result[i] = a_input[i] ^ b_input[i] ^ c_input[i];
    }

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (mut public_input, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let computed_result = public_input.read::<[u8; 16]>();
    assert_eq!(expected_result, computed_result);
    println!("computed result: {:?}", computed_result);

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();
    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `zkm_zkvm::io::commit`.
    let mut computed_result = proof.public_values.read::<[u8; 16]>();
    assert_eq!(expected_result, computed_result);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

fn main() {
    utils::setup_logger();
    prove_xor3128_rust();
}
