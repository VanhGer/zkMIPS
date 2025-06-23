//! A simple example showing how to aggregate proofs of multiple programs with ZKM.

use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
    ZKMVerifyingKey,
};

use std::fs::File;
use std::io::{Write, Read};
use bincode::{serialize, deserialize};

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: ZKMProofWithPublicValues,
    pub vk: ZKMVerifyingKey,
}

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::cpu();

    // Setup the proving and verifying keys.
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF);
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);

    // Generate the fibonacci proofs.
    // let proof_1 = tracing::info_span!("generate fibonacci proof n=10").in_scope(|| {
    //     let mut stdin = ZKMStdin::new();
    //     stdin.write(&10);
    //     client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    // });
    // let proof_2 = tracing::info_span!("generate fibonacci proof n=20").in_scope(|| {
    //     let mut stdin = ZKMStdin::new();
    //     stdin.write(&20);
    //     client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    // });
    // let proof_3 = tracing::info_span!("generate fibonacci proof n=30").in_scope(|| {
    //     let mut stdin = ZKMStdin::new();
    //     stdin.write(&30);
    //     client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    // });

    // Write to files
    // let vk_bytes = serialize(&fibonacci_vk).expect("serialize vk");
    // let mut vk_file = File::create("fibonacci_vk.bin").expect("create vk file");
    // vk_file.write_all(&vk_bytes).expect("write vk");
    //
    // let proof_bytes = serialize(&proof_1).expect("serialize proof");
    // let mut proof_file = File::create("proof_1.bin").expect("create proof file");
    // proof_file.write_all(&proof_bytes).expect("write proof");

    // Read from files
    let mut vk_file = File::open("fibonacci_vk.bin").expect("open vk file");
    let mut vk_bytes = Vec::new();
    vk_file.read_to_end(&mut vk_bytes).expect("read vk");
    let fibonacci_vk_read: ZKMVerifyingKey = deserialize(&vk_bytes).expect("deserialize vk");

    let mut proof_file = File::open("proof_1.bin").expect("open proof file");
    let mut proof_bytes = Vec::new();
    proof_file.read_to_end(&mut proof_bytes).expect("read proof");
    let proof_1_read: ZKMProofWithPublicValues = deserialize(&proof_bytes).expect("deserialize proof");

    // Setup the inputs to the aggregation program.
    let input_1 = AggregationInput { proof: proof_1_read, vk: fibonacci_vk_read};
    // let input_2 = AggregationInput { proof: proof_2, vk: fibonacci_vk.clone() };
    // let input_3 = AggregationInput { proof: proof_3, vk: fibonacci_vk.clone() };
    let inputs = vec![input_1];
    // let inputs: Vec<AggregationInput> = vec![];

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        
        let network_client = ProverClient::network();
        let mut stdin = ZKMStdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values =
            inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside zkMIPS itself.
        for input in inputs {
            let ZKMProof::Compressed(proof) = input.proof.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Generate the groth16 proof.
        network_client.prove(&aggregation_pk, stdin).groth16().run().expect("proving failed");
    });
}
