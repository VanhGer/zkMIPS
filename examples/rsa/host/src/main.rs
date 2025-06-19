use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    RsaPrivateKey, RsaPublicKey,
    signature::Signer,
};
use rsa::pkcs1v15::SigningKey;
use std::vec;
use rsa::signature::SignatureEncoding;
use sha2::Sha256;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const RSA_ELF: &[u8] = include_elf!("rsa");

const RSA_2048_PRIV_DER: &[u8] = include_bytes!("keys/rsa2048-priv-257.der");
const RSA_2048_PUB_DER: &[u8] = include_bytes!("keys/rsa2048-pub-257.der");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create a new stdin with the input for the program.
    let mut stdin = ZKMStdin::new();

    let private_key = RsaPrivateKey::from_pkcs8_der(RSA_2048_PRIV_DER).unwrap();
    let public_key = RsaPublicKey::from_public_key_der(RSA_2048_PUB_DER).unwrap();
    println!("{:?} \n\n{:?}", private_key, public_key);

    let signing_key: SigningKey<Sha256> = SigningKey::new(private_key.clone());

    let message = b"Hello world!".to_vec();

    let signature = signing_key.sign(&message).to_vec();

    stdin.write(&RSA_2048_PUB_DER);
    stdin.write(&message);
    stdin.write(&signature);

    // Instead of generating and verifying the proof each time while developing,
    // execute the program with the RISC-V runtime and read stdout.
    //
    // let mut stdout = ZKMProver::execute(REGEX_IO_ELF, stdin).expect("proving failed");
    // let verified = stdout.read::<bool>();

    // Generate the proof for the given program and input.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(RSA_ELF);

    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(RSA_ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // let start = std::time::Instant::now();
    let proof = client.prove(&pk, stdin).run().expect("proving failed");
    // println!("Proof generation took {:?}", start.elapsed());

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");
    //
    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
