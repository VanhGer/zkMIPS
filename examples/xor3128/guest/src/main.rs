#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

zkm_zkvm::entrypoint!(main);
use zkm_zkvm::lib::xor3_128::xor3_128;
pub fn main() {
    let input_a: [u8; 16] = zkm_zkvm::io::read();
    let input_b: [u8; 16] = zkm_zkvm::io::read();
    let input_c: [u8; 16] = zkm_zkvm::io::read();

    let result = xor3_128(&input_a, &input_b, &input_c);
    // let mut result = [0_u8; 16];
    // for i in 0..16 {
    //     result[i] = input_a[i] ^ input_b[i] ^ input_c[i];
    // }
    zkm_zkvm::io::commit::<[u8; 16]>(&result);
}
