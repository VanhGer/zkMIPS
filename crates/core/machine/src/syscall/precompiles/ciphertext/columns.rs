use crate::memory::{MemoryReadCols, MemoryWriteCols};
use zkm_derive::AlignedBorrow;
use crate::operations::{IsEqualWordOperation, XorOperation};

/// CiphertextCheckCols is the column layout for the Ciphertext check.
/// The number of rows equal to the number of gates
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct CiphertextCheckCols<T> {
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub input_address: T,
    pub output_address: T,
    pub receive_syscall: T,
    pub is_first_gate: T,
    pub is_last_gate: T,
    pub not_last_gate: T,
    pub gate_id: T,
    pub gates_num: T,
    pub gates_input_mem: [MemoryReadCols<T>; 16],
    pub gates_num_mem: MemoryReadCols<T>,
    pub result_mem: MemoryWriteCols<T>,
    pub inter1: [XorOperation<T>; 4], // h1 ^ h0
    pub inter2: [XorOperation<T>; 4], // h1 ^ h0 ^ label_b
    pub is_equal_words: [IsEqualWordOperation<T>; 4], // computed ciphertext == expected_ciphertext
    pub checks: [T; 4], // check result for each pair of is_equal_words
}

pub const NUM_CIPHERTEXT_CHECK_COLS: usize = size_of::<CiphertextCheckCols<u8>>();