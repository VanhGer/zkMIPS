use crate::memory::{MemoryReadCols, MemoryWriteCols};
use zkm_derive::AlignedBorrow;
use crate::operations::XorOperation;

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
    pub gates_id: T,
    pub gate_input_mem: [MemoryReadCols<T>; 16],
    pub num_gate_mem: MemoryReadCols<T>,
    pub result_mem: MemoryWriteCols<T>,
    pub inter1: [XorOperation<T>; 4], // h1 ^ h0
    pub inter2: [XorOperation<T>; 4], // h1 ^ h0 ^ label_b
    pub check: T,

}

pub const NUM_CIPHERTEXT_CHECK_COLS: usize = size_of::<CiphertextCheckCols<u8>>();