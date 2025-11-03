use zkm_derive::AlignedBorrow;
use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::XorOperation;

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct Xor3128Cols<T> {
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub input_address: T,
    pub result_address: T,
    pub receive_syscall: T,
    pub input_mem: [MemoryReadCols<T>; 12],
    pub result_mem: [MemoryWriteCols<T>; 4],
    pub intermediate: [XorOperation<T>; 4],
}

pub const NUM_XOR3_128_COLS: usize = size_of::<Xor3128Cols<u8>>();