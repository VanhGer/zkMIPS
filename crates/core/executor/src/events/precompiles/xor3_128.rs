use serde::{Deserialize, Serialize};
use crate::events::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord};

pub const XOR3_128_INPUT_BYTES_LEN: usize = 48;
pub const XOR3_128_INPUT_U32S_LEN: usize = 12;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Xor3128Event {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The address of the input
    pub input_addr: u32,
    /// The address of the result
    pub result_addr: u32,
    /// The first input values as a list of byte
    pub input_a: [u8; 16],
    /// The second input values as a list of byte
    pub input_b: [u8; 16],
    /// The third input values as a list of byte
    pub input_c: [u8; 16],
    /// The result as a list of byte
    pub result: [u8; 16],
    /// The memory records for the input
    pub input_read_records: [MemoryReadRecord; XOR3_128_INPUT_U32S_LEN],
    /// The memory records for the result
    pub result_write_records: [MemoryWriteRecord; 4],
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}