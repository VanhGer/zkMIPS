use zkm_primitives::consts::{bytes_to_words_le, words_to_bytes_le};
use crate::events::{MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, Xor3128Event};
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
pub(crate) struct Xor3128Syscall;

impl Syscall for Xor3128Syscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32
    ) -> Option<u32> {
        let start_clk = ctx.clk;
        let input_addr = arg1;
        let result_addr = arg2;

        let mut input_read_records_vec = Vec::new();
        // read the 3 input blocks
        let (input_a_record, input_a_u32s) = ctx.mr_slice(input_addr, 4);
        input_read_records_vec.extend(input_a_record);
        let a_bytes: [u8; 16] = words_to_bytes_le(&input_a_u32s);

        let (input_b_record, input_b_u32s) = ctx.mr_slice(input_addr + 16, 4);
        input_read_records_vec.extend(input_b_record);
        let b_bytes: [u8; 16] = words_to_bytes_le(&input_b_u32s);

        let (input_c_record, input_c_u32s) = ctx.mr_slice(input_addr + 32, 4);
        input_read_records_vec.extend(input_c_record);
        let c_bytes: [u8; 16] = words_to_bytes_le(&input_c_u32s);

        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = a_bytes[i] ^ b_bytes[i] ^ c_bytes[i];
        }
        let result_u32s: [u32; 4] = bytes_to_words_le(&result);

        // write the result
        let result_write_records_vec = ctx.mw_slice(result_addr, &result_u32s);
        let result_write_records: [MemoryWriteRecord; 4] = result_write_records_vec.try_into().unwrap();
        let input_read_records: [MemoryReadRecord; 12] = input_read_records_vec.try_into().unwrap();
        let shard = ctx.current_shard();
        let event = Xor3128Event {
            shard,
            clk: start_clk,
            input_addr,
            result_addr,
            input_a: a_bytes,
            input_b: b_bytes,
            input_c: c_bytes,
            result,
            input_read_records,
            result_write_records,
            local_mem_access: ctx.postprocess(),
        };
        let syscall_event = ctx.rt.syscall_event(
            start_clk,
            None,
            ctx.next_pc,
            syscall_code.syscall_id(),
            arg1,
            arg2,
        );
        ctx.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::Xor3_128(event));
        None
    }
}