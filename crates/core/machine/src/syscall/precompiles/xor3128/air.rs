use p3_air::{Air, BaseAir};
use p3_matrix::Matrix;
use std::borrow::Borrow;
use p3_field::FieldAlgebra;
use zkm_core_executor::ByteOpcode;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{LookupScope, ZKMAirBuilder};
use crate::air::MemoryAirBuilder;
use crate::operations::XorOperation;
use crate::syscall::precompiles::xor3128::columns::{Xor3128Cols, NUM_XOR3_128_COLS};
use crate::syscall::precompiles::xor3128::Xor3128Chip;

impl<F> BaseAir<F> for Xor3128Chip {
    fn width(&self) -> usize {
        NUM_XOR3_128_COLS
    }
}

impl<AB> Air<AB> for Xor3128Chip
where
    AB: ZKMAirBuilder
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, _) = (main.row_slice(0), main.row_slice(1));
        let local: &Xor3128Cols<AB::Var> = (*local).borrow();

        // builder.assert_bool(local.is_real);

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::XOR3_128.syscall_id()),
            local.input_address,
            local.result_address,
            local.receive_syscall,
            LookupScope::Local,
        );

        // eval memory accesses
        builder.eval_memory_access_slice(
            local.shard,
            local.clk,
            local.input_address,
            &local.input_mem,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk,
            local.result_address,
            &local.result_mem,
            local.is_real,
        );

        // eval xor operations
        for i in 0..4 {
            XorOperation::<AB::F>::eval(
                builder,
                local.input_mem[i].access.value,
                local.input_mem[4 + i].access.value,
                local.intermediate[i],
                local.is_real
            );
        }

        for i in 0..4 {
            for j in 0..WORD_SIZE {
                builder.send_byte(
                    AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                    local.result_mem[i].access.value[j],
                    local.intermediate[i].value[j],
                    local.input_mem[8 + i].access.value[j],
                    local.is_real,
                );
            }
        }

    }
}