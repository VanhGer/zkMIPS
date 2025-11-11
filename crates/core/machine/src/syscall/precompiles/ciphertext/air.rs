use std::borrow::Borrow;
use log::__private_api::loc;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{LookupScope, ZKMAirBuilder};
use crate::air::{MemoryAirBuilder, WordAirBuilder};
use crate::CiphertextCheckChip;
use crate::operations::{IsEqualWordOperation, IsZeroWordOperation, XorOperation};
use crate::syscall::precompiles::ciphertext::columns::{CiphertextCheckCols, NUM_CIPHERTEXT_CHECK_COLS};

impl<F> BaseAir<F> for CiphertextCheckChip {
    fn width(&self) -> usize {
        NUM_CIPHERTEXT_CHECK_COLS
    }
}

impl<AB> Air<AB> for CiphertextCheckChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CiphertextCheckCols<AB::Var> = (*local).borrow();
        let next: &CiphertextCheckCols<AB::Var> = (*next).borrow();

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::CIPHERTEXT_CHECK.syscall_id()),
            local.input_address - AB::F::from_canonical_u32(4), // adjust for num_gates u32
            local.output_address,
            local.receive_syscall,
            LookupScope::Local,
        );

        self.eval_flags(builder, local);
        self.eval_memory_access(builder, local);
        self.eval_logic_check(builder, local, next);
        self.eval_transition(builder, local, next);
    }
}

impl CiphertextCheckChip {
    fn eval_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CiphertextCheckCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_first_gate);
        builder.assert_bool(local.is_last_gate);
        builder.assert_bool(local.not_last_gate);
        builder.assert_zero(local.is_last_gate * local.not_last_gate);
        builder.assert_zero(local.is_last_gate * local.is_first_gate);
    }

    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CiphertextCheckCols<AB::Var>,
    ) {
        // eval gate number read
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.input_address - AB::F::from_canonical_u32(4), // adjust for num_gates u32,
            &local.gates_num_mem,
            local.is_first_gate
        );

        // eval gate info read
        for i in 0..16 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::F::from_canonical_u32((i as u32) * 4),
                &local.gates_input_mem[i],
                local.is_real,
            );
        }
        // eval result write
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.output_address,
            &local.result_mem,
            local.is_last_gate,
        );
    }

    fn eval_logic_check<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CiphertextCheckCols<AB::Var>,
        next: &CiphertextCheckCols<AB::Var>,
    ) {
        // eval XOR operations
        for i in 0..4 {
            let h0_id = i;
            let h1_id = 4 + i;
            let label_b_id = 8 + i;

            XorOperation::<AB::F>::eval(
                builder,
                local.gates_input_mem[h0_id].access.value,
                local.gates_input_mem[h1_id].access.value,
                local.inter1[i],
                local.is_real,
            );

            XorOperation::<AB::F>::eval(
                builder,
                local.inter1[i].value,
                local.gates_input_mem[label_b_id].access.value,
                local.inter2[i],
                local.is_real,
            );
        }

        // eval check
        for i in 0..4 {
            let expected_id = 12 + i;
            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.inter2[i].value.map(|x| x.into()),
                local.gates_input_mem[expected_id].access.value.map(|x| x.into()),
                local.is_equal_words[i],
                local.is_real.into()
            );
        }
        builder.when(local.is_real).assert_eq(
            local.checks[0],
            local.is_equal_words[0].is_diff_zero.result * local.is_equal_words[1].is_diff_zero.result,
        );
        builder.when(local.is_real).assert_eq(
            local.checks[1],
            local.is_equal_words[2].is_diff_zero.result * local.checks[0],
        );
        builder.when(local.is_real).assert_eq(
            local.checks[2],
            local.is_equal_words[3].is_diff_zero.result * local.checks[1],
        );
        builder.when(local.not_last_gate).assert_eq(
            next.checks[3],
            local.checks[3] * next.checks[2]
        );
    }

    fn eval_transition<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CiphertextCheckCols<AB::Var>,
        next: &CiphertextCheckCols<AB::Var>,
    ) {
        let bytes_shift = AB::F::from_canonical_u32(256);
        let num_gates = local.gates_num_mem.access.value.0[0]
        + local.gates_num_mem.access.value.0[1] * bytes_shift
        + local.gates_num_mem.access.value.0[2] * bytes_shift * bytes_shift
        + local.gates_num_mem.access.value.0[3] * bytes_shift * bytes_shift * bytes_shift;

        builder.when(local.is_first_gate).assert_zero(local.gate_id);
        builder.when(local.is_first_gate).assert_eq(local.gates_num, num_gates);
        builder.when(local.is_last_gate).assert_eq(local.gates_num - AB::F::ONE, local.gate_id);
        builder.when(local.not_last_gate).assert_eq(local.gate_id + AB::F::ONE, next.gate_id);

        builder.when(local.not_last_gate).assert_eq(
            local.input_address + AB::F::from_canonical_u32(64),
            next.input_address
        );
    }
}