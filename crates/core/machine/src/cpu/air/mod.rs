pub mod register;
pub mod syscall;

use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm2_core_executor::ByteOpcode;
use zkm2_stark::{
    air::{BaseAirBuilder, PublicValues, ZKMAirBuilder, ZKM_PROOF_NUM_PV_ELTS},
    Word,
};

use crate::{
    air::{MemoryAirBuilder, ZKMCoreAirBuilder},
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols, NUM_CPU_COLS},
        CpuChip,
    },
    operations::KoalaBearWordRangeChecker,
};
use zkm2_core_executor::Opcode;

use super::columns::OPCODE_SELECTORS_COL_MAP;

impl<AB> Air<AB> for CpuChip
where
    AB: ZKMCoreAirBuilder + AirBuilderWithPublicValues,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();

        // Program constraints.
        builder.send_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.shard,
            local.is_real,
        );

        let is_alu_instruction: AB::Expr = self.is_alu_instruction::<AB>(&local.selectors);

        // Register constraints.
        self.eval_registers::<AB>(builder, local);

        // ALU instructions.
        builder.send_alu_with_hi(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.op_hi_val(),
            local.shard,
            local.nonce,
            is_alu_instruction,
        );

        // syscall instruction.
        self.eval_syscall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS syscall instruction.
        let public_values_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();
        self.eval_commit(
            builder,
            local,
            public_values.committed_value_digest,
            public_values.deferred_proofs_digest,
        );

        // HALT syscall and UNIMPL instruction.
        self.eval_halt_unimpl(builder, local, next, public_values);

        // Check that the shard and clk is updated correctly.
        self.eval_shard_clk(builder, local, next);

        // Check that the pc is updated correctly.
        // TOFIX self.eval_pc(builder, local, next, is_branch_instruction.clone());

        // Check public values constraints.
        self.eval_public_values(builder, local, next, public_values);

        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);

        // Check that when `is_real=0` that all flags that send interactions are zero.
        local.selectors.into_iter().enumerate().for_each(|(i, selector)| {
            if i == OPCODE_SELECTORS_COL_MAP.imm_b {
                builder.when(AB::Expr::ONE - local.is_real).assert_one(local.selectors.imm_b);
            } else if i == OPCODE_SELECTORS_COL_MAP.imm_c {
                builder.when(AB::Expr::ONE - local.is_real).assert_one(local.selectors.imm_c);
            } else {
                builder.when(AB::Expr::ONE - local.is_real).assert_zero(selector);
            }
        });
    }
}

impl CpuChip {
    /// Whether the instruction is an ALU instruction.
    pub(crate) fn is_alu_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_alu.into()
    }

    // /// Constraints related to the AUIPC opcode.
    // pub(crate) fn eval_auipc<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
    //    // Get the auipc specific columns.
    //     let auipc_columns = local.opcode_specific_columns.auipc();
    //
    //     // Verify that the word form of local.pc is correct.
    //     builder.when(local.selectors.is_auipc).assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);
    //
    //     // Range check the pc.
    //     KoalaBearWordRangeChecker::<AB::F>::range_check(
    //         builder,
    //         auipc_columns.pc,
    //         auipc_columns.pc_range_checker,
    //         local.selectors.is_auipc.into(),
    //     );
    //
    //     // Verify that op_a == pc + op_b.
    //     builder.send_alu(
    //         AB::Expr::from_canonical_u32(Opcode::ADD as u32),
    //         local.op_a_val(),
    //         auipc_columns.pc,
    //         local.op_b_val(),
    //         local.shard,
    //         auipc_columns.auipc_nonce,
    //         local.selectors.is_auipc,
    //     );
    // }

    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Verify that all shard values are the same.
        builder.when_transition().when(next.is_real).assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        let num_extra_cycles = self.get_num_extra_syscall_cycles::<AB>(local);

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
        // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        let expected_next_clk =
            local.clk + AB::Expr::from_canonical_u32(5) + num_extra_cycles.clone();

        builder.when_transition().when(next.is_real).assert_eq(expected_next_clk.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.eval_range_check_24bits(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.is_real,
        );
    }

    /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch,
    /// jump and halt instructions. Also, it ensures that the pc is carried down to the last row
    /// for non-real rows.
    pub(crate) fn eval_pc<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        is_branch_instruction: AB::Expr,
    ) {
        // When is_sequential_instr is true, assert that instruction is not branch, jump.
        // Note that the condition `when(local_is_real)` is implied from the previous constraint.
       /* TODO
        let is_halt = self.get_is_halt_syscall::<AB>(builder, local);
        builder.when(local.is_real).assert_eq(
            local.is_sequential_instr,
            AB::Expr::ONE
                - (is_branch_instruction
                    + local.selectors.is_jump
                    + local.selectors.is_jumpd
                    + is_halt),
        );
         */
        // Verify that the pc increments by 4 for all instructions except instruction after branch, jump
        // instructions. The other case is handled by eval_jump, eval_branch and eval_syscall
        // (for halt).
        builder
            .when(local.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.next_pc + AB::Expr::from_canonical_u8(4), local.next_next_pc);

        // When the last row is real and it's a sequential instruction, assert that local.next_pc
        // <==> next.pc, local.next_next_pc <==> next.next_pc
        builder.when_transition().when(next.is_real).assert_eq(local.next_pc, next.pc);

        builder
            .when_transition()
            .when(next.is_real)
            .when(next.is_sequential_instr)
            .assert_eq(local.next_next_pc, next.next_pc);
    }

    /// Constraints related to the public values.
    pub(crate) fn eval_public_values<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        // Verify the public value's shard.
        builder.when(local.is_real).assert_eq(public_values.execution_shard, local.shard);

        // Verify the public value's start pc.
        builder.when_first_row().assert_eq(public_values.start_pc, local.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc, local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder.when_last_row().when(local.is_real).assert_eq(public_values.next_pc, local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder.when_transition().when_not(local.is_real).assert_zero(next.is_real);
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
