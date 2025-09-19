use std::borrow::Borrow;
use log::__private_api::loc;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use tempfile::Builder;
use zkm_core_executor::events::AES_128_BLOCK_BYTES;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{LookupScope, MachineAir, ZKMAirBuilder};
use crate::air::MemoryAirBuilder;
use crate::KeccakSpongeChip;
use crate::syscall::precompiles::aes128_encrypt::AES128EncryptChip;
use crate::syscall::precompiles::aes128_encrypt::columns::{AES128EncryptionCols, NUM_AES128_ENCRYPTION_COLS};

impl<F> BaseAir<F> for AES128EncryptChip {
    fn width(&self) -> usize {
        NUM_AES128_ENCRYPTION_COLS
    }
}

impl<AB> Air<AB> for AES128EncryptChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &AES128EncryptionCols<AB::Var> = (*local).borrow();
        let next: &AES128EncryptionCols<AB::Var> = (*next).borrow();

        self.eval_flags(builder, local);
        self.eval_memory_access(builder, local);

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::AES128_ENCRYPT.syscall_id()),
            local.block_address,
            local.key_address,
            local.receive_syscall,
            LookupScope::Local,
        );
    }
}

impl AES128EncryptChip {
    fn eval_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let first_round = local.round[0];
        let last_round = local.round[10];
        for i in 0..11 {
            builder.assert_bool(local.round[i]);
        }
        builder.assert_bool(local.round_1to9);

        builder.assert_eq(first_round * local.is_real, local.receive_syscall);
        builder.assert_eq(last_round + first_round + local.round_1to9, local.is_real);
    }
    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let mut round = AB::Expr::ZERO;
        for i in 0..11 {
            round = round + local.round[i] * AB::F::from_canonical_u32(i as u32);
        }

        // // if this is the first row, populate reading key
        // for i in 0..4 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk,
        //         local.key_address + AB::F::from_canonical_u32((i * 4) as u32),
        //         &local.key[i],
        //         local.round[0],
        //     );
        // }
        //
        // // if this is the first row, populate reading sbox_addr
        // builder.eval_memory_access(
        //     local.shard,
        //     local.clk,
        //     local.sbox_address,
        //     &local.sbox_addr_read,
        //     local.round[0],
        // );
        // // if this is the first row, populate reading input
        // for i in 0..4 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk,
        //         local.block_address + AB::F::from_canonical_u32((i * 4) as u32),
        //         &local.block[i],
        //         local.round[0],
        //     );
        // }
        //
        // // if this is the last row, populate writing output
        // for i in 0..4 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk + AB::Expr::ONE,
        //         local.block_address + AB::F::from_canonical_u32((i * 4) as u32),
        //         &local.block[i],
        //         local.round[10]
        //     );
        // }

        // for i in 0..24 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk,
        //         local.sbox_address
        //             +  AB::F::from_canonical_u32(i as u32) * AB::F::from_canonical_u8(4),
        //         &local.sbox[i],
        //         local.round[0].clone()
        //     );
        // }

        // let round_1to10 = local.round[10] + local.round_1to9;
        // subs_bytes for state matrix

        // builder.when(local.round[1]).assert_eq(
        //     local.state_subs_bytes[0].access.diff_8bit_limb,
        //     local.state_subs_bytes[1].access.diff_8bit_limb
        // );


        for i in 0..2 {
            let index = local.state_matrix[i];
            // let index = AB::F::from_canonical_u8(0);
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.sbox_address + index * AB::F::from_canonical_u8(4),
                &local.state_subs_bytes[i],
                local.round[1].clone(),
            );
        }
        // builder.when(local.is_real).assert_eq(local.sbox_address, AB::F::from_canonical_u32(2130705192 as u32));



        // builder.when(local.round[1]).assert_eq(
        //     local.state_subs_bytes[0].access.value[0],
        //     AB::F::from_canonical_u8(99)
        // );
        // builder.when(local.round[1]).assert_eq(
        //     local.state_subs_bytes[0].access.value[1],
        //     AB::F::from_canonical_u8(0)
        // );
        // builder.when(local.round[1]).assert_eq(
        //     local.state_subs_bytes[0].access.value[2],
        //     AB::F::from_canonical_u8(0)
        // );
        // builder.when(local.round[1]).assert_eq(
        //     local.state_subs_bytes[0].access.value[3],
        //     AB::F::from_canonical_u8(0)
        // );

        // let tmp = [127_u8, 254, 14, 149, 81, 165, 102, 53, 14, 52, 124, 71, 41, 41, 236, 203];
        // for i in 0..16 {
        //     builder.when(local.round[10]).assert_eq(
        //         local.state_matrix[i],
        //         AB::F::from_canonical_u8(tmp[i])
        //     );
        // }
        // let tmp_after = [210_u8, 187, 171, 42, 209, 6, 51, 150, 171, 24, 16, 160, 165, 165, 206, 31];
        // for i in 0..16 {
        //     builder.when(local.round[10]).assert_eq(
        //         local.state_subs_bytes[i].access.value[0],
        //         AB::F::from_canonical_u8(tmp_after[i])
        //     );
        // }



        //
        // // sbox elements
        // let round_0to9 = local.round_1to9 + local.round[0];
        // let start = round * AB::F::from_canonical_u32(24);
        // for i in 0..24 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk,
        //         local.sbox_address
        //             + (start.clone() + AB::F::from_canonical_u32(i as u32)) * AB::F::from_canonical_u8(4),
        //         &local.sbox[i],
        //         round_0to9.clone()
        //     );
        // }
        // for i in 0..16 {
        //     builder.eval_memory_access(
        //         local.shard,
        //         local.clk,
        //         local.sbox_address
        //             + (start.clone() + AB::F::from_canonical_u32(i as u32)) * AB::F::from_canonical_u8(4),
        //         &local.sbox[i],
        //         local.round[10].clone(),
        //     );
        // }

        // round key subs bytes
        // todo!()
    }
}