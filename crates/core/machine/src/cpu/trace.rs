use hashbrown::HashMap;
use itertools::Itertools;
use std::{array, borrow::BorrowMut};
use zkm2_core_executor::{
    events::{ByteLookupEvent, ByteRecord, CpuEvent, MemoryRecordEnum},
    syscalls::SyscallCode,
    ByteOpcode::{self, U16Range},
    ExecutionRecord, Instruction, Opcode, Program,
    Register::ZERO,
};
use zkm2_primitives::consts::WORD_SIZE;
use zkm2_stark::{air::MachineAir, Word};

use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use tracing::instrument;

use super::{columns::NUM_CPU_COLS, CpuChip};
use crate::{cpu::columns::CpuCols, memory::MemoryCols, utils::zeroed_f_vec};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let n_real_rows = input.cpu_events.len();
        let padded_nb_rows = if let Some(shape) = &input.shape {
            1 << shape.inner[&MachineAir::<F>::name(self)]
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_CPU_COLS);
        let shard = input.public_values.execution_shard;

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values.chunks_mut(chunk_size * NUM_CPU_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut CpuCols<F> = row.borrow_mut();

                    if idx >= input.cpu_events.len() {
                        cols.selectors.imm_b = F::ONE;
                        cols.selectors.imm_c = F::ONE;
                    } else {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.cpu_events[idx];
                        let instruction = &input.program.fetch(event.pc);
                        self.event_to_row(
                            event,
                            &input.nonce_lookup,
                            cols,
                            &mut byte_lookup_events,
                            shard,
                            instruction,
                        );
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_CPU_COLS)
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let shard = input.public_values.execution_shard;

        let blu_events: Vec<_> = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let instruction = &input.program.fetch(op.pc);
                    self.event_to_row::<F>(
                        op,
                        &input.nonce_lookup,
                        cols,
                        &mut blu,
                        shard,
                        instruction,
                    );
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.contains_cpu()
        }
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &[u32],
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
        shard: u32,
        instruction: &Instruction,
    ) {
        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events, shard);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup.get(event.alu_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.next_next_pc = F::from_canonical_u32(event.next_next_pc);
        cols.instruction.populate(instruction);
        cols.selectors.populate(instruction);

        cols.op_a_immutable = F::from_bool(
            instruction.is_memory_store_instruction_except_sc() || instruction.is_branch_instruction(),
        );

        if let Some(hi) = event.hi {
            *cols.op_hi_access.value_mut() = hi.into();
        }
        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for hi, a, b, and c.
        if let Some(record) = event.hi_record {
            cols.op_hi_access.populate(record, blu_events);
        }
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        // Populate range checks for a.
        let a_bytes = cols
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0] as u8,
            c: a_bytes[1] as u8,
        });
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            shard,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2] as u8,
            c: a_bytes[3] as u8,
        });

        // Populate memory accesses for reading from memory.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        if let Some(record) = event.memory_record {
            memory_columns.memory_access.populate(record, blu_events)
        }

        // Populate memory, branch, jump, and auipc specific fields.
        self.populate_memory(cols, event, blu_events, nonce_lookup, shard, instruction);
        //self.populate_auipc(cols, event, nonce_lookup, instruction);
        let is_halt = self.populate_syscall(cols, event, nonce_lookup);

        cols.is_sequential_instr = F::from_bool(
            !instruction.is_branch_instruction() && !instruction.is_jump_instruction() && !is_halt,
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;
    }

    /// Populates the shard and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
        shard: u32,
    ) {
        cols.shard = F::from_canonical_u32(shard);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            shard,
            U16Range,
            shard as u16,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            shard,
            U16Range,
            clk_16bit_limb,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            shard,
            ByteOpcode::U8Range,
            0,
            0,
            0,
            clk_8bit_limb as u8,
        ));
    }

    /// Populates columns related to memory.
    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
        nonce_lookup: &[u32],
        shard: u32,
        instruction: &Instruction,
    ) {
        if !matches!(
            instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LL
                | Opcode::LW
                | Opcode::LWL
                | Opcode::LWR
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
                | Opcode::SC
                | Opcode::SWL
                | Opcode::SWR //| Opcode::SDC1
        ) {
            return;
        }

        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup.get(event.memory_add_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            instruction.opcode,
            Opcode::LB
                | Opcode::LBU
                | Opcode::LH
                | Opcode::LHU
                | Opcode::LW
                | Opcode::LWL
                | Opcode::LWR
                | Opcode::LL
        ) {
            match instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    // LB: mem_value = sign_extend::<8>((mem >> (24 - (rs & 3) * 8)) & 0xff)
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    // LH: sign_extend::<16>((mem >> (16 - (rs & 2) * 8)) & 0xffff)
                    // LH: sign_extend::<16>((mem >> (8 * (2 - (rs & 2))) & 0xffff)
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                Opcode::LWL => {
                    // LWL:
                    //    let val = mem << (24 - (rs & 3) * 8);
                    //    let mask = 0xffFFffFFu32 << (24 - (rs & 3) * 8);
                    //    (rt & (!mask)) | val
                    let val = mem_value << (24 - addr_offset * 8);
                    let mask = 0xffFFffFFu32 << (24 - addr_offset * 8);
                    cols.unsigned_mem_val = ((mem_value & (!mask)) | val).into();
                }
                Opcode::LWR => {
                    // LWR:
                    //     let val = mem >> ((rs & 3) * 8);
                    //     let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
                    //     (rt & (!mask)) | val
                    let val = mem_value >> (addr_offset * 8);
                    let mask = 0xffFFffFFu32 >> (addr_offset * 8);
                    cols.unsigned_mem_val = ((mem_value & (!mask)) | val).into();
                }
                Opcode::LL => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte = if matches!(instruction.opcode, Opcode::LB) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::ONE {
                    cols.mem_value_is_neg_not_x0 = F::from_bool(instruction.op_a != (ZERO as u8));
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(event.memory_sub_lookup_id.0 as usize)
                            .copied()
                            .unwrap_or_default(),
                    );
                }
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(instruction.opcode, Opcode::LB | Opcode::LH)
                    && (memory_columns.most_sig_byte_decomp[7] == F::ZERO))
                    || matches!(instruction.opcode, Opcode::LBU | Opcode::LHU | Opcode::LW))
                    && instruction.op_a != (ZERO as u8),
            );
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            blu_events.add_byte_lookup_event(ByteLookupEvent {
                shard,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0],
                c: byte_pair[1],
            });
        }
    }

    // /// Populate columns related to AUIPC.
    // fn populate_auipc<F: PrimeField>(
    //     &self,
    //     cols: &mut CpuCols<F>,
    //     event: &CpuEvent,
    //     nonce_lookup: &[u32],
    //     instruction: &Instruction,
    // ) {
    //     if matches!(instruction.opcode, Opcode::AUIPC) {
    //         let auipc_columns = cols.opcode_specific_columns.auipc_mut();

    //         auipc_columns.pc = Word::from(event.pc);
    //         auipc_columns.pc_range_checker.populate(event.pc);
    //         auipc_columns.auipc_nonce = F::from_canonical_u32(
    //             nonce_lookup.get(event.auipc_lookup_id.0 as usize).copied().unwrap_or_default(),
    //         );
    //     }
    // }

    /// Populate columns related to syscall.
    fn populate_syscall<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        nonce_lookup: &[u32],
    ) -> bool {
        let mut is_halt = false;

        if cols.selectors.is_syscall == F::ONE {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `syscall_eval` in cpu/air/mod.rs for the corresponding constraint and
            // explanation.
            let syscall_cols = cols.opcode_specific_columns.syscall_mut();

            cols.syscall_mul_send_to_table =
                cols.selectors.is_syscall * cols.op_a_access.prev_value[1];

            let syscall_id = cols.op_a_access.prev_value[0];
            // let send_to_table = cols.op_a_access.prev_value[1];
            // let num_cycles = cols.op_a_access.prev_value[2];

            // Populate `is_enter_unconstrained`.
            syscall_cols.is_enter_unconstrained.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
            );

            // Populate `is_hint_len`.
            syscall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::SYSHINTLEN.syscall_id()),
            );

            // Populate `is_halt`.
            syscall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            syscall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // Populate `is_commit_deferred_proofs`.
            syscall_cols.is_commit_deferred_proofs.populate_from_field_element(
                syscall_id
                    - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
            );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
            // digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                syscall_cols.index_bitmap[digest_idx] = F::ONE;
            }

            // Write the syscall nonce.
            syscall_cols.syscall_nonce =
                F::from_canonical_u32(nonce_lookup[event.syscall_lookup_id.0 as usize]);

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

            // For halt and commit deferred proofs syscalls, we need to koala bear range check one of
            // it's operands.
            if is_halt {
                syscall_cols.operand_to_check = event.b.into();
                syscall_cols.operand_range_check_cols.populate(event.b);
                cols.syscall_range_check_operand = F::ONE;
            }

            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                syscall_cols.operand_to_check = event.c.into();
                syscall_cols.operand_range_check_cols.populate(event.c);
                cols.syscall_range_check_operand = F::ONE;
            }
        }

        is_halt
    }
}
