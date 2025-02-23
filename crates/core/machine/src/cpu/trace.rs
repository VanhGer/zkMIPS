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
                        cols.instruction.imm_b = F::ONE;
                        cols.instruction.imm_c = F::ONE;
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

        let mut is_halt = false;
        if instruction.is_syscall_instruction() {
            let syscall_id = cols.op_a_access.prev_value[0];
            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());
            let num_extra_cycles = cols.op_a_access.prev_value[2]; 
            cols.num_extra_cycles = num_extra_cycles;
        }

        cols.has_hi = F::from_bool(instruction.is_mult_div_instruction());
    
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

}
