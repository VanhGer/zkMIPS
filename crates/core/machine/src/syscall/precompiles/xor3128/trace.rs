use std::cmp::max;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use std::borrow::BorrowMut;
use zkm_core_executor::{ByteOpcode, ExecutionRecord, Program};
use zkm_core_executor::events::{ByteLookupEvent, ByteRecord, PrecompileEvent, Xor3128Event};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::MachineAir;
use crate::syscall::precompiles::xor3128::columns::{Xor3128Cols, NUM_XOR3_128_COLS};
use crate::syscall::precompiles::xor3128::Xor3128Chip;

impl<F: PrimeField32> MachineAir<F> for Xor3128Chip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Xor3128".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::XOR3_128);
        let chunk_size = max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Xor3128(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let mut row = [F::ZERO; NUM_XOR3_128_COLS];
                    self.event_to_row(event, &mut row, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F>{
        let events = input.get_precompile_events(SyscallCode::XOR3_128);
        let mut rows = events
            .par_iter()
            .map(|(_, event)| {
                let event = if let PrecompileEvent::Xor3128(event) = event {
                    event
                } else {
                    unreachable!();
                };

                let mut row = [F::ZERO; NUM_XOR3_128_COLS];
                self.event_to_row(event, &mut row, &mut Vec::new());
                row
            })
            .collect::<Vec<_>>();

        let num_real_rows = rows.len();
        let padded_num_rows = num_real_rows.next_power_of_two();
        for _ in num_real_rows..padded_num_rows {
            let row = [F::ZERO; NUM_XOR3_128_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_XOR3_128_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::XOR3_128).is_empty()
        }
    }
}

impl Xor3128Chip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &Xor3128Event,
        row: &mut [F],
        blu: &mut impl ByteRecord,
    ) {
        let col: &mut Xor3128Cols<F> = row.borrow_mut();
        col.clk = F::from_canonical_u32(event.clk);
        col.shard = F::from_canonical_u32(event.shard);
        col.input_address = F::from_canonical_u32(event.input_addr);
        col.result_address = F::from_canonical_u32(event.result_addr);
        col.is_real = F::ONE;
        col.receive_syscall = F::ONE;

        // read the input
        for i in 0..12 {
            col.input_mem[i].populate(event.input_read_records[i], blu);
        }

        // intermediate[i] = a[i] ^ b[i]
        let mut inter = [0_u32; 4];
        for i in 0..4 {
            inter[i] = col.intermediate[i].populate(
                blu,
                event.input_a[i],
                event.input_b[i],
            );
        }

        // output:
        for i in 0..4 {
            // adapt from XorOperation
            let left_bytes = inter[i].to_le_bytes();
            let right_bytes = event.input_c[i].to_le_bytes();
            for j in 0..WORD_SIZE {
                let xor = left_bytes[j] ^ right_bytes[j];
                let byte_event = ByteLookupEvent {
                    opcode: ByteOpcode::XOR,
                    a1: xor as u16,
                    a2: 0,
                    b: left_bytes[j],
                    c: right_bytes[j],
                };
                blu.add_byte_lookup_event(byte_event);
            }
        }

        // write the result
        for i in 0..4 {
            col.result_mem[i].populate(event.result_write_records[i], blu);
        }
    }
}