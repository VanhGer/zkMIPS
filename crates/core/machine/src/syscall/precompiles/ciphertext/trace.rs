use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::ParallelSlice;
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_core_executor::events::{ByteLookupEvent, ByteRecord, CiphertextCheckEvent, PrecompileEvent};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::MachineAir;
use std::borrow::BorrowMut;
use rayon::iter::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use crate::CiphertextCheckChip;
use crate::syscall::precompiles::ciphertext::columns::{CiphertextCheckCols, NUM_CIPHERTEXT_CHECK_COLS};

impl<F: PrimeField32> MachineAir<F> for CiphertextCheckChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "CiphertextCheck".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::CIPHERTEXT_CHECK);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::CiphertextCheck(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let _ = self.event_to_rows::<F>(&event, &mut blu);
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
        let events = input.get_precompile_events(SyscallCode::CIPHERTEXT_CHECK);
        let mut rows: Vec<[F; NUM_CIPHERTEXT_CHECK_COLS]> = events
            .par_iter()
            .flat_map(|(_, event)| {
                let event = if let PrecompileEvent::CiphertextCheck(event) = event {
                    event
                } else {
                    unreachable!();
                };

                self.event_to_rows(&event, &mut Vec::new())
            })
            .collect();



        let num_real_rows = rows.len();
        let padded_num_rows = num_real_rows.next_power_of_two();
        for _ in num_real_rows..padded_num_rows {
            let row = [F::ZERO; NUM_CIPHERTEXT_CHECK_COLS];
            rows.push(row);
        }
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_CIPHERTEXT_CHECK_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::CIPHERTEXT_CHECK).is_empty()
        }
    }
}

impl CiphertextCheckChip {
    pub fn event_to_rows<F: PrimeField32>(
        &self,
        event: &CiphertextCheckEvent,
        blu: &mut impl ByteRecord,
    ) -> Vec<[F; NUM_CIPHERTEXT_CHECK_COLS]> {
        let gates_num = event.num_gates();
        let mut rows = Vec::new();

        let mut input_address = event.input_addr + 4; // skip num_gates u32
        let mut pre_check = true;
        for gate_id in 0..gates_num {
            let mut row = [F::ZERO; NUM_CIPHERTEXT_CHECK_COLS];
            let cols: &mut CiphertextCheckCols<F> = row.as_mut_slice().borrow_mut();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::ONE;
            cols.receive_syscall = F::from_bool(gate_id == 0);
            cols.input_address = F::from_canonical_u32(input_address);
            cols.output_address = F::from_canonical_u32(event.output_addr);
            cols.is_first_gate = F::from_bool(gate_id == 0);
            cols.is_last_gate = F::from_bool(gate_id == gates_num - 1);
            cols.not_last_gate = F::from_bool(gate_id != gates_num - 1);
            cols.gate_id = F::from_canonical_u32(gate_id as u32);
            cols.gates_num = F::from_canonical_u32(gates_num as u32);

            if gate_id == 0 {
                // read number of gates
                cols.gates_num_mem.populate(event.num_gates_read_record, blu);
            }

            // read gate info
            for i in 0..16 {
                cols.gates_input_mem[i].populate(event.gates_read_records[gate_id * 16 + i], blu);
            }

            // XOR computation
            let mut check_u32s = [0u32; 4];
            for i in 0..4 {
                let h0_id = gate_id * 16 + i;
                let h1_id = gate_id * 16 + 4 + i;
                let label_b_id = gate_id * 16 + 8 + i;
                let expected_id = gate_id * 16 + 12 + i;

                let inter1 = cols.inter1[i].populate(blu, event.gates_info[h0_id], event.gates_info[h1_id]);
                let inter2 = cols.inter2[i].populate(blu, inter1, event.gates_info[label_b_id]);
                if i == 0 {
                    check_u32s[i] = cols.is_equal_words[i].populate(inter2, event.gates_info[expected_id]);
                } else  {
                    check_u32s[i] = check_u32s[i - 1] * cols.is_equal_words[i].populate(inter2, event.gates_info[expected_id]);
                }

            }
            // populate check results
            cols.checks[0] = F::from_canonical_u32(check_u32s[1]);
            cols.checks[1] = F::from_canonical_u32(check_u32s[2]);
            cols.checks[2] = F::from_canonical_u32(check_u32s[3]);
            cols.checks[3] = F::from_canonical_u32(check_u32s[3] * (pre_check as u32));
            pre_check = pre_check && (check_u32s[3] == 1);

            // if this is the last gate, write result
            if gate_id == gates_num - 1 {
                cols.result_mem.populate(event.output_write_record, blu);
            }

            rows.push(row);
            input_address += 64;
        }
        rows
    }
}