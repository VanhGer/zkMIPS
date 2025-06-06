use enum_map::EnumMap;
use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::{FieldAlgebra, PrimeField};
use zkm_stark::{
    air::{MachineAir, PublicValues},
    shape::Shape,
    MachineRecord, SplitOpts, ZKMCoreOpts,
};

use serde::{Deserialize, Serialize};
use std::{mem::take, str::FromStr, sync::Arc};

use crate::{
    events::{
        AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, CompAluEvent, CpuEvent,
        GlobalLookupEvent, JumpEvent, MemInstrEvent, MemoryInitializeFinalizeEvent,
        MemoryLocalEvent, MemoryRecordEnum, MiscEvent, PrecompileEvent, PrecompileEvents,
        SyscallEvent,
    },
    syscalls::{precompiles::keccak::sponge::GENERAL_BLOCK_SIZE_U32S, SyscallCode},
    MipsAirId, Program,
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
// todo: add logic opcode here, use bitwise_events
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,
    /// A trace of the ADD, ADDU, ADDI and ADDIU events.
    pub add_events: Vec<AluEvent>,
    /// A trace of the MUL, MULT and MULTU events.
    pub mul_events: Vec<CompAluEvent>,
    /// A trace of the SUB and SUBU events.
    pub sub_events: Vec<AluEvent>,
    /// A trace of the XOR, OR, AND and NOR events.
    pub bitwise_events: Vec<AluEvent>,
    /// A trace of the SLL and SLLV events.
    pub shift_left_events: Vec<AluEvent>,
    /// A trace of the SRL, SRLV, SRA, and SRAV events.
    pub shift_right_events: Vec<AluEvent>,
    /// A trace of the DIV, DIVU events.
    pub divrem_events: Vec<CompAluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
    /// A trace of the CLO and CLZ events.
    pub cloclz_events: Vec<AluEvent>,
    /// A trace of the memory instructions.
    pub memory_instr_events: Vec<MemInstrEvent>,
    /// A trace of the branch events.
    pub branch_events: Vec<BranchEvent>,
    /// A trace of the jump events.
    pub jump_events: Vec<JumpEvent>,
    /// A trace of the misc events.
    pub misc_events: Vec<MiscEvent>,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<ByteLookupEvent, usize>,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    // /// A trace of the global memory initialize events.
    pub global_memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    // /// A trace of the global memory finalize events.
    pub global_memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of all the shard's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<SyscallEvent>,
    /// A trace of all the global lookup events.
    pub global_lookup_events: Vec<GlobalLookupEvent>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,
    /// The shape of the proof.
    pub shape: Option<Shape<MipsAirId>>,
    /// The predicted counts of the proof.
    pub counts: Option<EnumMap<MipsAirId, u64>>,
}

impl ExecutionRecord {
    /// Create a new [`ExecutionRecord`].
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        Self { program, ..Default::default() }
    }

    /// Add a mul event to the execution record.
    pub fn add_mul_event(&mut self, mul_event: CompAluEvent) {
        self.mul_events.push(mul_event);
    }

    /// Add a lt event to the execution record.
    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    /// Take out events from the [`ExecutionRecord`] that should be deferred to a separate shard.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every shard.
    #[must_use]
    pub fn defer(&mut self) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::new(self.program.clone());
        execution_record.precompile_events = std::mem::take(&mut self.precompile_events);
        execution_record.global_memory_initialize_events =
            std::mem::take(&mut self.global_memory_initialize_events);
        execution_record.global_memory_finalize_events =
            std::mem::take(&mut self.global_memory_finalize_events);
        execution_record
    }

    /// Splits the deferred [`ExecutionRecord`] into multiple [`ExecutionRecord`]s, each which
    /// contain a "reasonable" number of deferred events.
    pub fn split(&mut self, last: bool, opts: SplitOpts) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();

        let precompile_events = take(&mut self.precompile_events);

        for (syscall_code, events) in precompile_events.into_iter() {
            let threshold = match syscall_code {
                SyscallCode::KECCAK_SPONGE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                _ => opts.deferred,
            };

            let mut shards_input = Vec::new();
            let remainder = if syscall_code == SyscallCode::KECCAK_SPONGE {
                let mut current_shard = Vec::new();
                let mut current_len = 0;

                for (syscall_event, event) in events {
                    if let PrecompileEvent::KeccakSponge(event) = &event {
                        // Here, input_len_u32s must be a multiple of GENERAL_BLOCK_SIZE_U32S.
                        let input_len = event.input_len_u32s as usize / GENERAL_BLOCK_SIZE_U32S;

                        if current_len + input_len > threshold && !current_shard.is_empty() {
                            let mut record = ExecutionRecord::new(self.program.clone());
                            record.precompile_events.insert(syscall_code, current_shard);
                            shards_input.push(record);
                            current_shard = Vec::new();
                            current_len = 0;
                        }
                        current_len += input_len;
                    }
                    current_shard.push((syscall_event, event));
                }

                current_shard
            } else {
                let chunks = events.chunks_exact(threshold);
                let remainder = chunks.remainder().to_vec();

                for chunk in chunks {
                    let mut record = ExecutionRecord::new(self.program.clone());
                    record.precompile_events.insert(syscall_code, chunk.to_vec());
                    shards_input.push(record);
                }

                remainder
            };
            if !remainder.is_empty() {
                if last {
                    let mut record = ExecutionRecord::new(self.program.clone());
                    record.precompile_events.insert(syscall_code, remainder);
                    shards_input.push(record);
                } else {
                    self.precompile_events.insert(syscall_code, remainder);
                }
            }

            shards.extend(shards_input);
        }

        if last {
            self.global_memory_initialize_events.sort_by_key(|event| event.addr);
            self.global_memory_finalize_events.sort_by_key(|event| event.addr);

            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for mem_chunks in self
                .global_memory_initialize_events
                .chunks(opts.memory)
                .zip_longest(self.global_memory_finalize_events.chunks(opts.memory))
            {
                let (mem_init_chunk, mem_finalize_chunk) = match mem_chunks {
                    EitherOrBoth::Both(mem_init_chunk, mem_finalize_chunk) => {
                        (mem_init_chunk, mem_finalize_chunk)
                    }
                    EitherOrBoth::Left(mem_init_chunk) => (mem_init_chunk, [].as_slice()),
                    EitherOrBoth::Right(mem_finalize_chunk) => ([].as_slice(), mem_finalize_chunk),
                };
                let mut shard = ExecutionRecord::new(self.program.clone());
                shard.global_memory_initialize_events.extend_from_slice(mem_init_chunk);
                shard.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    let last_init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    init_addr_bits = last_init_addr_bits;
                }
                shard.public_values.last_init_addr_bits = init_addr_bits;

                shard.global_memory_finalize_events.extend_from_slice(mem_finalize_chunk);
                shard.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    let last_finalize_addr_bits =
                        core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    finalize_addr_bits = last_finalize_addr_bits;
                }
                shard.public_values.last_finalize_addr_bits = finalize_addr_bits;

                shards.push(shard);
            }
        }

        shards
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    pub fn fixed_log2_rows<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape.as_ref().map(|shape| {
            shape
                .log2_height(&MipsAirId::from_str(&air.name()).unwrap())
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    /// Determines whether the execution record contains CPU events.
    #[must_use]
    pub fn contains_cpu(&self) -> bool {
        !self.cpu_events.is_empty()
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.precompile_events.add_event(syscall_code, syscall_event, event);
    }

    /// Get all the precompile events for a syscall code.
    #[inline]
    #[must_use]
    pub fn get_precompile_events(
        &self,
        syscall_code: SyscallCode,
    ) -> &Vec<(SyscallEvent, PrecompileEvent)> {
        self.precompile_events.get_events(syscall_code).expect("Precompile events not found")
    }

    /// Get all the local memory events.
    #[inline]
    pub fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let precompile_local_mem_events = self.precompile_events.get_local_mem_events();
        precompile_local_mem_events.chain(self.cpu_local_memory_access.iter())
    }
}

/// A memory access record.
#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register. read && write
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `hi` register and other special registers.
    /// read && write
    pub hi: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
}

impl MachineRecord for ExecutionRecord {
    type Config = ZKMCoreOpts;

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("add_events".to_string(), self.add_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("sub_events".to_string(), self.sub_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert("shift_left_events".to_string(), self.shift_left_events.len());
        stats.insert("shift_right_events".to_string(), self.shift_right_events.len());
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert("cloclz_events".to_string(), self.cloclz_events.len());
        stats.insert("memory_instr_events".to_string(), self.memory_instr_events.len());
        stats.insert("branch_events".to_string(), self.branch_events.len());
        stats.insert("jump_events".to_string(), self.jump_events.len());
        stats.insert("misc_events".to_string(), self.misc_events.len());

        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }

        stats.insert(
            "global_memory_initialize_events".to_string(),
            self.global_memory_initialize_events.len(),
        );
        stats.insert(
            "global_memory_finalize_events".to_string(),
            self.global_memory_finalize_events.len(),
        );
        stats.insert("local_memory_access_events".to_string(), self.cpu_local_memory_access.len());
        if !self.cpu_events.is_empty() {
            stats.insert("byte_lookups".to_string(), self.byte_lookups.len());
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_events.append(&mut other.add_events);
        self.sub_events.append(&mut other.sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events.append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.cloclz_events.append(&mut other.cloclz_events);
        self.memory_instr_events.append(&mut other.memory_instr_events);
        self.branch_events.append(&mut other.branch_events);
        self.jump_events.append(&mut other.jump_events);
        self.misc_events.append(&mut other.misc_events);
        self.syscall_events.append(&mut other.syscall_events);

        self.precompile_events.append(&mut other.precompile_events);

        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut other.byte_lookups);
        } else {
            self.add_byte_lookup_events_from_maps(vec![&other.byte_lookups]);
        }

        self.global_memory_initialize_events.append(&mut other.global_memory_initialize_events);
        self.global_memory_finalize_events.append(&mut other.global_memory_finalize_events);
        self.cpu_local_memory_access.append(&mut other.cpu_local_memory_access);
        self.global_lookup_events.append(&mut other.global_lookup_events);
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: FieldAlgebra>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;
    }

    #[inline]
    fn add_byte_lookup_events_from_maps(
        &mut self,
        new_events: Vec<&HashMap<ByteLookupEvent, usize>>,
    ) {
        for new_blu_map in new_events {
            for (blu_event, count) in new_blu_map.iter() {
                *self.byte_lookups.entry(*blu_event).or_insert(0) += count;
            }
        }
    }
}
