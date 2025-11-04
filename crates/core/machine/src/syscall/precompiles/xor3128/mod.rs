mod columns;
mod trace;
mod air;

#[derive(Default)]
pub struct Xor3128Chip;

impl Xor3128Chip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod tests {
    use crate::utils::{self, run_test};
    use test_artifacts::XOR3128_ELF;
    use zkm_core_executor::Program;
    use zkm_stark::CpuProver;
    #[test]
    fn test_xor3128_program_prove() {
        utils::setup_logger();
        let program = Program::from(XOR3128_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}