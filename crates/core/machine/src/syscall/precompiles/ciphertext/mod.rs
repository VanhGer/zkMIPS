mod air;
mod columns;
mod trace;

#[derive(Default)]
pub struct CiphertextCheckChip;

impl CiphertextCheckChip {
    pub const fn new() -> Self {
        Self {}
    }
}
