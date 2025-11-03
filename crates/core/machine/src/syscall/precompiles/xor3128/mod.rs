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
