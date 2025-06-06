//! A STARK framework.

//#![no_std]

extern crate alloc;

pub mod air;
mod chip;
mod config;
mod debug;
mod folder;
mod kb31_poseidon2;
mod lookup;
mod machine;
mod opts;
mod permutation;
mod proof;
mod prover;
mod quotient;
mod record;
pub mod septic_curve;
pub mod septic_digest;
pub mod septic_extension;
pub mod shape;
#[cfg(test)]
mod stark_testing;
mod types;
mod verifier;
mod word;
mod zerofier_coset;

pub use air::*;
pub use chip::*;
pub use config::*;
pub use debug::*;
pub use folder::*;
pub use kb31_poseidon2::*;
pub use lookup::*;
pub use machine::*;
pub use opts::*;
pub use permutation::*;
pub use proof::*;
pub use prover::*;
pub use quotient::*;
pub use record::*;
pub use types::*;
pub use verifier::*;
pub use word::*;
pub use zerofier_coset::*;
