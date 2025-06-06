use itertools::Itertools;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::circuit::CircuitV2Builder;
use zkm_recursion_compiler::ir::{Builder, Config, Felt};
use zkm_recursion_core::air::RecursionPublicValues;

/// Assertions on recursion public values which represent a complete proof.
///
/// The assertions consist of checking all the expected boundary conditions from a compress proof
/// that represents the end of the recursion tower.
pub(crate) fn assert_complete<C: Config<F = KoalaBear>>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
    is_complete: Felt<C::F>,
) {
    let RecursionPublicValues {
        deferred_proofs_digest,
        next_pc,
        start_shard,
        next_shard,
        start_execution_shard,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        global_cumulative_sum,
        contains_execution_shard,
        ..
    } = public_values;

    // Assert that the `is_complete` flag is boolean.
    builder.assert_felt_eq(is_complete * (is_complete - C::F::ONE), C::F::ZERO);

    // Assert that `next_pc` is equal to zero (so program execution has completed)
    builder.assert_felt_eq(is_complete * *next_pc, C::F::ZERO);

    // Assert that start shard is equal to 1.
    builder.assert_felt_eq(is_complete * (*start_shard - C::F::ONE), C::F::ZERO);

    // Assert that the next shard is not equal to one. This guarantees that there is at least one
    // shard that contains CPU.
    //
    // TODO: figure out if this is needed.
    builder.assert_felt_ne(is_complete * *next_shard, C::F::ONE);

    // Assert that that an execution shard is present.
    builder.assert_felt_eq(is_complete * (*contains_execution_shard - C::F::ONE), C::F::ZERO);
    // Assert that the start execution shard is equal to 1.
    builder.assert_felt_eq(is_complete * (*start_execution_shard - C::F::ONE), C::F::ZERO);

    // The start reconstruct deferred digest should be zero.
    for start_digest_word in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(is_complete * *start_digest_word, C::F::ZERO);
    }

    // The end reconstruct deferred digest should be equal to the deferred proofs digest.
    for (end_digest_word, deferred_digest_word) in
        end_reconstruct_deferred_digest.iter().zip_eq(deferred_proofs_digest.iter())
    {
        builder
            .assert_felt_eq(is_complete * (*end_digest_word - *deferred_digest_word), C::F::ZERO);
    }

    builder.assert_digest_zero_v2(is_complete, *global_cumulative_sum);
}
