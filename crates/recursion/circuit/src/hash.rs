use std::fmt::Debug;
use std::iter::{repeat, zip};

use itertools::Itertools;
use p3_field::{Field, FieldAlgebra};
use p3_koala_bear::KoalaBear;

use p3_bn254_fr::Bn254Fr;
use p3_symmetric::Permutation;
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Felt, Var},
};
use zkm_recursion_core::stark::{outer_perm, OUTER_MULTI_FIELD_CHALLENGER_WIDTH};
use zkm_recursion_core::{stark::KoalaBearPoseidon2Outer, DIGEST_SIZE};
use zkm_recursion_core::{HASH_RATE, PERMUTATION_WIDTH};
use zkm_stark::inner_perm;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;

use crate::{
    challenger::{reduce_32, POSEIDON_2_BB_RATE},
    CircuitConfig,
};

pub trait FieldHasher<F: Field> {
    type Digest: Copy + Default + Eq + Ord + Copy + Debug + Send + Sync;

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;
}

pub trait Posedion2KoalaBearHasherVariable<C: CircuitConfig> {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<C::F>; PERMUTATION_WIDTH],
    ) -> [Felt<C::F>; PERMUTATION_WIDTH];

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| builder.eval(C::F::ZERO));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = Self::poseidon2_permute(builder, state);
        }
        let digest: [Felt<C::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }
}

pub trait FieldHasherVariable<C: CircuitConfig>: FieldHasher<C::F> {
    type DigestVariable: Clone + Copy;

    fn hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> Self::DigestVariable;

    fn compress(builder: &mut Builder<C>, input: [Self::DigestVariable; 2])
        -> Self::DigestVariable;

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::DigestVariable, b: Self::DigestVariable);

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: C::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2];

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable);
}

impl FieldHasher<KoalaBear> for KoalaBearPoseidon2 {
    type Digest = [KoalaBear; DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut pre_iter = input.into_iter().flatten().chain(repeat(KoalaBear::ZERO));
        let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        (inner_perm()).permute_mut(&mut pre);
        pre[..DIGEST_SIZE].try_into().unwrap()
    }
}

impl<C: CircuitConfig<F = KoalaBear>> Posedion2KoalaBearHasherVariable<C> for KoalaBearPoseidon2 {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        input: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        builder.poseidon2_permute_v2(input)
    }
}

impl<C: CircuitConfig> Posedion2KoalaBearHasherVariable<C> for KoalaBearPoseidon2Outer {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        let state: [Felt<_>; PERMUTATION_WIDTH] = state.map(|x| builder.eval(x));
        builder.push_op(DslIr::CircuitPoseidon2PermuteKoalaBear(Box::new(state)));
        state
    }
}

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> FieldHasherVariable<C>
    for KoalaBearPoseidon2
{
    type DigestVariable = [Felt<KoalaBear>; DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        <Self as Posedion2KoalaBearHasherVariable<C>>::poseidon2_hash(builder, input)
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        builder.poseidon2_compress_v2(input.into_iter().flatten())
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Felt<KoalaBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());
        let result1: [Felt<KoalaBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());

        (0..DIGEST_SIZE).for_each(|i| {
            builder.push_op(DslIr::Select(
                should_swap,
                result0[i],
                result1[i],
                input[0][i],
                input[1][i],
            ));
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_f(*d);
        }
    }
}

pub const BN254_DIGEST_SIZE: usize = 1;

impl FieldHasher<KoalaBear> for KoalaBearPoseidon2Outer {
    type Digest = [Bn254Fr; BN254_DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut state = [input[0][0], input[1][0], Bn254Fr::ZERO];
        outer_perm().permute_mut(&mut state);
        [state[0]; BN254_DIGEST_SIZE]
    }
}

impl<C: CircuitConfig<F = KoalaBear, N = Bn254Fr, Bit = Var<Bn254Fr>>> FieldHasherVariable<C>
    for KoalaBearPoseidon2Outer
{
    type DigestVariable = [Var<Bn254Fr>; BN254_DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        assert!(C::N::bits() == p3_bn254_fr::Bn254Fr::bits());
        assert!(C::F::bits() == p3_koala_bear::KoalaBear::bits());
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(C::N::ZERO), builder.eval(C::N::ZERO), builder.eval(C::N::ZERO)];
        for block_chunk in &input.iter().chunks(POSEIDON_2_BB_RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(builder, chunk.as_slice());
            }
            builder.push_op(DslIr::CircuitPoseidon2Permute(state))
        }

        [state[0]; BN254_DIGEST_SIZE]
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        let state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(input[0][0]), builder.eval(input[1][0]), builder.eval(C::N::ZERO)];
        builder.push_op(DslIr::CircuitPoseidon2Permute(state));
        [state[0]; BN254_DIGEST_SIZE]
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[1][j], input[0][j], result));
            result
        });
        let result1: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[0][j], input[1][j], result));
            result
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_v(*d);
        }
    }
}
