use std::array;

use p3_air::PairBuilder;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_poseidon2::matmul_internal;
use zkm_primitives::RC_16_30_U32;
use zkm_stark::air::MachineAirBuilder;

use super::{permutation::Poseidon2Cols, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

const INTERNAL_DIAG_MONTY_16: [KoalaBear; 16] = KoalaBear::new_array([
    KoalaBear::ORDER_U32 - 2,
    1,
    2,
    (KoalaBear::ORDER_U32 + 1) >> 1,
    3,
    4,
    (KoalaBear::ORDER_U32 - 1) >> 1,
    KoalaBear::ORDER_U32 - 3,
    KoalaBear::ORDER_U32 - 4,
    KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 8),
    KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 3),
    KoalaBear::ORDER_U32 - 127,
    (KoalaBear::ORDER_U32 - 1) >> 8,
    (KoalaBear::ORDER_U32 - 1) >> 3,
    (KoalaBear::ORDER_U32 - 1) >> 4,
    127,
]);

pub fn apply_m_4_mut<AF>(x: &mut [AF])
where
    AF: FieldAlgebra,
{
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123.clone() + x[3].clone();
    x[3] = t01233.clone() + x[0].double();
    x[1] = t01123.clone() + x[2].double();
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

pub fn external_linear_layer_mut<AF: FieldAlgebra>(state: &mut [AF; WIDTH]) {
    for j in (0..WIDTH).step_by(4) {
        apply_m_4_mut(&mut state[j..j + 4]);
    }
    let sums: [AF; 4] =
        core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| state[j + k].clone()).sum::<AF>());

    for j in 0..WIDTH {
        state[j] = state[j].clone() + sums[j % 4].clone();
    }
}

pub fn external_linear_layer<AF: FieldAlgebra + Copy>(state: &[AF; WIDTH]) -> [AF; WIDTH] {
    let mut state = *state;
    external_linear_layer_mut(&mut state);
    state
}

pub fn internal_linear_layer_mut<F: FieldAlgebra>(state: &mut [F; WIDTH]) {
    let matmul_constants: [<F as FieldAlgebra>::F; WIDTH] = INTERNAL_DIAG_MONTY_16
        .iter()
        .map(|x| <F as FieldAlgebra>::F::from_wrapped_u32(x.as_canonical_u32()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    matmul_internal(state, matmul_constants);
}

/// Eval the constraints for the external rounds.
pub fn eval_external_round<AB>(builder: &mut AB, local_row: &dyn Poseidon2Cols<AB::Var>, r: usize)
where
    AB: MachineAirBuilder + PairBuilder,
{
    let mut local_state: [AB::Expr; WIDTH] =
        array::from_fn(|i| local_row.external_rounds_state()[r][i].into());

    // For the first round, apply the linear layer.
    if r == 0 {
        external_linear_layer_mut(&mut local_state);
    }

    // Add the round constants.
    let round = if r < NUM_EXTERNAL_ROUNDS / 2 { r } else { r + NUM_INTERNAL_ROUNDS };
    let add_rc: [AB::Expr; WIDTH] = array::from_fn(|i| {
        local_state[i].clone() + AB::F::from_wrapped_u32(RC_16_30_U32[round][i])
    });

    // Apply the sboxes.
    // See `populate_external_round` for why we don't have columns for the sbox output here.
    let mut sbox_deg_3: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::ZERO);
    for i in 0..WIDTH {
        let calculated_sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

        if let Some(external_sbox) = local_row.external_rounds_sbox() {
            builder.assert_eq(external_sbox[r][i].into(), calculated_sbox_deg_3);
            sbox_deg_3[i] = external_sbox[r][i].into();
        } else {
            sbox_deg_3[i] = calculated_sbox_deg_3;
        }
    }

    // Apply the linear layer.
    let mut state = sbox_deg_3;
    external_linear_layer_mut(&mut state);

    let next_state = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
        local_row.internal_rounds_state()
    } else if r == NUM_EXTERNAL_ROUNDS - 1 {
        local_row.perm_output()
    } else {
        &local_row.external_rounds_state()[r + 1]
    };

    for i in 0..WIDTH {
        builder.assert_eq(next_state[i], state[i].clone());
    }
}

/// Eval the constraints for the internal rounds.
pub fn eval_internal_rounds<AB>(builder: &mut AB, local_row: &dyn Poseidon2Cols<AB::Var>)
where
    AB: MachineAirBuilder + PairBuilder,
{
    let state = &local_row.internal_rounds_state();
    let s0 = local_row.internal_rounds_s0();
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i].into());
    for r in 0..NUM_INTERNAL_ROUNDS {
        // Add the round constant.
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = if r == 0 { state[0].clone() } else { s0[r - 1].into() }
            + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

        let mut sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        if let Some(internal_sbox) = local_row.internal_rounds_sbox() {
            builder.assert_eq(internal_sbox[r], sbox_deg_3);
            sbox_deg_3 = internal_sbox[r].into();
        }

        // Apply the linear layer.
        // See `populate_internal_rounds` for why we don't have columns for the new state here.
        state[0] = sbox_deg_3.clone();
        internal_linear_layer_mut(&mut state);

        if r < NUM_INTERNAL_ROUNDS - 1 {
            builder.assert_eq(s0[r], state[0].clone());
        }
    }

    let external_state = local_row.external_rounds_state()[NUM_EXTERNAL_ROUNDS / 2];
    for i in 0..WIDTH {
        builder.assert_eq(external_state[i], state[i].clone())
    }
}
