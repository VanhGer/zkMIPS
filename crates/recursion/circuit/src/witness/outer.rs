use std::borrow::Borrow;

use p3_bn254_fr::Bn254Fr;
use p3_field::FieldAlgebra;

use p3_fri::{CommitPhaseProofStep, QueryProof};
pub use zkm_recursion_compiler::ir::Witness as OuterWitness;
use zkm_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Var},
};
use zkm_recursion_core::stark::{
    KoalaBearPoseidon2Outer, OuterBatchOpening, OuterChallenge, OuterChallengeMmcs, OuterDigest,
    OuterFriProof, OuterInputProof, OuterVal,
};

use crate::{
    BatchOpeningVariable, CircuitConfig, FriCommitPhaseProofStepVariable, FriProofVariable,
    FriQueryProofVariable,
};

use super::{WitnessWriter, Witnessable};

impl WitnessWriter<OuterConfig> for OuterWitness<OuterConfig> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(Bn254Fr::from_bool(value));
    }

    fn write_var(&mut self, value: Bn254Fr) {
        self.vars.push(value);
    }

    fn write_felt(&mut self, value: OuterVal) {
        self.felts.push(value);
    }

    fn write_ext(&mut self, value: OuterChallenge) {
        self.exts.push(value);
    }
}

impl<C: CircuitConfig<N = Bn254Fr>> Witnessable<C> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_var(*self)
    }
}

impl Witnessable<OuterConfig> for OuterBatchOpening {
    type WitnessVariable = BatchOpeningVariable<OuterConfig, KoalaBearPoseidon2Outer>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        let opened_values =
            self.opened_values.read(builder).into_iter().map(|a| a.into_iter().collect()).collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { opened_values, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}

impl Witnessable<OuterConfig> for OuterFriProof {
    type WitnessVariable = FriProofVariable<OuterConfig, KoalaBearPoseidon2Outer>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: &OuterDigest = commit.borrow();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        Self::WitnessVariable { commit_phase_commits, query_proofs, final_poly, pow_witness }
    }

    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        self.commit_phase_commits.iter().for_each(|commit| {
            let commit = Borrow::<OuterDigest>::borrow(commit);
            commit.write(witness);
        });
        self.query_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}

impl Witnessable<OuterConfig> for CommitPhaseProofStep<OuterChallenge, OuterChallengeMmcs> {
    type WitnessVariable = FriCommitPhaseProofStepVariable<OuterConfig, KoalaBearPoseidon2Outer>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { sibling_value, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        self.sibling_value.write(witness);
        self.opening_proof.write(witness);
    }
}

impl Witnessable<OuterConfig> for QueryProof<OuterChallenge, OuterChallengeMmcs, OuterInputProof> {
    type WitnessVariable = FriQueryProofVariable<OuterConfig, KoalaBearPoseidon2Outer>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        let input_proof = self.input_proof.read(builder);
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        Self::WitnessVariable { input_proof, commit_phase_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        self.input_proof.write(witness);
        self.commit_phase_openings.write(witness);
    }
}
