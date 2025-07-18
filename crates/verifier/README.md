# Ziren Verifier

This crate provides verifiers for Ziren Groth16 and Plonk zero-knowledge proofs. These proofs are expected
to be generated using the [Ziren SDK](../sdk).

## Features

Groth16 and Plonk proof verification are supported in `no-std` environments. Verification in the
Ziren zkVM context is patched, in order to make use of the bn254 precompiles.

### Pre-generated verification keys

Verification keys for Groth16 and Plonk are stored in the [`bn254-vk`](./bn254-vk/) directory. These
vkeys are used to verify all Ziren proofs.

These vkeys are the same as those found locally in
`~/.zkm/circuits/<circuit_name>/<version>/<circuit_name>_vk.bin`, and should be automatically
updated after every release.

## Tests

Run tests with the following command:

```sh
cargo test --package zkm-verifier
```

These tests verify the proofs in the [`test_binaries`](./test_binaries) directory. These test binaries
were generated from the fibonacci [groth16](../../examples/fibonacci/host/bin/groth16_bn254.rs) and
[plonk](../../examples/fibonacci/host/bin/plonk_bn254.rs) examples. You can reproduce these proofs
from the examples by running `cargo run --bin groth16_bn254` and `cargo run --bin plonk_bn254` from the
[`examples/fibonacci`](../../examples/fibonacci/) directory.

## Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.
