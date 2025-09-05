use ff::PrimeField as FFPrimeField;
use p3_sect_fr::{params::RC3, FFSectFr, FpSECT as ark_FpSECT, SectFr};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
};

fn bn254_from_ark_ff(input: ark_FpSECT) -> SectFr {
    let bytes = input.into_bigint().to_bytes_le();

    let mut res = <FFSectFr as ff::PrimeField>::Repr::default();

    for (i, digit) in res.as_mut().iter_mut().enumerate() {
        *digit = bytes[i];
    }

    let value = FFSectFr::from_repr(res);

    if value.is_some().into() {
        SectFr { value: value.unwrap() }
    } else {
        panic!("Invalid field element")
    }
}

pub fn bn254_poseidon2_rc3() -> Vec<[SectFr; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
        })
        .collect()
}

pub fn bn254_poseidon2_rc4() -> Vec<[SectFr; 4]> {
    RC3.iter()
        .map(|vec| {
            let result: [SectFr; 3] =
                vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap();
            [result[0], result[1], result[2], result[2]]
        })
        .collect()
}
