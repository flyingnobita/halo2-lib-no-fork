use crate::halo2_proofs::halo2curves::bls12_381::{Fq, Fq12, Fq2};
use crate::{
    bigint::CRTInteger,
    fields::{fp, fp12, fp2, FieldExtPoint},
};

pub mod bls_signature;
pub mod bls_signature_test;
pub mod final_exp;
pub mod frobenius_map_fp2;
pub mod pairing;

pub type FpChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type FpPoint<F> = CRTInteger<F>;
pub type FqPoint<F> = FieldExtPoint<FpPoint<F>>;
pub type Fp2Chip<'chip, F> = fp2::Fp2Chip<'chip, F, FpChip<'chip, F>, Fq2>;
pub type Fp12Chip<'chip, F> = fp12::Fp12Chip<'chip, F, FpChip<'chip, F>, Fq12, 9>;

// #[cfg(test)]
// pub(crate) mod tests;
