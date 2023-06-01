#![allow(non_snake_case)]
use std::fs::File;

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FpPoint, FqPoint};
use crate::bigint::CRTInteger;
use crate::ecc::{EcPoint, EccChip};
use crate::fields::{self, FieldChip, FieldExtPoint, FpStrategy, PrimeField, PrimeFieldChip};
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq12, BN_X};
use halo2_base::Context;
use num_bigint::BigUint;

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows

pub struct BlsSignatureChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip_1: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip: pairing_chip_1 }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1
    // where e(,) is optimal Ate pairing
    // G1: {g1, pubkey}, G2: {signature, message}
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signature: G2Affine,
        pubkey: G1Affine,
        msghash: G2Affine,
    ) -> FqPoint<F> {
        // ) -> halo2_base::AssignedValue<F> {

        let g1_assigned = self.pairing_chip.load_private_g1(ctx, g1);
        let signature_assigned = self.pairing_chip.load_private_g2(ctx, signature);
        let pubkey_assigned = self.pairing_chip.load_private_g1(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip.load_private_g2(ctx, msghash);

        // Check points are on curve
        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>(
            ctx,
            &g1_assigned,
        );
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G2Affine>(
            ctx,
            &signature_assigned,
        );
        // Checking pubkefiny is on curve also check that it's in subgroup G1 since G1 has cofactor of 1
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>(
            ctx,
            &pubkey_assigned,
        );
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G2Affine>(
            ctx,
            &hash_m_assigned,
        );

        // Check Signature is in Subgroup G2
        self.assert_in_g2(ctx, &signature_assigned.clone());

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_assigned);

        let multi_paired = self.pairing_chip.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &neg_signature_assigned_g12), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result = fp12_chip.final_exp(ctx, &multi_paired);
        result

        // Verify signature
        // let fp12_chip_2 = Fp12Chip::<F>::new(self.fp_chip);
        // let one = fp12_chip_2.load_private(ctx, Fp12Chip::<F>::fe_to_witness(&Fq12::one()));
        // fp12_chip_2.is_equal(ctx, &result, &one)
    }

    /// Subgroup check for G2:
    /// use the latest method by El Housni, Guillevic, Piellard: https://eprint.iacr.org/2022/352.pdf
    /// By Proposition 3, enough to check psi(P) = [lambda]P for lambda = t - 1 = 6 * x^2
    pub fn assert_in_g2(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FieldExtPoint<FpPoint<F>>>,
        // P: &FieldExtPoint<FpPoint<F>>,
    ) {
        // calculate Endomorphism Psi of P
        // get fp12 frobenius
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let frob_x = fp2_chip.frobenius_map(ctx, P.x(), 1);
        let frob_y = fp2_chip.frobenius_map(ctx, P.y(), 1);

        // calculate Lambda of P
        let lambdaPx_x = fp2_chip.scalar_mul_no_carry(ctx, P.x(), BN_X as i64);
        let lambdaPx_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPx_x, BN_X as i64);
        let lambdaPx_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPx_x_sq, 6);
        let lambdaPy_x = fp2_chip.scalar_mul_no_carry(ctx, P.y(), BN_X as i64);
        let lambdaPy_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPy_x, BN_X as i64);
        let lambdaPy_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPy_x_sq, 6);

        // let lambdaPy_x2 = fp2_chip.scalar_mul_no_carry(ctx, P.y(), 6);
        // let lambdaPy_x_sq2 = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPy_x, BN_X as i64);
        // let lambdaPy_6_x_sq2 = fp2_chip.scalar_mul_no_carry(ctx, &lambdaPy_x_sq, BN_X as i64);

        // check the two are equal
        // println!("frob_x: {frob_x:#?})");
        // println!("frob_y: {frob_y:#?})");
        // println!("lambdaPx_6_x_sq: {lambdaPx_6_x_sq:#?})");
        // println!("lambdaPy_6_x_sq: {lambdaPy_6_x_sq:#?})");
        // println!("lambdaPy_6_x_sq2: {lambdaPy_6_x_sq2:#?})");

        println!("BN_X as u64: {BN_X:#?}");
        // let BN_X_i64: i64 = BN_X as i64;
        // println!("BN_X_i64 as i64: {BN_X_i64:#?}");
        // assert_eq!(BN_X, BN_X_i64);
        let lambda_u128 = 6 * BN_X as u128 * BN_X as u128;
        // println!("lambda as u128: {lambda_u128:#?}");

        // println!("P.x(): {:#?}", P.x().coeffs[0].value);
        let actual = &P.x().coeffs[0].value * lambda_u128;
        // println!("actual Lambda X: {actual}");
        assert_eq!(actual, lambdaPx_6_x_sq.coeffs[0].value);
    }
}
