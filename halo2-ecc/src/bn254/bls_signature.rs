#![allow(non_snake_case)]

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::bn254::pairing::{neg_twisted_frobenius, twisted_frobenius};
use crate::ecc::{EcPoint, EccChip};
use crate::fields::vector::FieldVector;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::halo2curves::bn256::{
    Fq, Fq2, G1Affine, G2Affine, BN_X, FROBENIUS_COEFF_FQ12_C1, FROBENIUS_COEFF_FQ2_C1,
};
use crate::print_type_of;
use halo2_base::utils::modulus;
use halo2_base::Context;
use num_bigint::BigUint;

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows

impl<'chip, F: PrimeField> Fp2Chip<'chip, F> {
    pub fn frobenius_map(
        &self,
        ctx: &mut Context<F>,
        a: &<Self as FieldChip<F>>::FieldPoint,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        assert_eq!(modulus::<Fq>() % 4u64, BigUint::from(3u64));
        assert_eq!(modulus::<Fq>() % 6u64, BigUint::from(1u64));
        assert_eq!(a.0.len(), 2);
        // println!("a: {a:#?}");

        let mut out_fp2 = Vec::with_capacity(1);

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);

        let frob_coeff = FROBENIUS_COEFF_FQ2_C1[1].pow_vartime([1_u64]);
        let mut a_fp2 = FieldVector(vec![a[0].clone(), a[1].clone()]);
        a_fp2 = fp2_chip.conjugate(ctx, a_fp2);
        out_fp2.push(a_fp2);

        // if frob_coeff == Fq::one() {
        //     out_fp2.push(a_fp2);
        // } else if frob_coeff == Fq::zero() {
        //     let frob_fixed = fp_chip.load_constant(ctx, frob_coeff);
        //     {
        //         let out_nocarry = fp2_chip.0.fp_mul_no_carry(ctx, a_fp2, frob_fixed);
        //         out_fp2.push(fp2_chip.carry_mod(ctx, out_nocarry));
        //     }
        // } else {
        //     let frob_fixed = fp_chip.load_constant(ctx, frob_coeff);
        //     out_fp2.push(fp_chip.mul(ctx, a_fp2, frob_fixed));
        // }

        let out_coeffs = out_fp2
            .iter()
            .map(|x| x.0[0].clone())
            .chain(out_fp2.iter().map(|x| x.0[1].clone()))
            .collect();

        FieldVector(out_coeffs)
    }
}

pub struct BlsSignatureChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip_1: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip: pairing_chip_1 }
    }

    // FIXME assert_in_g2() not working yet. Problem in Fp2Chip::frobenius_map()?
    /// Subgroup check for G2:
    /// use the latest method by El Housni, Guillevic, Piellard: https://eprint.iacr.org/2022/352.pdf
    /// By Proposition 3, enough to check psi(P) = [lambda]P for lambda = t - 1 = 6 * x^2
    pub fn assert_in_g2(
        &self,
        ecc_chip: &EccChip<F, Fp2Chip<F>>,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FqPoint<F>>,
    ) {
        // calculate Endomorphism Psi of P

        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);

        // Get the coefficients
        let coeff_over_6 = FROBENIUS_COEFF_FQ12_C1[1]; // [1][c0, c1][0 to 3]
        let coeff_over_3 = coeff_over_6 * coeff_over_6;
        let coeff_over_2 = coeff_over_3 * coeff_over_6;
        let coeff_over_6 = ecc_chip.field_chip.load_constant(ctx, coeff_over_6);
        let coeff_over_3 = ecc_chip.field_chip.load_constant(ctx, coeff_over_3);
        let coeff_over_2 = ecc_chip.field_chip.load_constant(ctx, coeff_over_2);

        // calculate frobenius of P (raise P(x, y) to the power of 1)
        let frob_x = fp2_chip.frobenius_map(ctx, P.x());
        let frob_y = fp2_chip.frobenius_map(ctx, P.y());
        // println!("frob_x: {frob_x:#?})");
        // println!("frob_y: {frob_y:#?})");

        // psi = coefficients * frobenius
        let psi_x = fp2_chip.mul_no_carry(ctx, coeff_over_3, &frob_x);
        let psi_y = fp2_chip.mul_no_carry(ctx, coeff_over_2, &frob_y);
        // print_type_of(&psi_x);
        // println!("psi_x: {:#?}", psi_x);

        // calculate lambda of P
        let lambda_Px_x = fp2_chip.scalar_mul_no_carry(ctx, P.x(), BN_X as i64);
        let lambda_Px_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Px_x, BN_X as i64);
        let lambda_Px_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Px_x_sq, 6);
        let lambda_Py_x = fp2_chip.scalar_mul_no_carry(ctx, P.y(), BN_X as i64);
        let lambda_Py_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Py_x, BN_X as i64);
        let lambda_Py_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Py_x_sq, 6);
        // println!("lambda_Px_6_x_sq: {:#?}", lambda_Px_6_x_sq);

        // calculate actual lambda of P (for checking during dev)
        let lambda_u128 = 6 * BN_X as u128 * BN_X as u128;
        let actual_lambda_Px = P.x.0[0].value() * lambda_u128;
        // println!("lambda_Px_6_x_sq.0[0].value: {:#?}", lambda_Px_6_x_sq.0[0].value);
        // println!("actual Lambda X: {actual_lambda_Px}");
        // not sure how to compare num_bigint::biguint::BigUint with num_bigint::bigint::BigInt?
        // assert_eq!(actual, lambdaPx_6_x_sq.0[0].value);

        // check the two are equal
        // assert_eq!(psi_x.0[0].value, lambda_Px_6_x_sq.0[0].value);
        // assert_eq!(psi_y.0[0].value, lambda_Py_6_x_sq.0[0].value);
        // println!("psi_x.0[0].value: {}", psi_x.0[0].value);
        // println!("lambda_Px_6_x_sq.0[0].value: {}", lambda_Px_6_x_sq.0[0].value);
        // println!("psi_y.0[0].value: {}", psi_y.0[0].value);
        // println!("lambda_Py_6_x_sq.0[0].value: {}", lambda_Py_6_x_sq.0[0].value);
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

        let g1_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, g1);
        let signature_assigned = self.pairing_chip.load_private_g2_unchecked(ctx, signature);
        let pubkey_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip.load_private_g2_unchecked(ctx, msghash);

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
        // Checking pubkey is on curve also check that it's in subgroup G1 since G1 has cofactor of 1
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>(
            ctx,
            &pubkey_assigned,
        );
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G2Affine>(
            ctx,
            &hash_m_assigned,
        );

        // Check Signature is in Subgroup G2
        self.assert_in_g2(&g2_chip, ctx, &signature_assigned.clone());

        self.assert_in_g2(&g2_chip, ctx, &hash_m_assigned.clone());

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_assigned);

        let multi_paired = self.pairing_chip.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &neg_signature_assigned_g12), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result = fp12_chip.final_exp(ctx, multi_paired);
        result
    }
}
