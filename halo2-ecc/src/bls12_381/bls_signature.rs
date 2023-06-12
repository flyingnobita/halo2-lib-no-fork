#![allow(non_snake_case)]

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::ecc::{EcPoint, EccChip};
use crate::fields::vector::FieldVector;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::halo2curves::bls12_381::{
    Fq, G1Affine, G2Affine, BLS_X, FROBENIUS_COEFF_FQ12_C1,
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
        // let pow = power % 2;
        let mut out_fp2 = Vec::with_capacity(6);

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);
        // pow = 1
        // for i in 0..1 {
        //     let frob_coeff = FROBENIUS_COEFF_FQ2_C1[pow].pow_vartime([i as u64]);
        //     println!("frob_coeff: {frob_coeff:#?}");
        //     let mut a_fp2 =
        //         FieldExtPoint::construct(vec![a.coeffs[i].clone(), a.coeffs[i + 1].clone()]);
        //     println!("pow: {pow:#?}");
        //     if pow % 2 != 0 {
        //         a_fp2 = fp2_chip.conjugate(ctx, &a_fp2);
        //     }
        //     if frob_coeff == Fq::one() {
        //         println!("frob_coeff == Fq::one()");
        //         out_fp2.push(a_fp2);
        //     } else {
        //         let frob_fixed = fp_chip.load_constant(ctx, frob_coeff.);
        //         out_fp2.push(fp2_chip.mul(ctx, &a_fp2, &frob_fixed));
        //     }
        // }

        // println!("a: {a:#?}");
        // pow = 1
        // let frob_coeff = FROBENIUS_COEFF_FQ2_C1[pow]; // frob_coeff = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46

        // let frob_coeff = FROBENIUS_COEFF_FQ2_C1[pow].pow_vartime([0_u64]); // frob_coeff = 0x00...1
        // println!("frob_coeff: {frob_coeff:#?}");

        // let mut a_fp2 = FieldExtPoint::construct(vec![a.0[0].clone(), a.0[1].clone()]);
        let mut a_fp2 = FieldVector(vec![a[0].clone(), a[1].clone()]);
        a_fp2 = fp2_chip.conjugate(ctx, a_fp2);
        // println!("a_fp2: {a_fp2:#?}");
        // let frob_fixed = fp2_chip.load_constant(ctx, frob_coeff);
        // frob_coeff in Fq
        // out_fp2.push(fp2_chip.mul(ctx, &a_fp2, &frob_coeff));

        // out_fp2.push(fp2_chip.scalar_mul_no_carry(ctx, &a_fp2, frob_coeff));
        // let a = fp_chip.mul(ctx, &a_fp2, frob_coeff);
        // let b = fp_chip.scalar_mul_no_carry(ctx, &a_fp2, frob_coeff);
        out_fp2.push(a_fp2);

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
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bls12_381::G1Affine>(
            ctx,
            &g1_assigned,
        );
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bls12_381::G2Affine>(
            ctx,
            &signature_assigned,
        );
        // Checking pubkey is on curve also check that it's in subgroup G1 since G1 has cofactor of 1
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bls12_381::G1Affine>(
            ctx,
            &pubkey_assigned,
        );
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bls12_381::G2Affine>(
            ctx,
            &hash_m_assigned,
        );

        // Check Signature is in Subgroup G2
        self.assert_in_g2(ctx, &signature_assigned.clone());

        self.assert_in_g2(ctx, &hash_m_assigned.clone());

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

    /// Subgroup check for G2:
    /// use the latest method by El Housni, Guillevic, Piellard: https://eprint.iacr.org/2022/352.pdf
    /// By Proposition 3, enough to check psi(P) = [lambda]P for lambda = t - 1 = 6 * x^2
    pub fn assert_in_g2(&self, ctx: &mut Context<F>, P: &EcPoint<F, FqPoint<F>>) {
        // calculate Endomorphism Psi of P

        // coeff = get_Fp12_frobenius()
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let coeff = FROBENIUS_COEFF_FQ12_C1[1]; // [1][c0, c1][0 to 5]

        // frob = Fp2frobeniusMap()
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let frob_x = fp2_chip.frobenius_map(ctx, P.x());
        let frob_y = fp2_chip.frobenius_map(ctx, P.y());

        // psi = coeff * frob
        // let psi_x = fp2_chip.mul_no_carry(ctx, &coeff, &frob_x);
        // let psi_y = fp2_chip.mul_no_carry(ctx, &coeff, &frob_y);
        // print_type_of(&psi_x.0[0].0.value); // num_bigint::bigint::BigInt
        // println!("psi_x: {:#?}", psi_x.0[0].0.value);
        // let psi_x;
        // for i in 0..1 {
        //     fp2_chip.scalar_mul_no_carry(ctx, &frob_x, coeff);
        // }

        // calculate Lambda of P
        let lambda_Px_x = fp2_chip.scalar_mul_no_carry(ctx, P.x(), BLS_X as i64);
        let lambda_Px_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Px_x, BLS_X as i64);
        let lambda_Px_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Px_x_sq, 6);
        let lambda_Py_x = fp2_chip.scalar_mul_no_carry(ctx, P.y(), BLS_X as i64);
        let lambda_Py_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Py_x, BLS_X as i64);
        let lambda_Py_6_x_sq = fp2_chip.scalar_mul_no_carry(ctx, &lambda_Py_x_sq, 6);

        // check the two are equal
        // println!("frob_x: {frob_x:#?})");
        // println!("frob_y: {frob_y:#?})");
        // println!("lambda_Px_6_x_sq: {:#?}", lambda_Px_6_x_sq.0[0].value);
        // println!("lambda_Py_6_x_sq: {:#?}", lambda_Py_6_x_sq.0[0].value);

        // println!("BLS_X as u64: {BLS_X:#?}");
        // let BLS_X_i64: i64 = BLS_X as i64;
        // println!("BLS_X_i64 as i64: {BLS_X_i64:#?}");
        // assert_eq!(BLS_X, BLS_X_i64);
        let lambda_u128 = 6 * u128::from(BLS_X) * u128::from(BLS_X);
        // println!("lambda as u128: {lambda_u128:#?}");

        // println!("P.x(): {:#?}", P.x().coeffs[0].value);
        let actual_lambda_Px = P.x.0[0].value() * lambda_u128;
        println!("actual Lambda X: {actual_lambda_Px}");

        print_type_of(&actual_lambda_Px); // num_bigint::biguint::BigUint
        print_type_of(&lambda_Px_6_x_sq.0[0].value); // num_bigint::bigint::BigInt

        // To compare num_bigint::biguint::BigUint with num_bigint::bigint::BigInt?
        // assert_eq!(actual, lambdaPx_6_x_sq.0[0].value);

        // assert_eq!(psi_x.0[0].0.value, lambda_Px_6_x_sq.0[0].value);
        // assert_eq!(psi_y.0[0].0.value, lambda_Py_6_x_sq.0[0].value);
    }
}
