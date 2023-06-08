#![allow(non_snake_case)]

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::ecc::EccChip;
use crate::fields::vector::FieldVector;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::halo2curves::bn256::{
    Fq, Fq2, G1Affine, G2Affine, FROBENIUS_COEFF_FQ2_C1,
};
use halo2_base::utils::modulus;
use halo2_base::Context;
use num_bigint::BigUint;

impl<'chip, F: PrimeField> Fp2Chip<'chip, F> {
    // computes a ** (p ** power)
    // only works for p = 3 (mod 4) and p = 1 (mod 6)
    pub fn frobenius_map(
        &self,
        ctx: &mut Context<F>,
        a: &<Self as FieldChip<F>>::FieldPoint,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        assert_eq!(modulus::<Fq>() % 4u64, BigUint::from(3u64));
        assert_eq!(modulus::<Fq>() % 6u64, BigUint::from(1u64));
        assert_eq!(a.0.len(), 2);
        let mut out_fp2 = Vec::with_capacity(1);

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);

        let frob_coeff =
            Fq2::new(FROBENIUS_COEFF_FQ2_C1[0], FROBENIUS_COEFF_FQ2_C1[1]).pow_vartime([1_u64]);
        let mut a_fp2 = FieldVector(vec![a[0].clone(), a[1].clone()]);
        a_fp2 = fp2_chip.conjugate(ctx, a_fp2);
        // out_fp2.push(a_fp2);

        // if `frob_coeff` is in `Fp` and not just `Fp2`, then we can be more efficient in multiplication
        if frob_coeff == Fq2::one() {
            out_fp2.push(a_fp2);
        } else if frob_coeff == Fq2::zero() {
            let frob_fixed = fp_chip.load_constant(ctx, frob_coeff.c0);
            {
                let out_nocarry = fp2_chip.0.fp_mul_no_carry(ctx, a_fp2, frob_fixed);
                out_fp2.push(fp2_chip.carry_mod(ctx, out_nocarry));
            }
        } else {
            let frob_fixed = fp2_chip.load_constant(ctx, frob_coeff);
            out_fp2.push(fp2_chip.mul(ctx, a_fp2, frob_fixed));
        }

        let out_coeffs = out_fp2
            .iter()
            .map(|x| x.0[0].clone())
            .chain(out_fp2.iter().map(|x| x.0[1].clone()))
            .collect();

        FieldVector(out_coeffs)
    }
}

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows
pub struct BlsSignatureChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1
    // where e(,) is optimal Ate pairing
    // G1: {g1, pubkey}, G2: {signature, message}
    // TODO add support for aggregating signatures over different messages
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine],
        msghash: G2Affine,
    ) -> FqPoint<F> {
        assert!(
            signatures.len() == pubkeys.len(),
            "signatures and pubkeys must be the same length"
        );
        assert!(!signatures.is_empty(), "signatures must not be empty");
        assert!(!pubkeys.is_empty(), "pubkeys must not be empty");

        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let g1_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, g1);
        // Checking element from G1 is on curve also check that it's in subgroup G1 since G1 has cofactor of 1
        g1_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>(
            ctx,
            &g1_assigned,
        );

        let hash_m_assigned = self.pairing_chip.load_private_g2_unchecked(ctx, msghash);
        g2_chip.assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G2Affine>(
            ctx,
            &hash_m_assigned,
        );

        let mut signature_agg_assigned =
            self.pairing_chip.load_private_g2_unchecked(ctx, signatures[0]);
        g2_chip.field_chip.enforce_less_than(ctx, signature_agg_assigned.x().clone());
        let mut pubkey_agg_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, pubkeys[0]);
        g1_chip.field_chip.enforce_less_than(ctx, pubkey_agg_assigned.x().clone());

        // loop through signatures and aggregate them
        for (index, signature) in signatures.iter().enumerate() {
            if index > 0 {
                let signature_assigned =
                    self.pairing_chip.load_private_g2_unchecked(ctx, *signature);
                g2_chip.field_chip.enforce_less_than(ctx, signature_assigned.x().clone());
                g2_chip
                    .assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G2Affine>(
                        ctx,
                        &signature_assigned,
                    );
                signature_agg_assigned =
                    g2_chip.add_unequal(ctx, &signature_agg_assigned, &signature_assigned, false);
            }
        }

        // loop through pubkeys and aggregate them
        for (index, pubkey) in pubkeys.iter().enumerate() {
            if index > 0 {
                let pubkey_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, *pubkey);
                g1_chip.field_chip.enforce_less_than(ctx, pubkey_assigned.x().clone());
                g1_chip
                    .assert_is_on_curve::<halo2_base::halo2_proofs::halo2curves::bn256::G1Affine>(
                        ctx,
                        &pubkey_assigned,
                    );
                pubkey_agg_assigned =
                    g1_chip.add_unequal(ctx, &pubkey_agg_assigned, &pubkey_assigned, false);
            }
        }

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_agg_assigned);

        let multi_paired = self.pairing_chip.multi_miller_loop(
            ctx,
            vec![
                (&g1_assigned, &neg_signature_assigned_g12),
                (&pubkey_agg_assigned, &hash_m_assigned),
            ],
        );
        let result = fp12_chip.final_exp(ctx, multi_paired);
        result
    }
}
