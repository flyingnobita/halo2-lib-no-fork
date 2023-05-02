#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::{Fp12Chip, FpChip, FqPoint};
use crate::ecc::EccChip;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::bn256::Fq12;
use halo2_base::Context;

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows
pub struct BlsSignatureChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip_1: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip: pairing_chip_1 }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1 where e(,) is optimal Ate pairing
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
        // Check Pubkey is valid

        // Check Signature is valid

        // Verify both pairing with multi_miller_loop()
        // e(g1, signature)*e(pubkey, -H(m)) === 1
        let g1_assigned = self.pairing_chip.load_private_g1(ctx, g1);
        let signature_assigned = self.pairing_chip.load_private_g2(ctx, signature);
        let pubkey_assigned = self.pairing_chip.load_private_g1(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip.load_private_g2(ctx, msghash);

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
}
