#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip};
use crate::ecc::EccChip;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::bn256::Fq12;
use halo2_base::{AssignedValue, Context};

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows
pub struct BlsSignatureChipTest<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip_1: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChipTest<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip_1: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip_1 }
    }

    pub fn bls_signature_verify_test(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signature: G2Affine,
        pubkey: G1Affine,
        msghash: G2Affine,
    ) -> Vec<AssignedValue<F>> {
        // Check Pubkey is valid

        // Check Signature is valid

        // Verify both pairing with multi_miller_loop()
        // e(g1, signature)*e(pubkey, -H(m)) === 1
        let g1_assigned = self.pairing_chip_1.load_private_g1(ctx, g1);
        let signature_assigned = self.pairing_chip_1.load_private_g2(ctx, signature);
        let pubkey_assigned = self.pairing_chip_1.load_private_g1(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip_1.load_private_g2(ctx, msghash);

        let neg_signature_assigned = self.pairing_chip_1.load_private_g2(ctx, -signature);
        let neg_hash_m_assigned = self.pairing_chip_1.load_private_g2(ctx, -msghash);

        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let neg_signature_assigned_g2 = g2_chip.negate(ctx, &signature_assigned);
        let neg_hash_m_asssigned_g2 = g2_chip.negate(ctx, &hash_m_assigned);

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_assigned);
        let neg_hash_m_asssigned_g12 = g12_chip.negate(ctx, &hash_m_assigned);

        let multi_paired_1 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result_1 = fp12_chip.final_exp(ctx, &multi_paired_1);
        let multi_paired_2 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &neg_signature_assigned), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result_2 = fp12_chip.final_exp(ctx, &multi_paired_2);
        let multi_paired_3 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &neg_hash_m_assigned)],
        );
        let result_3 = fp12_chip.final_exp(ctx, &multi_paired_3);
        let multi_paired_4 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &neg_signature_assigned_g2), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result_4 = fp12_chip.final_exp(ctx, &multi_paired_4);
        let multi_paired_5 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &neg_signature_assigned_g12), (&pubkey_assigned, &hash_m_assigned)],
        );
        let result_5 = fp12_chip.final_exp(ctx, &multi_paired_5);
        let multi_paired_6 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &neg_hash_m_asssigned_g2)],
        );
        let result_6 = fp12_chip.final_exp(ctx, &multi_paired_6);
        let multi_paired_7 = self.pairing_chip_1.multi_miller_loop(
            ctx,
            vec![
                (&g1_assigned, &signature_assigned),
                (&pubkey_assigned, &neg_hash_m_asssigned_g12),
            ],
        );
        let result_7 = fp12_chip.final_exp(ctx, &multi_paired_7);

        let fp12_chip_2 = Fp12Chip::<F>::new(self.fp_chip);
        let one = fp12_chip_2.load_private(ctx, Fp12Chip::<F>::fe_to_witness(&Fq12::one()));
        // println!("--- bls_signature_verify_test().one: {one:#?}");

        vec![
            fp12_chip_2.is_equal(ctx, &result_1, &one),
            fp12_chip_2.is_equal(ctx, &result_2, &one), // 1
            fp12_chip_2.is_equal(ctx, &result_3, &one), // 1
            fp12_chip_2.is_equal(ctx, &result_4, &one), // 1
            fp12_chip_2.is_equal(ctx, &result_5, &one), // 1
            fp12_chip_2.is_equal(ctx, &result_6, &one), // 1
            fp12_chip_2.is_equal(ctx, &result_7, &one), // 1
        ]
    }
}

pub struct BlsSignatureChipSeparateTest<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip_1: &'chip PairingChip<'chip, F>,
    pub pairing_chip_2: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChipSeparateTest<'chip, F> {
    pub fn new(
        fp_chip: &'chip FpChip<F>,
        pairing_chip_1: &'chip PairingChip<F>,
        pairing_chip_2: &'chip PairingChip<F>,
    ) -> Self {
        Self { fp_chip, pairing_chip_1, pairing_chip_2 }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1 where e(,) is optimal Ate pairing
    // G1: {g1, pubkey}, G2: {signature, message}
    pub fn bls_signature_verify_separate_test(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signature: G2Affine,
        pubkey: G1Affine,
        msghash: G2Affine,
    ) -> halo2_base::AssignedValue<F> {
        // Check Pubkey is valid

        // Check Signature is valid

        // Setup Pairing 1: e(g1, signature); g1 in G1, signature in G2
        let g1_assigned = self.pairing_chip_1.load_private_g1(ctx, g1);
        let signature_assigned = self.pairing_chip_1.load_private_g2(ctx, signature);
        let paired_Point_1 = self.pairing_chip_1.pairing(ctx, &signature_assigned, &g1_assigned);

        // Setup Pairing 2: e(pubkey, -H(m)); pubkey in G1, message in G2
        let pubkey_assigned = self.pairing_chip_2.load_private_g1(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip_2.load_private_g2(ctx, -msghash);
        let paired_Point_2 = self.pairing_chip_2.pairing(ctx, &hash_m_assigned, &pubkey_assigned);

        // Verify e(g1, signature)*e(pubkey, -H(m)) === 1
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let pairs_multiplied = fp12_chip.mul_no_carry(ctx, &paired_Point_1, &paired_Point_2);

        let one = fp12_chip.load_private(ctx, Fp12Chip::<F>::fe_to_witness(&Fq12::one()));
        let pairs_multiplied_minus_one = fp12_chip.sub_no_carry(ctx, &pairs_multiplied, &one);
        fp12_chip.is_zero(ctx, &pairs_multiplied_minus_one);

        println!("bls_signature_verify_separate_test().pairs_multiplied {pairs_multiplied:#?}");
        fp12_chip.is_equal(ctx, &pairs_multiplied, &one)
    }
}
