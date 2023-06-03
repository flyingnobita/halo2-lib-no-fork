use super::{Fp2Chip, FpChip, FpPoint};
use crate::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bls12_381::{Fq, Fq2, BLS_X, FROBENIUS_COEFF_FQ2_C1},
};
use crate::{
    ecc::get_naf,
    fields::{FieldChip, FieldExtPoint, PrimeField},
};
use halo2_base::{
    gates::GateInstructions,
    utils::{fe_to_biguint, modulus},
    Context,
    QuantumCell::Constant,
};
use num_bigint::BigUint;

const XI_0: i64 = 9;

impl<'chip, F: PrimeField> Fp2Chip<'chip, F> {
    pub fn frobenius_map(
        &self,
        ctx: &mut Context<F>,
        a: &<Self as FieldChip<F>>::FieldPoint,
        power: usize,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        assert_eq!(modulus::<Fq>() % 4u64, BigUint::from(3u64));
        assert_eq!(modulus::<Fq>() % 6u64, BigUint::from(1u64));
        assert_eq!(a.coeffs.len(), 2);
        let pow = power % 2;
        let mut out_fp2 = Vec::with_capacity(6);

        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let fp_chip = self.fp_chip;
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

        println!("a: {a:#?}");
        // pow = 1
        let frob_coeff = FROBENIUS_COEFF_FQ2_C1[pow]; // frob_coeff = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46

        // let frob_coeff = FROBENIUS_COEFF_FQ2_C1[pow].pow_vartime([0_u64]); // frob_coeff = 0x00...1
        println!("frob_coeff: {frob_coeff:#?}");

        let mut a_fp2 = FieldExtPoint::construct(vec![a.coeffs[0].clone(), a.coeffs[1].clone()]);
        a_fp2 = fp2_chip.conjugate(ctx, &a_fp2);
        println!("a_fp2: {a_fp2:#?}");
        // let frob_fixed = fp2_chip.load_constant(ctx, frob_coeff);
        // frob_coeff in Fq
        // out_fp2.push(fp2_chip.mul(ctx, &a_fp2, &frob_coeff));

        // out_fp2.push(fp2_chip.scalar_mul_no_carry(ctx, &a_fp2, frob_coeff));
        // let a = fp_chip.mul(ctx, &a_fp2, frob_coeff);
        // let b = fp_chip.scalar_mul_no_carry(ctx, &a_fp2, frob_coeff);
        out_fp2.push(a_fp2);

        let out_coeffs = out_fp2
            .iter()
            .map(|x| x.coeffs[0].clone())
            .chain(out_fp2.iter().map(|x| x.coeffs[1].clone()))
            .collect();

        FieldExtPoint::construct(out_coeffs)
    }
}
