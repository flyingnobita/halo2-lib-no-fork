use super::*;
use crate::{
    fields::{FieldChip, FpStrategy},
    halo2_proofs::halo2curves::bn256::G2Affine,
};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::halo2curves::{
        bn256::{multi_miller_loop, G2Prepared},
        pairing::MillerLoopResult,
    },
    Context,
};
use rand_core::OsRng;
use std::fs::File;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct BlsSignatureCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

/// Verify e(g1, signature) = e(pubkey, H(m))
fn bls_signature_test_2<F: PrimeField>(
    ctx: &mut Context<F>,
    params: BlsSignatureCircuitParams,
    g1: G1Affine,
    signature: G2Affine,
    pubkey: G1Affine,
    msghash: G2Affine,
) {
    // Calculate halo2 pairing by Multipairing
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip_1 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip_1);

    // Verify both pairing with multi_miller_loop()
    // e(g1, signature)*e(pubkey, -H(m)) === 1
    let g1_assigned = pairing_chip.load_private_g1(ctx, g1);
    let signature_assigned = pairing_chip.load_private_g2(ctx, signature);
    let pubkey_assigned = pairing_chip.load_private_g1(ctx, pubkey);
    let hash_m_assigned = pairing_chip.load_private_g2(ctx, msghash);

    let neg_signature_assigned = pairing_chip.load_private_g2(ctx, -signature);
    let neg_hash_m_assigned = pairing_chip.load_private_g2(ctx, -msghash);

    let fp2_chip = Fp2Chip::<F>::new(&fp_chip_1);
    let g2_chip = EccChip::new(&fp2_chip);
    let neg_signature_assigned_g2 = g2_chip.negate(ctx, &signature_assigned);
    let neg_hash_m_asssigned_g2 = g2_chip.negate(ctx, &hash_m_assigned);

    let fp12_chip = Fp12Chip::<F>::new(&fp_chip_1);
    let g12_chip = EccChip::new(&fp12_chip);
    let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_assigned);
    let neg_hash_m_asssigned_g12 = g12_chip.negate(ctx, &hash_m_assigned);

    let fp12_chip_2 = Fp12Chip::<F>::new(&fp_chip_1);
    let result_1 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &hash_m_assigned)],
    );
    let result_1b = fp12_chip.final_exp(ctx, &result_1);
    let result_2 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &neg_signature_assigned), (&pubkey_assigned, &hash_m_assigned)],
    );
    let result_2b = fp12_chip.final_exp(ctx, &result_2);
    let result_3 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &neg_hash_m_assigned)],
    );
    let result_3b = fp12_chip.final_exp(ctx, &result_3);
    let result_4 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &neg_hash_m_asssigned_g2)],
    );
    let result_4b = fp12_chip.final_exp(ctx, &result_4);
    let result_5 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &signature_assigned), (&pubkey_assigned, &neg_hash_m_asssigned_g12)],
    );
    let result_5b = fp12_chip.final_exp(ctx, &result_5);
    let result_6 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &neg_signature_assigned_g2), (&pubkey_assigned, &hash_m_assigned)],
    );
    let result_6b = fp12_chip.final_exp(ctx, &result_6);
    let result_7 = pairing_chip.multi_miller_loop(
        ctx,
        vec![(&g1_assigned, &neg_signature_assigned_g12), (&pubkey_assigned, &hash_m_assigned)],
    );
    let result_7b = fp12_chip.final_exp(ctx, &result_7);

    // println!("--- bls_signature_test_2().result: {result:#?}");
    // assert_eq!(result.value(), &F::one());
    // result.iter().for_each(|&x| println!("--- bls_signature_test().result: {x:#?}"));

    let fp12_chip = Fp12Chip::new(&fp_chip_1);
    println!(
        "--- bls_signature_test_2().result_1b: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_1b)
    );
    println!(
        "--- bls_signature_test_2().result_2b: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_2b)
    );
    println!(
        "--- bls_signature_test_2().result_3b: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_3b)
    );
    println!(
        "--- bls_signature_test_2().result_4: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_4b)
    );
    println!(
        "--- bls_signature_test_2().result_5: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_5b)
    );
    println!(
        "--- bls_signature_test_2().result_6: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_6b)
    );
    println!(
        "--- bls_signature_test_2().result_7: Gt({:#?})",
        fp12_chip.get_assigned_value(&result_7b)
    );

    // Calculate non-halo2 pairing by Multipairing
    let signature_g2_prepared = G2Prepared::from(signature);
    let hash_m_prepared = G2Prepared::from(-msghash);
    let actual_result =
        multi_miller_loop(&[(&g1, &signature_g2_prepared), (&pubkey, &hash_m_prepared)])
            .final_exponentiation();
    let one = halo2_base::halo2_proofs::halo2curves::bn256::Gt::identity();
    println!("--- bls_signature_test_2().actual_result: {actual_result:#?}");
    assert_eq!(one, actual_result);
    println!("--- bls_signature_test_2().one == actual_result !!!");

    // Compare halo2 with non-halo2
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_1)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_2)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_3)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_4)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_5)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_6)),
    //     format!("{actual_result:?}")
    // );
    // assert_eq!(
    //     format!("Gt({:?})", fp12_chip.get_assigned_value(&result_7)),
    //     format!("{actual_result:?}")
    // );
}

fn bls_signature_test_3<F: PrimeField>(
    ctx: &mut Context<F>,
    params: BlsSignatureCircuitParams,
    g1: G1Affine,
    signature: G2Affine,
    pubkey: G1Affine,
    msghash: G2Affine,
) {
    // Calculate halo2 pairing by Multipairing
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);

    let fp_chip_1 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fp_chip_2 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip_1);
    let bls_signature_chip = BlsSignatureChipTest::new(&fp_chip_2, &pairing_chip);
    let result = bls_signature_chip.bls_signature_verify_test(ctx, g1, signature, pubkey, msghash);

    result.iter().for_each(|x| println!("--- bls_signature_test_3(): {x:#?}"));

    // Calculate non-halo2 pairing by Multipairing
    let signature_g2_prepared = G2Prepared::from(signature);
    let hash_m_prepared = G2Prepared::from(-msghash);
    let actual_result =
        multi_miller_loop(&[(&g1, &signature_g2_prepared), (&pubkey, &hash_m_prepared)])
            .final_exponentiation();
    let one = halo2_base::halo2_proofs::halo2curves::bn256::Gt::identity();
    assert_eq!(one, actual_result);

    // let fp12_chip = Fp12Chip::new(&fp_chip_1);
    // println!("--- bls_signature_test().result: Gt({:#?})", fp12_chip.get_assigned_value(&result));
    // println!("actual_result: {actual_result:#?}");
    // assert_eq!(
    // format!("Gt({:?})", fp12_chip.get_assigned_value(&result)),
    // format!("{actual_result:?}")
    // );
}

/// Verify e(g1, signature) = e(pubkey, H(m))
fn bls_signature_separate_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: BlsSignatureCircuitParams,
    g1: G1Affine,
    signature: G2Affine,
    pubkey: G1Affine,
    msghash: G2Affine,
) {
    // Calculate halo2 pairing

    // By 2 separate pairing
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);

    let fp_chip_1 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fp_chip_2 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fp_chip_3 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let pairing_chip_1 = PairingChip::new(&fp_chip_1);
    let pairing_chip_2 = PairingChip::new(&fp_chip_2);
    let bls_signature_chip =
        BlsSignatureChipSeparateTest::new(&fp_chip_3, &pairing_chip_1, &pairing_chip_2);
    let result =
        bls_signature_chip.bls_signature_verify_separate_test(ctx, g1, signature, pubkey, msghash);
    println!("--- bls_signature_separate_test().result: {result:#?}");
    // assert_eq!(&F::one(), &F::one());

    // Calculate non-halo2 pairing

    // By 2 separate pairings
    let pairing_1 = pairing(&g1, &signature);
    let pairing_2 = pairing(&pubkey, &msghash);
    assert_eq!(format!("{pairing_1:?}"), format!("{pairing_2:?}"));
}

fn random_bls_signature_circuit_2(
    params: BlsSignatureCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let sk = Fr::random(OsRng);
    let pubkey = G1Affine::from(G1Affine::generator() * sk);
    // let Hash_m = G2Affine::random(OsRng);
    let msg_hash = G2Affine::generator();
    let signature = G2Affine::from(msg_hash * sk);
    let g1 = G1Affine::generator();

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    bls_signature_test_2::<Fr>(builder.main(0), params, g1, signature, pubkey, msg_hash);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

fn random_bls_signature_circuit_3(
    params: BlsSignatureCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let sk = Fr::random(OsRng);
    let pubkey = G1Affine::from(G1Affine::generator() * sk);
    // let Hash_m = G2Affine::random(OsRng);
    let msg_hash = G2Affine::generator();
    let signature = G2Affine::from(msg_hash * sk);
    let g1 = G1Affine::generator();

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    bls_signature_test_3::<Fr>(builder.main(0), params, g1, signature, pubkey, msg_hash);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

fn random_bls_signature_circuit_separate(
    params: BlsSignatureCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let sk = Fr::random(OsRng);
    let pubkey = G1Affine::from(G1Affine::generator() * sk);
    // let Hash_m = G2Affine::random(OsRng);
    let msg_hash = G2Affine::generator();
    let signature = G2Affine::from(msg_hash * sk);
    let g1 = G1Affine::generator();

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    bls_signature_separate_test::<Fr>(builder.main(0), params, g1, signature, pubkey, msg_hash);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

#[test]
fn test_2_bls_signature_test_2() {
    let path = "configs/bn254/bls_signature_circuit.config";
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!(
        "test_bls_signature_test_2().num_advice: {num_advice}",
        num_advice = params.num_advice
    );

    let circuit = random_bls_signature_circuit_2(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_2_bls_signature_test_3() {
    let path = "configs/bn254/bls_signature_circuit.config";
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!(
        "test_bls_signature_test_3().num_advice: {num_advice}",
        num_advice = params.num_advice
    );

    let circuit = random_bls_signature_circuit_3(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_2_bls_signature_separate_test() {
    let path = "configs/bn254/bls_signature_circuit.config";
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!(
        "test_bls_signature_separate_test().num_advice: {num_advice}",
        num_advice = params.num_advice
    );

    let circuit = random_bls_signature_circuit_separate(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
