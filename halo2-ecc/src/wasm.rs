#![allow(non_snake_case)]

use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

use super::bn254::bls_signature::BlsSignatureChip;
use super::bn254::pairing::PairingChip;
use super::bn254::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{pairing, Bn256, Fr, G1Affine},
    plonk::*,
    poly::commitment::ParamsProver,
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use crate::{ecc::EccChip, fields::PrimeField};
use group::Curve;
use halo2_base::utils::fe_to_biguint;
use serde::{Deserialize, Serialize};
use std::io::Write;

extern crate console_error_panic_hook;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

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
    halo2_proofs::{
        halo2curves::{
            bn256::{multi_miller_loop, G2Prepared},
            pairing::MillerLoopResult,
        },
        poly::kzg::multiopen::{ProverGWC, VerifierGWC},
    },
    utils::fs::gen_srs,
    Context,
};
use rand_core::OsRng;
use rayon::vec;

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
    num_aggregation: u32,
}

/// Verify e(g1, signature_agg) = e(pubkey_agg, H(m))
fn bls_signature_test_wasm<F: PrimeField>(
    ctx: &mut Context<F>,
    params: BlsSignatureCircuitParams,
    g1: G1Affine,
    signatures: &[G2Affine],
    pubkeys: &[G1Affine],
    msghash: G2Affine,
) {
    // Calculate halo2 pairing by multipairing
    // std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip_1 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fp_chip_2 = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip_1);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip_2, &pairing_chip);
    let result = bls_signature_chip.bls_signature_verify(ctx, g1, signatures, pubkeys, msghash);

    // Calculate non-halo2 pairing by multipairing
    let signature_g2_prepared = G2Prepared::from(signatures.iter().sum::<G2Affine>());
    let pubkey_aggregated = pubkeys.iter().sum::<G1Affine>();
    let hash_m_prepared = G2Prepared::from(-msghash);
    let actual_result =
        multi_miller_loop(&[(&g1, &signature_g2_prepared), (&pubkey_aggregated, &hash_m_prepared)])
            .final_exponentiation();

    // Compare the 2 results
    let fp12_chip = Fp12Chip::new(&fp_chip_1);
    assert_eq!(
        format!("Gt({:?})", fp12_chip.get_assigned_value(&result.into())),
        format!("{actual_result:?}")
    );
}

fn random_bls_signature_circuit(
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

    assert!(params.num_aggregation > 0);

    // TODO: Implement hash_to_curve(msg) for arbitrary message
    let msg_hash = G2Affine::random(OsRng);
    let g1 = G1Affine::generator();

    let mut sks: Vec<Fr> = Vec::new();
    let mut signatures: Vec<G2Affine> = Vec::new();
    let mut pubkeys: Vec<G1Affine> = Vec::new();

    for _ in 0..params.num_aggregation {
        let sk = Fr::random(OsRng);
        let signature = G2Affine::from(msg_hash * sk);
        let pubkey = G1Affine::from(G1Affine::generator() * sk);

        sks.push(sk);
        signatures.push(signature);
        pubkeys.push(pubkey);
    }

    // let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    bls_signature_test_wasm::<Fr>(builder.main(0), params, g1, &signatures, &pubkeys, msg_hash);

    match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    }
    // end_timer!(start0);
}

#[wasm_bindgen]
pub fn bls_signature_wasm() -> JsValue {
    // let run_path = "configs/bn254/bls_signature_circuit.config";
    // let debug_path = "halo2-ecc/configs/bn254/bls_signature_circuit.config";
    // let path = run_path;
    // // let path = debug_path;
    // // println!("{:#?}", std::env::current_dir());
    // let params: BlsSignatureCircuitParams = serde_json::from_reader(
    //     File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    // )
    // .unwrap();

    let config = r#"{"strategy":"Simple","degree":19,"num_advice":6,"num_lookup_advice":1,"num_fixed":1,"lookup_bits":18,"limb_bits":90,"num_limbs":3,"num_aggregation":30}"#;
    let params: BlsSignatureCircuitParams = serde_json::from_str(config).unwrap();

    println!("num_advice: {num_advice}", num_advice = params.num_advice);
    let circuit = random_bls_signature_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();

    JsValue::from_serde(&1).unwrap()
}
