#![allow(clippy::too_many_arguments)]
#![allow(clippy::op_ref)]
#![allow(clippy::type_complexity)]
#![feature(int_log)]
#![feature(trait_alias)]
#![feature(core_intrinsics)]
#![allow(unused_imports)]
#![allow(unused_variables)]

// fn print_type_of<T>(_: &T) {
//     println!("{}", { std::intrinsics::type_name::<T>() });
// }

pub mod bigint;
pub mod ecc;
pub mod fields;

pub mod bn254;
pub mod secp256k1;

pub use halo2_base;
pub(crate) use halo2_base::halo2_proofs;

#[cfg(target_family = "wasm")]
pub mod wasm;
