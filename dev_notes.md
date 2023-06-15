# Developer Notes

## Problem: Environment variables are not supported on browser

Following are not allowed

1. `halo2-base::gates::builder::GateThreadBuilder::config()`:
   `set_var("FLEX_GATE_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());`

2. `halo2-base::gates::builder::GateThreadBuilder::config()`:
   `serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();`

3. `halo2-base::gates::builder`:

```
impl<F: ScalarField> Circuit<F> for RangeCircuitBuilder<F> {

  fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {

    serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();

  }
}
```

### Cause

Web browser doesn't have environment variables. Need another way to store and retrieve `FLEX_GATE_CONFIG_PARAMS`

### Solution

#### Attempt 1: Use file storage with `localstoragefs`

Use [localstoragefs](https://github.com/iceiix/localstoragefs/tree/master)

Getting following error when executing:

```bash
wasm-pack build --target web --out-dir ../react_app/public/pkg
```

Error:

```bash
error[E0433]: failed to resolve: unresolved import
  --> /Users/jansonmak/.cargo/registry/src/github.com-1ecc6299db9ec823/stdweb-0.4.20/src/webcore/ffi/wasm_bindgen.rs:67:32
   |
67 |             alloc: &Closure< Fn( usize ) -> *mut u8 >,
   |                                ^ unresolved import

error[E0425]: cannot find function `wasm_bindgen_initialize` in this scope
  --> /Users/jansonmak/.cargo/registry/src/github.com-1ecc6299db9ec823/stdweb-0.4.20/src/webcore/ffi/wasm_bindgen.rs:77:22
   |
77 |         let module = wasm_bindgen_initialize( memory, table, &alloc, &free );
   |                      ^^^^^^^^^^^^^^^^^^^^^^^ not found in this scope
```

#### Attempt 2: Use WebAssembly System Interface(WASI) which support files

wasm-pack currently [does not support](https://github.com/rustwasm/wasm-pack/issues/654) WASI

#### Attempt 3: Hardcode FLEX_GATE_CONFIG_PARAMS (current solution)

`FlexGateConfigParams` has been hardcoded to be the following

```rust
 FlexGateConfigParams {
            strategy: GateStrategy::Vertical,
            k: 19,
            num_advice_per_phase: vec![9, 0, 0],
            num_lookup_advice_per_phase: vec![1, 0, 0],
            num_fixed: 1,
        }
```

## Problem: Runtime Error in browser

`yarn dev` gives following error in browser console:

```bash
halo2ecc.js:356 panicked at 'internal error: entered unreachable code', /Users/jansonmak/Data/Project/zk/axiom-crypto/flyingnobita-halo2/halo2_proofs/src/dev/failure.rs:560:30

Stack:

Error
    at imports.wbg.__wbg_new_abda76e883ba8a5f (http://localhost:3000/static/js/public_pkg_halo2ecc_js.chunk.js:429:17)
    at http://localhost:3000/static/media/halo2ecc_bg.3f008c2f754296db0049.wasm:wasm-function[769]:0x9a752
    at http://localhost:3000/static/media/halo2ecc_bg.3f008c2f754296db0049.wasm:wasm-function[373]:0x84cac
    at http://localhost:3000/static/media/halo2ecc_bg.3f008c2f754296db0049.wasm:wasm-function[596]:0x95798
    at http://localhost:3000/static/media/halo2ecc_bg.3f008c2f754296db0049.wasm:wasm-function[579]:0x91423
    at http://localhost:3000/static/media/halo2ecc_bg.3f008c2f754296db0049.wasm:wasm-function[770]:0xc4177
    at Module.bls_signature_wasm (http://localhost:3000/static/js/public_pkg_halo2ecc_js.chunk.js:95:20)
    at Object.bls_signature_wasm (http://localhost:3000/static/js/halo-worker.chunk.js:28:27)
```
