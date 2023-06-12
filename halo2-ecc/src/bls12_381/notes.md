# Problems

## BN254 - `assert_in_g2()` not working

- problem might lie in Fp2Chip::frobenius_map()

## BLS12_381 - `n` and `k`

n = 90
k = 5

### 1. max_bits > n \* (k - 1) && max_bits <= n \* k

[halo2-ecc/src/fields/fp.rs::range_check()](https://github.com/axiom-crypto/halo2-lib/blob/68e1a81b7fbe5f2b942f8b7b9a0e90a4087a967a/halo2-ecc/src/fields/fp.rs#LL311C4-L311C4)
halo2-ecc/src/fields/fp.rs::range_check() {
debug_assert!(max_bits > n \* (k - 1) && max_bits <= n \* k);
}

max_bits = 381

n \* (k - 1) < max_bits <= n \* k
420 < max_bits <= 525

### 2. limb_bits (n) and the limb length (k)

Issue with the limb_bits (n) and the limb length (k) that I was wondering if you can help me with.

There are 2 assert statements that seems to go against one another:

[halo2-ecc/src/bigint/carry_mod.rs](https://github.com/axiom-crypto/halo2-lib/blob/68e1a81b7fbe5f2b942f8b7b9a0e90a4087a967a/halo2-ecc/src/bigint/carry_mod.rs#LL47C6-L47C6)

```rust
halo2-ecc/src/bigint/carry_mod.rs::crt() {
debug_assert!(a.value.bits() as usize <= n \* k - 1 + (F::NUM_BITS as usize) - 2);
}
```

[halo2-ecc/src/bigint/check_carry_mod_to_zero.rs](https://github.com/axiom-crypto/halo2-lib/blob/68e1a81b7fbe5f2b942f8b7b9a0e90a4087a967a/halo2-ecc/src/bigint/check_carry_mod_to_zero.rs#L32)

```rust
halo2-ecc/src/bigint/carry_mod.rs::crt() {
   debug_assert!(a.value.bits() as usize <= n \* k - 1 + (F::NUM_BITS as usize) - 2);
}
```

a.value.bits() as usize = 762
n \* k - 1 + (F::NUM_BITS as usize) - 2 = 702
n = 90
k = 5
F::NUM_BITS as usize = 255

Same line also appears in `halo2-ecc/src/bigint/check_carry_mod_to_zero.rs::crt()`
